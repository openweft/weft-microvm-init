package secretclient

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	guestv1 "github.com/openweft/weft-proto/guestv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fake is an in-process GuestSecrets server: secrets by ID with a version,
// a required token, and a scripted list of errors served before the answer.
type fake struct {
	guestv1.UnimplementedGuestSecretsServer
	mu      sync.Mutex
	secrets map[string]*guestv1.FetchResponse
	token   []byte
	errs    []error // consumed one per call, before answering
	calls   int
	seen    []*guestv1.FetchRequest
}

func (f *fake) Fetch(_ context.Context, r *guestv1.FetchRequest) (*guestv1.FetchResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.seen = append(f.seen, r)
	if len(f.errs) > 0 {
		e := f.errs[0]
		f.errs = f.errs[1:]
		return nil, e
	}
	if f.token != nil && !bytes.Equal(f.token, r.BootToken) {
		return nil, status.Error(codes.PermissionDenied, "denied")
	}
	s, ok := f.secrets[r.SecretId]
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "denied")
	}
	if r.KnownVersion == s.Version {
		return &guestv1.FetchResponse{Version: s.Version, Unchanged: true}, nil
	}
	return &guestv1.FetchResponse{Value: append([]byte(nil), s.Value...), Version: s.Version}, nil
}

func start(t *testing.T, f *fake) *Client {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	guestv1.RegisterGuestSecretsServer(srv, f)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	c := &Client{
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", lis.Addr().String())
		},
		Backoff: time.Millisecond,
		sleep:   func(context.Context, time.Duration) error { return nil },
	}
	return c
}

func TestFetchValueAndUnchanged(t *testing.T) {
	f := &fake{secrets: map[string]*guestv1.FetchResponse{"wg-key": {Value: []byte("s3cret"), Version: 3}}}
	c := start(t, f)
	s, err := c.Fetch(context.Background(), "wg-key", 0)
	if err != nil || string(s.Value) != "s3cret" || s.Version != 3 || s.Unchanged {
		t.Fatalf("got %+v, %v", s, err)
	}
	s.Wipe()
	if s.Value != nil {
		t.Fatal("Wipe left the value")
	}
	u, err := c.Fetch(context.Background(), "wg-key", 3)
	if err != nil || !u.Unchanged || len(u.Value) != 0 || u.Version != 3 {
		t.Fatalf("unchanged: %+v, %v", u, err)
	}
}

func TestRotationReturnsNewValue(t *testing.T) {
	f := &fake{secrets: map[string]*guestv1.FetchResponse{"k": {Value: []byte("old"), Version: 1}}}
	c := start(t, f)
	if _, err := c.Fetch(context.Background(), "k", 0); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.secrets["k"] = &guestv1.FetchResponse{Value: []byte("new"), Version: 2}
	f.mu.Unlock()
	s, err := c.Fetch(context.Background(), "k", 1)
	if err != nil || string(s.Value) != "new" || s.Version != 2 || s.Unchanged {
		t.Fatalf("rotation: %+v, %v", s, err)
	}
}

func TestWrongIDDeniedNotRetried(t *testing.T) {
	f := &fake{secrets: map[string]*guestv1.FetchResponse{"k": {Value: []byte("v"), Version: 1}}}
	c := start(t, f)
	_, err := c.Fetch(context.Background(), "other", 0)
	if status.Code(errors.Unwrap(err)) != codes.PermissionDenied && !strings.Contains(err.Error(), "PermissionDenied") {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if f.calls != 1 {
		t.Fatalf("PermissionDenied must not be retried: %d calls", f.calls)
	}
}

func TestMalformedIDRefusedBeforeDial(t *testing.T) {
	c := &Client{Dial: func(context.Context) (net.Conn, error) { t.Fatal("dialed"); return nil, nil }}
	for _, id := range []string{"", "Upper", "-x", "a b", strings.Repeat("a", 64)} {
		if _, err := c.Fetch(context.Background(), id, 0); err == nil {
			t.Errorf("id %q accepted", id)
		}
	}
	if !ValidID(strings.Repeat("a", 63)) || !ValidID("a.b-c0") {
		t.Error("valid ids refused")
	}
	if ValidID("a/b") {
		t.Error("slash must be refused")
	}
}

func TestRetryOnUnavailableThenSucceeds(t *testing.T) {
	f := &fake{
		secrets: map[string]*guestv1.FetchResponse{"k": {Value: []byte("v"), Version: 1}},
		errs:    []error{status.Error(codes.Unavailable, "x"), status.Error(codes.ResourceExhausted, "y")},
	}
	c := start(t, f)
	var slept []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	s, err := c.Fetch(context.Background(), "k", 0)
	if err != nil || string(s.Value) != "v" {
		t.Fatalf("got %+v, %v", s, err)
	}
	if f.calls != 3 || len(slept) != 2 || slept[1] != 2*slept[0] {
		t.Fatalf("calls=%d slept=%v: want 3 calls and doubling backoff", f.calls, slept)
	}
}

func TestRetriesAreBounded(t *testing.T) {
	f := &fake{}
	for range 20 {
		f.errs = append(f.errs, status.Error(codes.Unavailable, "down"))
	}
	c := start(t, f)
	c.Attempts = 4
	_, err := c.Fetch(context.Background(), "k", 0)
	if err == nil || f.calls != 4 || !strings.Contains(err.Error(), "Unavailable") {
		t.Fatalf("calls=%d err=%v", f.calls, err)
	}
}

func TestDialFailureIsRetried(t *testing.T) {
	n := 0
	c := &Client{
		Dial:     func(context.Context) (net.Conn, error) { n++; return nil, errors.New("no route") },
		Attempts: 3,
		sleep:    func(context.Context, time.Duration) error { return nil },
	}
	if _, err := c.Fetch(context.Background(), "k", 0); err == nil || n != 3 {
		t.Fatalf("dials=%d err=%v", n, err)
	}
}

func TestOversizeRefused(t *testing.T) {
	f := &fake{secrets: map[string]*guestv1.FetchResponse{"big": {Value: make([]byte, MaxValue+1), Version: 1}}}
	c := start(t, f)
	_, err := c.Fetch(context.Background(), "big", 0)
	if !errors.Is(err, ErrOversize) || f.calls != 1 {
		t.Fatalf("calls=%d err=%v", f.calls, err)
	}
	f.secrets["ok"] = &guestv1.FetchResponse{Value: make([]byte, MaxValue), Version: 1}
	if _, err := c.Fetch(context.Background(), "ok", 0); err != nil {
		t.Fatalf("exactly MaxValue must pass: %v", err)
	}
}

func TestTokenSentWhenPresentAndValidated(t *testing.T) {
	tok := bytes.Repeat([]byte{7}, TokenLen)
	f := &fake{secrets: map[string]*guestv1.FetchResponse{"k": {Value: []byte("v"), Version: 1}}, token: tok}
	c := start(t, f)
	if _, err := c.Fetch(context.Background(), "k", 0); err == nil {
		t.Fatal("no token must be refused by a host that holds one")
	}
	c.Token = func() ([]byte, error) { return tok, nil }
	if _, err := c.Fetch(context.Background(), "k", 0); err != nil {
		t.Fatal(err)
	}
	c.Token = func() ([]byte, error) { return []byte("short"), nil }
	calls := f.calls
	if _, err := c.Fetch(context.Background(), "k", 0); err == nil || f.calls != calls {
		t.Fatalf("a bad-length token must be refused before any request: %v", err)
	}
	c.Token = func() ([]byte, error) { return nil, errors.New("boom") }
	if _, err := c.Fetch(context.Background(), "k", 0); err == nil {
		t.Fatal("token source error must surface")
	}
}

func TestErrorsNeverCarryTheValueOrToken(t *testing.T) {
	f := &fake{errs: []error{status.Error(codes.Internal, "leaked-value-xyz")}}
	c := start(t, f)
	_, err := c.Fetch(context.Background(), "k", 0)
	if err == nil || strings.Contains(err.Error(), "leaked-value-xyz") {
		t.Fatalf("server text must not reach the error: %v", err)
	}
}

func TestNoDialer(t *testing.T) {
	if _, err := (&Client{}).Fetch(context.Background(), "k", 0); err == nil {
		t.Fatal("want error")
	}
}

func TestContextCancelStopsBackoff(t *testing.T) {
	f := &fake{}
	for range 5 {
		f.errs = append(f.errs, status.Error(codes.Unavailable, "d"))
	}
	c := start(t, f)
	c.sleep = nil
	c.Backoff = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Fetch(ctx, "k", 0); err == nil {
		t.Fatal("want error")
	}
}

// noPanic fails the test, instead of crashing the binary, when f panics: a
// guard whose removal only crashes is held by luck, not by an assertion.
func noPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panicked: %v", r)
		}
	}()
	f()
}

func TestWipeNilIsSafe(t *testing.T) {
	noPanic(t, func() { (*Secret)(nil).Wipe() })
}

func TestNoDialerMessage(t *testing.T) {
	noPanic(t, func() {
		_, err := (&Client{}).Fetch(context.Background(), "k", 0)
		if err == nil || !strings.Contains(err.Error(), "no dialer") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestDialErrorIsReportedNotDereferenced(t *testing.T) {
	noPanic(t, func() {
		c := &Client{
			Dial:     func(context.Context) (net.Conn, error) { return nil, errors.New("no route") },
			Attempts: 1,
		}
		_, err := c.Fetch(context.Background(), "k", 0)
		if err == nil || !strings.Contains(err.Error(), "dial host") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestCancelDuringBackoffReturnsContextError(t *testing.T) {
	f := &fake{errs: []error{status.Error(codes.Unavailable, "d"), status.Error(codes.Unavailable, "d")}}
	c := start(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	c.sleep = func(ctx context.Context, _ time.Duration) error { cancel(); return ctx.Err() }
	_, err := c.Fetch(ctx, "k", 0)
	if !errors.Is(err, context.Canceled) || f.calls != 1 {
		t.Fatalf("calls=%d err=%v", f.calls, err)
	}
}

func TestBackoffWaitErrorIsReturnedAsIs(t *testing.T) {
	sentinel := errors.New("sleep refused")
	f := &fake{errs: []error{status.Error(codes.Unavailable, "d"), status.Error(codes.Unavailable, "d")}}
	c := start(t, f)
	c.sleep = func(context.Context, time.Duration) error { return sentinel }
	_, err := c.Fetch(context.Background(), "k", 0)
	if !errors.Is(err, sentinel) || f.calls != 1 {
		t.Fatalf("calls=%d err=%v", f.calls, err)
	}
}

func TestEmptyValueWithoutUnchangedIsRefused(t *testing.T) {
	f := &fake{secrets: map[string]*guestv1.FetchResponse{"e": {Value: nil, Version: 5}}}
	c := start(t, f)
	if _, err := c.Fetch(context.Background(), "e", 0); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err = %v", err)
	}
}

func TestTokenSourceErrorMessage(t *testing.T) {
	f := &fake{secrets: map[string]*guestv1.FetchResponse{"k": {Value: []byte("v"), Version: 1}}}
	c := start(t, f)
	c.Token = func() ([]byte, error) { return nil, errors.New("boom") }
	_, err := c.Fetch(context.Background(), "k", 0)
	if err == nil || !strings.Contains(err.Error(), "boot token") || f.calls != 0 {
		t.Fatalf("calls=%d err=%v", f.calls, err)
	}
}

func TestClientConstructionFailure(t *testing.T) {
	old := newClient
	defer func() { newClient = old }()
	newClient = func(string, ...grpc.DialOption) (*grpc.ClientConn, error) { return nil, errors.New("bad target") }
	closed := false
	c := &Client{Dial: func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		_ = b.Close()
		return &closeSpy{Conn: a, closed: &closed}, nil
	}}
	_, err := c.Fetch(context.Background(), "k", 0)
	if err == nil || !strings.Contains(err.Error(), "grpc client") || !closed {
		t.Fatalf("closed=%v err=%v", closed, err)
	}
}

type closeSpy struct {
	net.Conn
	closed *bool
}

func (c *closeSpy) Close() error { *c.closed = true; return c.Conn.Close() }
