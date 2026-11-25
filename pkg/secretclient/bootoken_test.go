package secretclient

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	guestv1 "github.com/openweft/weft-proto/guestv1"
)

func tokenFile(t *testing.T, content []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "raw")
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFileTokenSourceReadsExactlyTokenLenBytes(t *testing.T) {
	want := bytes.Repeat([]byte{0xA5, 0x00, 0x5A, 0xFF}, TokenLen/4)
	got, err := FileTokenSource(tokenFile(t, want))()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("got %x, %v", got, err)
	}
}

func TestFileTokenSourceAbsentFileIsEmptyToken(t *testing.T) {
	got, err := FileTokenSource(filepath.Join(t.TempDir(), "no", "such", "raw"))()
	if err != nil || len(got) != 0 {
		t.Fatalf("got %x, %v", got, err)
	}
}

func TestFileTokenSourceWrongLengthIsAnErrorWithNoToken(t *testing.T) {
	for name, n := range map[string]int{"empty": 0, "short": TokenLen - 1, "long": TokenLen + 1, "huge": 4096} {
		got, err := FileTokenSource(tokenFile(t, bytes.Repeat([]byte{7}, n)))()
		if err == nil || got != nil {
			t.Errorf("%s: got %x, %v", name, got, err)
		}
	}
}

func TestFileTokenSourceErrorNamesLengthNotBytes(t *testing.T) {
	_, err := FileTokenSource(tokenFile(t, []byte("SECRETSECRET")))()
	if err == nil || strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "got 12") {
		t.Fatalf("err = %v", err)
	}
}

func TestFileTokenSourceUnreadablePathIsAnError(t *testing.T) {
	// a directory opens but cannot be read
	got, err := FileTokenSource(t.TempDir())()
	if err == nil || got != nil || !strings.Contains(err.Error(), "read boot token failed") {
		t.Fatalf("got %x, %v", got, err)
	}
}

func TestFileTokenSourceOpenFailureOtherThanAbsentIsAnError(t *testing.T) {
	// a path below a regular file fails with ENOTDIR, not "does not exist"
	got, err := FileTokenSource(filepath.Join(tokenFile(t, []byte("x")), "raw"))()
	if err == nil || got != nil || !strings.Contains(err.Error(), "open boot token") {
		t.Fatalf("got %x, %v", got, err)
	}
}

func TestFileTokenSourceReadsOnce(t *testing.T) {
	want := bytes.Repeat([]byte{1}, TokenLen)
	p := tokenFile(t, want)
	src := FileTokenSource(p)
	if _, err := src(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, bytes.Repeat([]byte{2}, TokenLen), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := src()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("second call re-read the file: %x, %v", got, err)
	}
}

func TestFileTokenSourceRemembersAnAbsentFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "raw")
	src := FileTokenSource(p)
	if got, err := src(); err != nil || len(got) != 0 {
		t.Fatalf("%x %v", got, err)
	}
	if err := os.WriteFile(p, bytes.Repeat([]byte{2}, TokenLen), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := src(); len(got) != 0 {
		t.Fatal("token appeared after boot: the file must be read once")
	}
}

func TestClientSendsTheFileTokenAsBootToken(t *testing.T) {
	want := bytes.Repeat([]byte{9}, TokenLen)
	f := &fake{token: want, secrets: map[string]*guestv1.FetchResponse{"k": {Value: []byte("v"), Version: 1}}}
	c := start(t, f)
	c.Token = FileTokenSource(tokenFile(t, want))
	if s, err := c.Fetch(context.Background(), "k", 0); err != nil || string(s.Value) != "v" {
		t.Fatalf("%+v %v", s, err)
	}
	if !bytes.Equal(f.seen[0].BootToken, want) {
		t.Fatal("token not sent")
	}
	// a wrong-length file: no request leaves the guest
	f.calls = 0
	c.Token = FileTokenSource(tokenFile(t, want[:5]))
	if _, err := c.Fetch(context.Background(), "k", 0); err == nil || f.calls != 0 {
		t.Fatalf("calls=%d err=%v", f.calls, err)
	}
}
