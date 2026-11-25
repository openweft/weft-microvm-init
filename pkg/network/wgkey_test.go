package network

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openweft/weft-microvm-init/pkg/pod"
	"github.com/openweft/weft-microvm-init/pkg/secretclient"
)

type oneSource struct {
	id  string
	val []byte
	err error
	got *secretclient.Secret
}

func (o *oneSource) Fetch(_ context.Context, id string, _ uint64) (*secretclient.Secret, error) {
	if o.err != nil {
		return nil, o.err
	}
	if id != o.id {
		return nil, errors.New("PermissionDenied")
	}
	o.got = &secretclient.Secret{Value: append([]byte(nil), o.val...), Version: 1}
	return o.got, nil
}

func TestResolveKeyFromRefTrimsAndWipes(t *testing.T) {
	src := &oneSource{id: "wg", val: []byte("QUJD\n")}
	key, wipe, err := resolveWireGuardKey(context.Background(), &pod.WireGuard{PrivateKeyRef: "wg"}, src)
	if err != nil || string(key) != "QUJD" {
		t.Fatalf("%q %v", key, err)
	}
	wipe()
	if src.got.Value != nil {
		t.Fatal("secret not wiped")
	}
}

func TestResolveKeyInlineStillWorks(t *testing.T) {
	key, wipe, err := resolveWireGuardKey(context.Background(), &pod.WireGuard{PrivateKey: "QUJD"}, nil)
	if err != nil || string(key) != "QUJD" {
		t.Fatalf("%q %v", key, err)
	}
	wipe()
	if key[0] != 0 {
		t.Fatal("inline copy not wiped")
	}
}

// anySource would serve any id: only the caller's own check can refuse.
type anySource struct{ calls int }

func (a *anySource) Fetch(context.Context, string, uint64) (*secretclient.Secret, error) {
	a.calls++
	return &secretclient.Secret{Value: []byte("k"), Version: 1}, nil
}

func TestResolveKeyRefusesBadIDBeforeFetching(t *testing.T) {
	src := &anySource{}
	_, _, err := resolveWireGuardKey(context.Background(), &pod.WireGuard{PrivateKeyRef: "Bad ID"}, src)
	if err == nil || !strings.Contains(err.Error(), "valid secret id") || src.calls != 0 {
		t.Fatalf("calls=%d err=%v", src.calls, err)
	}
}

func TestResolveKeyNoSourceIsAnErrorNotAPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panicked: %v", r)
		}
	}()
	_, _, err := resolveWireGuardKey(context.Background(), &pod.WireGuard{PrivateKeyRef: "wg"}, nil)
	if err == nil || !strings.Contains(err.Error(), "no secret source") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveKeyFetchFailureIsAnErrorNotAPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panicked: %v", r)
		}
	}()
	_, _, err := resolveWireGuardKey(context.Background(), &pod.WireGuard{PrivateKeyRef: "wg"}, &oneSource{err: errors.New("Unavailable")})
	if err == nil || !strings.Contains(err.Error(), "Unavailable") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveKeyErrors(t *testing.T) {
	ctx := context.Background()
	src := &oneSource{id: "wg", val: []byte("x")}
	for name, tc := range map[string]struct {
		wg  *pod.WireGuard
		src secretclient.Source
	}{
		"both set":      {&pod.WireGuard{PrivateKey: "a", PrivateKeyRef: "wg"}, src},
		"neither":       {&pod.WireGuard{}, src},
		"no source":     {&pod.WireGuard{PrivateKeyRef: "wg"}, nil},
		"bad id":        {&pod.WireGuard{PrivateKeyRef: "Bad ID"}, src},
		"wrong id":      {&pod.WireGuard{PrivateKeyRef: "other"}, src},
		"fetch failure": {&pod.WireGuard{PrivateKeyRef: "wg"}, &oneSource{err: errors.New("Unavailable")}},
	} {
		if _, _, err := resolveWireGuardKey(ctx, tc.wg, tc.src); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}
