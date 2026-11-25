package pod

import (
	"encoding/json"
	"testing"
)

func TestWireGuardRefValidation(t *testing.T) {
	base := WireGuard{Address: "10.9.0.1/24"}
	cases := map[string]struct {
		key, ref string
		ok       bool
	}{
		"inline":   {"k", "", true},
		"ref":      {"", "wg-key", true},
		"both":     {"k", "wg-key", false},
		"neither":  {"", "", false},
		"bad ref":  {"", "Bad/ID", false},
		"ref dots": {"", "a.b_c-d", true},
	}
	for name, c := range cases {
		w := base
		w.PrivateKey, w.PrivateKeyRef = c.key, c.ref
		if err := w.Validate(); (err == nil) != c.ok {
			t.Errorf("%s: err=%v want ok=%v", name, err, c.ok)
		}
	}
}

func TestShareMountSecretRefs(t *testing.T) {
	mk := func(c CubeFSMount) ShareMount {
		c.Volume, c.Masters, c.Owner = "v", []string{"m:1"}, "o"
		return ShareMount{ID: "x", MountPoint: "/m", CubeFS: &c}
	}
	for name, c := range map[string]struct {
		c  CubeFSMount
		ok bool
	}{
		"refs":        {CubeFSMount{AccessKeyRef: "ak", SecretKeyRef: "sk", SecretVersion: 2}, true},
		"inline":      {CubeFSMount{AccessKey: "a", SecretKey: "s"}, true},
		"mixed":       {CubeFSMount{AccessKey: "a", SecretKeyRef: "sk"}, true},
		"secret both": {CubeFSMount{SecretKey: "s", SecretKeyRef: "sk"}, false},
		"access both": {CubeFSMount{AccessKey: "a", AccessKeyRef: "ak"}, false},
		"bad ref":     {CubeFSMount{SecretKeyRef: "UPPER"}, false},
	} {
		m := mk(c.c)
		if err := m.Validate(); (err == nil) != c.ok {
			t.Errorf("%s: err=%v want ok=%v", name, err, c.ok)
		}
	}
}

func TestSecretRefJSONNames(t *testing.T) {
	var m ShareMount
	in := `{"id":"x","mount_point":"/m","cubefs":{"volume":"v","masters":["m:1"],"owner":"o","access_key_ref":"ak","secret_key_ref":"sk","secret_version":7}}`
	if err := json.Unmarshal([]byte(in), &m); err != nil {
		t.Fatal(err)
	}
	if m.CubeFS.AccessKeyRef != "ak" || m.CubeFS.SecretKeyRef != "sk" || m.CubeFS.SecretVersion != 7 {
		t.Fatalf("%+v", m.CubeFS)
	}
	var w WireGuard
	if err := json.Unmarshal([]byte(`{"private_key_ref":"wg","address":"10.0.0.1/24"}`), &w); err != nil || w.PrivateKeyRef != "wg" {
		t.Fatalf("%+v %v", w, err)
	}
}
