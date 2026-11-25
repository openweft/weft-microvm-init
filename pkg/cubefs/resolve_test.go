package cubefs

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openweft/weft-microvm-init/pkg/pod"
	"github.com/openweft/weft-microvm-init/pkg/secretclient"
)

// mapSource serves values by ID, recording the IDs asked for.
type mapSource struct {
	vals  map[string]string
	asked []string
	buf   [][]byte
}

func (m *mapSource) Fetch(_ context.Context, id string, _ uint64) (*secretclient.Secret, error) {
	m.asked = append(m.asked, id)
	v, ok := m.vals[id]
	if !ok {
		return nil, errors.New("host refused: PermissionDenied")
	}
	b := []byte(v + "\n")
	m.buf = append(m.buf, b)
	return &secretclient.Secret{Value: b, Version: 1}, nil
}

func shareWith(c pod.CubeFSMount) pod.ShareMount {
	c.Volume, c.Masters, c.Owner = "vol", []string{"10.0.0.1:17010"}, "me"
	return pod.ShareMount{ID: "team", MountPoint: "/run/weft/shares/team", CubeFS: &c}
}

func TestResolveFetchesRefsAndWipes(t *testing.T) {
	src := &mapSource{vals: map[string]string{"ak": "AKVAL", "sk": "SKVAL"}}
	in := shareWith(pod.CubeFSMount{AccessKeyRef: "ak", SecretKeyRef: "sk", SecretVersion: 4})
	out, wipe, err := Resolve(context.Background(), in, src)
	if err != nil {
		t.Fatal(err)
	}
	if out.CubeFS.AccessKey != "AKVAL" || out.CubeFS.SecretKey != "SKVAL" {
		t.Fatalf("keys not filled: %+v", out.CubeFS)
	}
	if in.CubeFS.SecretKey != "" {
		t.Fatal("Resolve modified its input")
	}
	cfg, err := clientConfig(out, "/log")
	if err != nil || !strings.Contains(string(cfg), "SKVAL") {
		t.Fatalf("config: %s %v", cfg, err)
	}
	wipe()
	for _, b := range src.buf {
		for _, c := range b {
			if c != 0 {
				t.Fatalf("fetched buffer not wiped: %q", b)
			}
		}
	}
}

func TestResolveInlineStillWorks(t *testing.T) {
	in := shareWith(pod.CubeFSMount{AccessKey: "A", SecretKey: "S"})
	out, wipe, err := Resolve(context.Background(), in, nil)
	if err != nil || out.CubeFS.SecretKey != "S" {
		t.Fatalf("%+v %v", out.CubeFS, err)
	}
	wipe()
}

func TestResolveRefAndInlineBothIsError(t *testing.T) {
	src := &mapSource{vals: map[string]string{"sk": "x"}}
	for _, c := range []pod.CubeFSMount{
		{SecretKey: "S", SecretKeyRef: "sk"},
		{AccessKey: "A", AccessKeyRef: "sk"},
	} {
		if _, _, err := Resolve(context.Background(), shareWith(c), src); err == nil {
			t.Errorf("both set accepted: %+v", c)
		}
	}
	if len(src.asked) != 0 {
		t.Fatal("must refuse before any fetch")
	}
}

func TestResolveDeniedWrongIDAndNoSource(t *testing.T) {
	src := &mapSource{vals: map[string]string{"ak": "A"}}
	in := shareWith(pod.CubeFSMount{AccessKeyRef: "ak", SecretKeyRef: "nope"})
	if _, _, err := Resolve(context.Background(), in, src); err == nil || !strings.Contains(err.Error(), "PermissionDenied") {
		t.Fatalf("err = %v", err)
	}
	// the access key fetched before the failure was wiped
	for _, b := range src.buf {
		if b[0] != 0 {
			t.Fatal("partial fetch not wiped on failure")
		}
	}
	if _, _, err := Resolve(context.Background(), in, nil); err == nil {
		t.Fatal("ref without a source must fail")
	}
	if _, _, err := Resolve(context.Background(), shareWith(pod.CubeFSMount{SecretKeyRef: "Bad ID"}), src); err == nil {
		t.Fatal("malformed ref accepted")
	}
}

func TestResolveNoCubeFS(t *testing.T) {
	if _, _, err := Resolve(context.Background(), pod.ShareMount{ID: "x"}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryFailedFetchKeepsOldMountAndRotationRemounts(t *testing.T) {
	src := &mapSource{vals: map[string]string{"sk": "v1"}}
	r := NewRegistryWithSecrets(src)
	var mounted []pod.ShareMount
	r.mount = func(s pod.ShareMount) (*Mounted, error) {
		mounted = append(mounted, s)
		return &Mounted{mountPoint: s.MountPoint, secretVersion: s.CubeFS.SecretVersion, exited: closedChan()}, nil
	}
	// the unmount path shells out; neutralise it with an already-gone mount point
	spec := shareWith(pod.CubeFSMount{SecretKeyRef: "sk", SecretVersion: 1})
	if err := r.Apply(spec); err != nil {
		t.Fatal(err)
	}
	if r.active["team"].SecretVersion() != 1 || mounted[0].CubeFS.SecretKey != "v1" {
		t.Fatalf("first mount: %+v", mounted[0].CubeFS)
	}
	// a fetch that fails must not tear the existing mount down
	delete(src.vals, "sk")
	old := r.active["team"]
	spec.CubeFS.SecretVersion = 2
	if err := r.Apply(spec); err == nil {
		t.Fatal("want fetch failure")
	}
	if r.active["team"] != old || len(mounted) != 1 {
		t.Fatal("old mount was disturbed by a failed fetch")
	}
}

func TestNewRegistryRefusesRefsWithoutSource(t *testing.T) {
	r := NewRegistry()
	r.mount = func(pod.ShareMount) (*Mounted, error) { t.Fatal("mounted"); return nil, nil }
	if err := r.Apply(shareWith(pod.CubeFSMount{SecretKeyRef: "sk"})); err == nil {
		t.Fatal("want error")
	}
}

func closedChan() chan struct{} { c := make(chan struct{}); close(c); return c }
