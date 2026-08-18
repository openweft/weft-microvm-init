package bundler

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// withResolvConf points the bundler at a resolver that does (or does not)
// exist, without touching the real /etc. The seam is restored on cleanup.
func withResolvConf(t *testing.T, exists bool) {
	t.Helper()
	orig := osStat
	t.Cleanup(func() { osStat = orig })
	if exists {
		osStat = func(string) (fs.FileInfo, error) { return nil, nil }
		return
	}
	osStat = func(string) (fs.FileInfo, error) { return nil, errors.New("no such file") }
}

// hasNamespace reports whether typ appears in ns.
func hasNamespace(ns []namespace, typ string) bool {
	for _, n := range ns {
		if n.Type == typ {
			return true
		}
	}
	return false
}

// TestNamespacesFor_DefaultJoinsPodNetns is the whole point of the change:
// with no Net set, the container must NOT ask for its own network
// namespace, because the init pairs no veth into one — a private netns
// inside the VM has a loopback and nothing else.
func TestNamespacesFor_DefaultJoinsPodNetns(t *testing.T) {
	t.Setenv("WEFT_BUNDLE_NAMESPACES", "")
	os.Unsetenv("WEFT_BUNDLE_NAMESPACES")

	ns := namespacesFor(&pod.Container{ID: "main"})

	if hasNamespace(ns, "network") {
		t.Fatalf("default container asked for a private netns: %+v", ns)
	}
	// Every other namespace of the Docker-style set must survive: this
	// change is about connectivity, not about dropping isolation.
	for _, typ := range []string{"pid", "ipc", "uts", "mount"} {
		if !hasNamespace(ns, typ) {
			t.Errorf("namespace %q was dropped: %+v", typ, ns)
		}
	}
}

// TestNamespacesFor_HostIsExplicitDefault checks "host" is a synonym of the
// empty default rather than a third behaviour.
func TestNamespacesFor_HostIsExplicitDefault(t *testing.T) {
	os.Unsetenv("WEFT_BUNDLE_NAMESPACES")

	empty := namespacesFor(&pod.Container{ID: "a"})
	host := namespacesFor(&pod.Container{ID: "a", Net: "host"})

	if len(empty) != len(host) {
		t.Fatalf("host (%+v) differs from default (%+v)", host, empty)
	}
	for i := range empty {
		if empty[i] != host[i] {
			t.Fatalf("host (%+v) differs from default (%+v)", host, empty)
		}
	}
}

// TestNamespacesFor_NoneKeepsPrivateNetns: offline is still expressible,
// and now deliberately so.
func TestNamespacesFor_NoneKeepsPrivateNetns(t *testing.T) {
	os.Unsetenv("WEFT_BUNDLE_NAMESPACES")

	ns := namespacesFor(&pod.Container{ID: "main", Net: "none"})

	if !hasNamespace(ns, "network") {
		t.Fatalf(`net="none" must keep a private netns: %+v`, ns)
	}
}

// TestNamespacesFor_EnvOverrideWins: the debug lever must outrank the spec
// field, or it cannot be used to bisect anything.
func TestNamespacesFor_EnvOverrideWins(t *testing.T) {
	t.Setenv("WEFT_BUNDLE_NAMESPACES", "network,uts")

	ns := namespacesFor(&pod.Container{ID: "main"}) // default would drop network

	if !hasNamespace(ns, "network") || !hasNamespace(ns, "uts") || len(ns) != 2 {
		t.Fatalf("env override not honoured: %+v", ns)
	}
}

// TestNamespacesFor_EmptyEnvOverrideWins covers the meaningful-empty case:
// "" asks for zero namespaces, and namespacesFor must not turn that into
// the default set on its way through.
func TestNamespacesFor_EmptyEnvOverrideWins(t *testing.T) {
	t.Setenv("WEFT_BUNDLE_NAMESPACES", "")

	if ns := namespacesFor(&pod.Container{ID: "main"}); len(ns) != 0 {
		t.Fatalf("empty override should request no namespaces, got %+v", ns)
	}
	if ns := namespacesFor(&pod.Container{ID: "main", Net: "none"}); len(ns) != 0 {
		t.Fatalf("empty override should outrank net=none, got %+v", ns)
	}
}

// TestResolvConfMount_PresentIsBoundReadOnly: routes without a resolver
// are not connectivity — the container reads its OWN rootfs's
// /etc/resolv.conf, and a FROM-scratch image has none.
func TestResolvConfMount_PresentIsBoundReadOnly(t *testing.T) {
	withResolvConf(t, true)

	m, ok := resolvConfMount(&pod.Container{ID: "main"})

	if !ok {
		t.Fatal("resolver exists but was not bound into the container")
	}
	if m.Destination != "/etc/resolv.conf" || m.Source != resolvConfPath || m.Type != "bind" {
		t.Fatalf("unexpected mount: %+v", m)
	}
	var ro bool
	for _, o := range m.Options {
		if o == "ro" {
			ro = true
		}
	}
	if !ro {
		t.Errorf("the pod's resolver must be read-only in a container: %+v", m.Options)
	}
}

// TestResolvConfMount_AbsentIsSkipped: binding a missing source fails the
// container's create, so a pod with no Network must yield no mount.
func TestResolvConfMount_AbsentIsSkipped(t *testing.T) {
	withResolvConf(t, false)

	if _, ok := resolvConfMount(&pod.Container{ID: "main"}); ok {
		t.Fatal("bound a resolver the init never wrote")
	}
}

// TestResolvConfMount_NoneIsSkipped: an offline container gets no resolver
// even when the pod has one.
func TestResolvConfMount_NoneIsSkipped(t *testing.T) {
	withResolvConf(t, true)

	if _, ok := resolvConfMount(&pod.Container{ID: "main", Net: "none"}); ok {
		t.Fatal(`net="none" must not receive the pod resolver`)
	}
}

// TestBuild_EmitsJoinedNetnsAndResolver is the end-to-end assertion on the
// artefact crun actually reads: the generated config.json.
func TestBuild_EmitsJoinedNetnsAndResolver(t *testing.T) {
	os.Unsetenv("WEFT_BUNDLE_NAMESPACES")
	withResolvConf(t, true)
	root := t.TempDir()
	origRoot := BundlesRoot
	BundlesRoot = filepath.Join(root, "bundles")
	t.Cleanup(func() { BundlesRoot = origRoot })

	dir, err := Build("pod1", &pod.Container{
		ID:      "main",
		Command: []string{"/bin/true"},
	}, filepath.Join(root, "rootfs"))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("read config.json: %v", err)
	}
	var got spec
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("decode config.json: %v", err)
	}
	if hasNamespace(got.Linux.Namespaces, "network") {
		t.Errorf("config.json still requests a private netns: %+v", got.Linux.Namespaces)
	}
	var bound bool
	for _, m := range got.Mounts {
		if m.Destination == "/etc/resolv.conf" {
			bound = true
		}
	}
	if !bound {
		t.Errorf("config.json carries no resolver mount: %+v", got.Mounts)
	}
}
