package bundler

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// tempBundles points BundlesRoot at a writable dir for the duration of a
// test, so `go test` needs no /run.
func tempBundles(t *testing.T) string {
	t.Helper()
	orig := BundlesRoot
	BundlesRoot = filepath.Join(t.TempDir(), "bundles")
	t.Cleanup(func() { BundlesRoot = orig })
	return BundlesRoot
}

// TestBuild_RejectsMissingCommand: the guest cannot read an image config,
// so a container with no resolved entrypoint is a host-side bug that must
// surface here rather than as crun's opaque "command is required".
func TestBuild_RejectsMissingCommand(t *testing.T) {
	tempBundles(t)

	_, err := Build("pod", &pod.Container{ID: "main"}, "/rootfs")

	if err == nil || !strings.Contains(err.Error(), "command is required") {
		t.Fatalf("want a command-required error, got %v", err)
	}
}

// TestBuild_RejectsMissingRootfs guards the other required input.
func TestBuild_RejectsMissingRootfs(t *testing.T) {
	tempBundles(t)

	_, err := Build("pod", &pod.Container{ID: "main", Command: []string{"/bin/true"}}, "")

	if err == nil || !strings.Contains(err.Error(), "rootfsPath is required") {
		t.Fatalf("want a rootfs-required error, got %v", err)
	}
}

// TestBuild_ReportsUnwritableBundleRoot: /run is a tmpfs the init mounts,
// and a full or read-only one must not be reported as a runtime failure
// three layers later.
func TestBuild_ReportsUnwritableBundleRoot(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocked")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	orig := BundlesRoot
	BundlesRoot = blocker // a FILE where a directory must go
	t.Cleanup(func() { BundlesRoot = orig })

	_, err := Build("pod", &pod.Container{ID: "main", Command: []string{"/bin/true"}}, "/rootfs")

	if err == nil || !strings.Contains(err.Error(), "mkdir bundle") {
		t.Fatalf("want a mkdir error, got %v", err)
	}
}

// TestBuild_ReportsUnwritableConfig covers the write half: the bundle dir
// exists but config.json cannot be created.
func TestBuild_ReportsUnwritableConfig(t *testing.T) {
	bundles := tempBundles(t)
	// Pre-create <bundles>/main/config.json as a DIRECTORY: MkdirAll then
	// succeeds and only the WriteFile fails.
	if err := os.MkdirAll(filepath.Join(bundles, "main", "config.json"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := Build("pod", &pod.Container{ID: "main", Command: []string{"/bin/true"}}, "/rootfs")

	if err == nil || !strings.Contains(err.Error(), "write config.json") {
		t.Fatalf("want a write error, got %v", err)
	}
}

// TestBuild_CarriesContainerMounts: a pod's declared mounts must reach the
// runtime spec unchanged, after the defaults.
func TestBuild_CarriesContainerMounts(t *testing.T) {
	tempBundles(t)
	withResolvConf(t, false)

	dir, err := Build("pod", &pod.Container{
		ID:      "main",
		Command: []string{"/bin/true"},
		Mounts: []pod.Mount{{
			Source: "/run/weft/cache", Destination: "/cache",
			Type: "bind", Options: []string{"rbind", "rw"},
		}},
	}, "/rootfs")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	var got spec
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	last := got.Mounts[len(got.Mounts)-1]
	if last.Destination != "/cache" || last.Source != "/run/weft/cache" ||
		last.Type != "bind" || strings.Join(last.Options, ",") != "rbind,rw" {
		t.Fatalf("container mount mangled: %+v", last)
	}
}

// TestBuild_HonoursWorkdir: an empty Workdir must become "/", not "".
func TestBuild_HonoursWorkdir(t *testing.T) {
	tempBundles(t)
	withResolvConf(t, false)

	for _, tc := range []struct{ in, want string }{
		{"", "/"},
		{"/src", "/src"},
	} {
		dir, err := Build("pod", &pod.Container{
			ID: "main", Command: []string{"/bin/true"}, Workdir: tc.in,
		}, "/rootfs")
		if err != nil {
			t.Fatalf("Build(%q): %v", tc.in, err)
		}
		var got spec
		b, _ := os.ReadFile(filepath.Join(dir, "config.json"))
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if got.Process.Cwd != tc.want {
			t.Errorf("Workdir %q → cwd %q, want %q", tc.in, got.Process.Cwd, tc.want)
		}
	}
}

// TestParseUser covers every form the field accepts, including the
// malformed ones the parser deliberately swallows.
func TestParseUser(t *testing.T) {
	for _, tc := range []struct {
		in       string
		uid, gid uint32
	}{
		{"", 0, 0},
		{"1000", 1000, 1000},      // a lone uid also sets the gid
		{"1000:2000", 1000, 2000}, // explicit pair
		{"root", 0, 0},            // unparseable → 0, not an error
		{"1000:", 1000, 0},        // half a pair
		{":2000", 0, 2000},        // the other half
	} {
		uid, gid := parseUser(tc.in)
		if uid != tc.uid || gid != tc.gid {
			t.Errorf("parseUser(%q) = %d:%d, want %d:%d", tc.in, uid, gid, tc.uid, tc.gid)
		}
	}
}

// TestBuildResources_ZeroIsNil: an unset Resources must emit no cgroup
// limits at all, rather than limits of zero — which crun reads as "no
// memory, no pids" and refuses.
func TestBuildResources_ZeroIsNil(t *testing.T) {
	if got := buildResources(pod.Resources{}); got != nil {
		t.Fatalf("empty Resources produced %+v", got)
	}
}

// TestBuildResources_EachFieldIndependently: a container that limits only
// one dimension must not acquire the other two.
func TestBuildResources_EachFieldIndependently(t *testing.T) {
	mem := buildResources(pod.Resources{MemBytes: 512 << 20})
	if mem.Memory == nil || *mem.Memory.Limit != 512<<20 || mem.CPU != nil || mem.Pids != nil {
		t.Errorf("mem-only: %+v", mem)
	}
	cpuOnly := buildResources(pod.Resources{CPUShares: 512})
	if cpuOnly.CPU == nil || *cpuOnly.CPU.Shares != 512 || cpuOnly.Memory != nil || cpuOnly.Pids != nil {
		t.Errorf("cpu-only: %+v", cpuOnly)
	}
	pidsOnly := buildResources(pod.Resources{PidsMax: 64})
	if pidsOnly.Pids == nil || pidsOnly.Pids.Limit != 64 || pidsOnly.Memory != nil || pidsOnly.CPU != nil {
		t.Errorf("pids-only: %+v", pidsOnly)
	}
}

// TestBuildResources_AllThree checks they compose.
func TestBuildResources_AllThree(t *testing.T) {
	got := buildResources(pod.Resources{MemBytes: 1 << 20, CPUShares: 2, PidsMax: 3})
	if got.Memory == nil || got.CPU == nil || got.Pids == nil {
		t.Fatalf("dropped a limit: %+v", got)
	}
}

// TestDefaultCaps_PrivilegedIsASuperset: privileged must ADD to the base
// set, never replace it.
func TestDefaultCaps_PrivilegedIsASuperset(t *testing.T) {
	base := defaultCaps(false)
	priv := defaultCaps(true)

	if len(priv) <= len(base) {
		t.Fatalf("privileged (%d caps) is not wider than base (%d)", len(priv), len(base))
	}
	have := map[string]bool{}
	for _, c := range priv {
		have[c] = true
	}
	for _, c := range base {
		if !have[c] {
			t.Errorf("privileged dropped base capability %q", c)
		}
	}
	for _, c := range []string{"CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE"} {
		if !have[c] {
			t.Errorf("privileged is missing %q", c)
		}
	}
	if have["CAP_SYS_MODULE"] {
		t.Error("privileged must not grant CAP_SYS_MODULE: the guest kernel is built without modules")
	}
}

// TestBuild_PrivilegedDropsNoNewPrivileges ties the flag to the spec field
// crun reads.
func TestBuild_PrivilegedDropsNoNewPrivileges(t *testing.T) {
	tempBundles(t)
	withResolvConf(t, false)

	dir, err := Build("pod", &pod.Container{
		ID: "main", Command: []string{"/bin/true"}, Privileged: true,
	}, "/rootfs")
	if err != nil {
		t.Fatal(err)
	}
	var got spec
	b, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Process.NoNewPrivileges {
		t.Error("privileged container still sets noNewPrivileges")
	}
}

// TestBuild_ReportsMarshalFailure exercises the encode branch through its
// seam: unreachable with today's spec types, but the message is what a
// future field of an unencodable type would surface as.
func TestBuild_ReportsMarshalFailure(t *testing.T) {
	tempBundles(t)
	orig := jsonMarshalIndent
	jsonMarshalIndent = func(any, string, string) ([]byte, error) {
		return nil, errors.New("boom")
	}
	t.Cleanup(func() { jsonMarshalIndent = orig })

	_, err := Build("pod", &pod.Container{ID: "main", Command: []string{"/bin/true"}}, "/rootfs")

	if err == nil || !strings.Contains(err.Error(), "marshal config.json") {
		t.Fatalf("want a marshal error, got %v", err)
	}
}
