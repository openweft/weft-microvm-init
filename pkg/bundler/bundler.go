// Package bundler turns a pod.Container into an OCI runtime
// bundle on disk — the directory + config.json the OCI runtime
// (runc/crun) consumes.
//
// We don't import github.com/opencontainers/runtime-spec to keep
// the module dep-free ; we emit only the fields we actually set,
// and the runtime fills defaults for the rest. The schema is OCI
// Runtime Specification v1.0.2.
//
// Scope of this MVP:
//   - mono-container per pod: each container gets fresh pid/net/
//     uts/ipc/mount namespaces.
//   - pod-style namespace sharing (pause container pattern) is a
//     follow-up: store the first container's PID, then emit
//     `{"type": "network", "path": "/proc/<pid>/ns/net"}` for
//     siblings instead of an empty entry that creates a new ns.
package bundler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/openweft/weft-microvm-init/pkg/pod"
)

const ociVersion = "1.0.2"

// BundlesRoot is where Build() places per-container bundle dirs.
// One dir per container holds the generated config.json ; the
// rootfs is referenced by absolute path inside that config.
const BundlesRoot = "/run/weft/bundles"

// Build writes a config.json for c into <BundlesRoot>/<c.ID>/.
// rootfsPath is the absolute path of the container's root
// filesystem (typically a virtio-fs share mount point). Returns
// the bundle directory the OCI runtime should be invoked against.
func Build(podID string, c *pod.Container, rootfsPath string) (string, error) {
	if len(c.Command) == 0 {
		// The runtime cannot guess the image entrypoint from the
		// bundle alone ; the host is responsible for resolving the
		// image's CMD/ENTRYPOINT and injecting it into PodSpec.
		return "", fmt.Errorf("container %q: command is required (host must resolve image entrypoint)", c.ID)
	}
	if rootfsPath == "" {
		return "", fmt.Errorf("container %q: rootfsPath is required", c.ID)
	}

	bundleDir := filepath.Join(BundlesRoot, c.ID)
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir bundle %s: %w", bundleDir, err)
	}

	spec := buildSpec(podID, c, rootfsPath)
	b, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal config.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "config.json"), b, 0o644); err != nil {
		return "", fmt.Errorf("write config.json: %w", err)
	}
	return bundleDir, nil
}

// --- OCI spec types (subset) -------------------------------

type spec struct {
	OCIVersion string    `json:"ociVersion"`
	Process    *process  `json:"process"`
	Root       root      `json:"root"`
	Hostname   string    `json:"hostname,omitempty"`
	Mounts     []mount   `json:"mounts"`
	Linux      *linuxCfg `json:"linux,omitempty"`
}

type process struct {
	Terminal        bool     `json:"terminal"`
	User            user     `json:"user"`
	Args            []string `json:"args"`
	Env             []string `json:"env,omitempty"`
	Cwd             string   `json:"cwd"`
	Capabilities    *capSet  `json:"capabilities,omitempty"`
	Rlimits         []rlimit `json:"rlimits,omitempty"`
	NoNewPrivileges bool     `json:"noNewPrivileges,omitempty"`
}

type user struct {
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}

type capSet struct {
	Bounding    []string `json:"bounding,omitempty"`
	Permitted   []string `json:"permitted,omitempty"`
	Effective   []string `json:"effective,omitempty"`
	Inheritable []string `json:"inheritable,omitempty"`
	Ambient     []string `json:"ambient,omitempty"`
}

type rlimit struct {
	Type string `json:"type"`
	Hard uint64 `json:"hard"`
	Soft uint64 `json:"soft"`
}

type root struct {
	Path     string `json:"path"`
	Readonly bool   `json:"readonly"`
}

type mount struct {
	Destination string   `json:"destination"`
	Type        string   `json:"type,omitempty"`
	Source      string   `json:"source,omitempty"`
	Options     []string `json:"options,omitempty"`
}

type linuxCfg struct {
	Namespaces    []namespace `json:"namespaces"`
	Resources     *resources  `json:"resources,omitempty"`
	MaskedPaths   []string    `json:"maskedPaths,omitempty"`
	ReadonlyPaths []string    `json:"readonlyPaths,omitempty"`
}

type namespace struct {
	Type string `json:"type"`
	Path string `json:"path,omitempty"`
}

type resources struct {
	Memory *memory `json:"memory,omitempty"`
	CPU    *cpu    `json:"cpu,omitempty"`
	Pids   *pids   `json:"pids,omitempty"`
}

type memory struct {
	Limit *int64 `json:"limit,omitempty"`
}

type cpu struct {
	Shares *uint64 `json:"shares,omitempty"`
}

type pids struct {
	Limit int64 `json:"limit"`
}

// --- builder ------------------------------------------------

func buildSpec(podID string, c *pod.Container, rootfsPath string) spec {
	uid, gid := parseUser(c.User)

	args := append([]string{}, c.Command...)
	args = append(args, c.Args...)

	env := mergeEnv(defaultEnv(), c.Env)

	caps := defaultCaps(c.Privileged)

	mounts := defaultMounts()
	for _, m := range c.Mounts {
		mounts = append(mounts, mount{
			Destination: m.Destination,
			Source:      m.Source,
			Type:        m.Type,
			Options:     m.Options,
		})
	}

	cwd := c.Workdir
	if cwd == "" {
		cwd = "/"
	}

	return spec{
		OCIVersion: ociVersion,
		Process: &process{
			Terminal: false,
			User:     user{UID: uid, GID: gid},
			Args:     args,
			Env:      env,
			Cwd:      cwd,
			Capabilities: &capSet{
				Bounding: caps, Permitted: caps, Effective: caps,
			},
			Rlimits:         defaultRlimits(),
			NoNewPrivileges: !c.Privileged,
		},
		Root:     root{Path: rootfsPath, Readonly: false},
		Hostname: podID,
		Mounts:   mounts,
		Linux: &linuxCfg{
			Namespaces:    namespacesFromEnv(),
			Resources:     buildResources(c.Resources),
			MaskedPaths:   defaultMaskedPaths(),
			ReadonlyPaths: defaultReadonlyPaths(),
		},
	}
}

// namespacesFromEnv reads $WEFT_BUNDLE_NAMESPACES — a comma-separated list
// of OCI namespace types to request in the generated bundle. Defaults to
// the conventional Docker-style set when unset or empty:
//
//	pid,network,ipc,uts,mount
//
// The override exists to bisect a TCG/arm64 crun-create wedge ([[qemu-
// microvm-9p]] open issue): setting it to "" or "uts" or "" lets us
// confirm/exclude clone3-with-namespaces as the hang site without
// rebuilding the binary for every variant. Production callers leave it
// unset; the dev harness sets it explicitly.
func namespacesFromEnv() []namespace {
	const env = "WEFT_BUNDLE_NAMESPACES"
	raw, ok := os.LookupEnv(env)
	if !ok {
		return []namespace{
			{Type: "pid"},
			{Type: "network"},
			{Type: "ipc"},
			{Type: "uts"},
			{Type: "mount"},
		}
	}
	// Empty value is meaningful — it asks for zero namespaces (share
	// host's pid/net/mount/…). Single-token "none" is a synonym.
	if raw == "" || raw == "none" {
		return nil
	}
	out := make([]namespace, 0, 5)
	for _, t := range strings.Split(raw, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			out = append(out, namespace{Type: t})
		}
	}
	return out
}

func parseUser(s string) (uid, gid uint32) {
	if s == "" {
		return 0, 0
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		u, _ := strconv.ParseUint(s[:i], 10, 32)
		g, _ := strconv.ParseUint(s[i+1:], 10, 32)
		return uint32(u), uint32(g)
	}
	u, _ := strconv.ParseUint(s, 10, 32)
	return uint32(u), uint32(u)
}

func buildResources(r pod.Resources) *resources {
	if r.MemBytes == 0 && r.CPUShares == 0 && r.PidsMax == 0 {
		return nil
	}
	out := &resources{}
	if r.MemBytes > 0 {
		lim := int64(r.MemBytes)
		out.Memory = &memory{Limit: &lim}
	}
	if r.CPUShares > 0 {
		s := r.CPUShares
		out.CPU = &cpu{Shares: &s}
	}
	if r.PidsMax > 0 {
		out.Pids = &pids{Limit: r.PidsMax}
	}
	return out
}

// mergeEnv folds the user-supplied env map onto the defaults with
// override-on-conflict + deterministic ordering. The OCI runtime
// honours the last instance of a duplicate key in Process.Env, so a
// naive append-from-map relied on Go map iteration order — meaning
// two consecutive Build()s of the same Container could emit byte-
// different config.json files, and a user override of PATH was won
// by whichever copy crun saw last (non-deterministic). The merge
// here :
//   - keeps `defaults` order for any default key not overridden,
//   - replaces a default value when c.Env names the same key,
//   - appends any new c.Env keys in sorted order (stable bytes
//     regardless of map enumeration).
//
// Pure ; unit-testable without a runtime.
func mergeEnv(defaults []string, overrides map[string]string) []string {
	out := make([]string, 0, len(defaults)+len(overrides))
	consumed := make(map[string]struct{}, len(overrides))
	for _, d := range defaults {
		k, _, ok := strings.Cut(d, "=")
		if !ok {
			out = append(out, d) // malformed default ; preserve verbatim
			continue
		}
		if v, has := overrides[k]; has {
			out = append(out, k+"="+v)
			consumed[k] = struct{}{}
			continue
		}
		out = append(out, d)
	}
	// Remaining override keys, in sorted order, so equal inputs produce
	// equal outputs across Go versions + builds.
	remaining := make([]string, 0, len(overrides)-len(consumed))
	for k := range overrides {
		if _, done := consumed[k]; !done {
			remaining = append(remaining, k)
		}
	}
	sort.Strings(remaining)
	for _, k := range remaining {
		out = append(out, k+"="+overrides[k])
	}
	return out
}

// --- defaults (kept here, not user-tunable in MVP) ---------

func defaultEnv() []string {
	return []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"TERM=xterm",
	}
}

// defaultCaps is the runc/Docker default capability set. For
// Privileged containers we widen to a superset but still avoid
// the truly dangerous ones unless explicitly enabled.
func defaultCaps(privileged bool) []string {
	base := []string{
		"CAP_AUDIT_WRITE",
		"CAP_CHOWN",
		"CAP_DAC_OVERRIDE",
		"CAP_FOWNER",
		"CAP_FSETID",
		"CAP_KILL",
		"CAP_MKNOD",
		"CAP_NET_BIND_SERVICE",
		"CAP_NET_RAW",
		"CAP_SETFCAP",
		"CAP_SETGID",
		"CAP_SETPCAP",
		"CAP_SETUID",
		"CAP_SYS_CHROOT",
	}
	if !privileged {
		return base
	}
	return append(base,
		"CAP_SYS_ADMIN",
		"CAP_NET_ADMIN",
		"CAP_SYS_PTRACE",
	)
}

func defaultRlimits() []rlimit {
	return []rlimit{{Type: "RLIMIT_NOFILE", Hard: 1024, Soft: 1024}}
}

func defaultMounts() []mount {
	return []mount{
		{Destination: "/proc", Type: "proc", Source: "proc"},
		{
			Destination: "/dev", Type: "tmpfs", Source: "tmpfs",
			Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"},
		},
		{
			Destination: "/dev/pts", Type: "devpts", Source: "devpts",
			Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"},
		},
		{
			Destination: "/dev/shm", Type: "tmpfs", Source: "shm",
			Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"},
		},
		{
			Destination: "/dev/mqueue", Type: "mqueue", Source: "mqueue",
			Options: []string{"nosuid", "noexec", "nodev"},
		},
		{
			Destination: "/sys", Type: "sysfs", Source: "sysfs",
			Options: []string{"nosuid", "noexec", "nodev", "ro"},
		},
	}
}

func defaultMaskedPaths() []string {
	return []string{
		"/proc/acpi",
		"/proc/asound",
		"/proc/kcore",
		"/proc/keys",
		"/proc/latency_stats",
		"/proc/timer_list",
		"/proc/timer_stats",
		"/proc/sched_debug",
		"/sys/firmware",
		"/proc/scsi",
	}
}

func defaultReadonlyPaths() []string {
	return []string{
		"/proc/bus",
		"/proc/fs",
		"/proc/irq",
		"/proc/sys",
		"/proc/sysrq-trigger",
	}
}
