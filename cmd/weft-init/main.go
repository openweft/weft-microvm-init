//go:build linux

// weft-init is the PID-1 binary that boots inside an openweft
// micro-VM. It mounts the pseudo-filesystems the OCI runtime
// requires, configures pod-level networking, locates the pod spec
// dropped by the host (virtio-fs share or kernel cmdline), then
// hands control to the supervisor which exec's crun for each
// container in the pod.
//
// The init is intentionally tiny — no daemon framework, no plugin
// model, no config file format beyond pod.Spec JSON. It is replaced
// rather than extended.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/openweft/weft-microvm-init/pkg/bundler"
	"github.com/openweft/weft-microvm-init/pkg/network"
	"github.com/openweft/weft-microvm-init/pkg/pod"
	"github.com/openweft/weft-microvm-init/pkg/runtime/crun"
	"github.com/openweft/weft-microvm-init/pkg/supervisor"
)

// guestPath is where the runner places the helper binaries (crun, …) in
// the initramfs; weft-init puts it on $PATH so the runtime resolves them.
const guestPath = "/bin:/usr/bin:/sbin"

const (
	// The config share is mounted read-only on a sub-dir of /run/weft so that
	// /run/weft itself stays writable for the rootfs/, shares/, bundles/ and
	// crun-runtime trees mountShares + prepareBundles populate next.
	defaultPodSpecPath   = "/run/weft/cfg/pod.json"
	defaultWireGuardPath = "/run/weft/cfg/wireguard.json"
	stopGrace            = 10 * time.Second
)

func main() {
	specPath := flag.String("spec", defaultPodSpecPath, "path to pod.json")
	debug := flag.Bool("debug", false, "verbose logging")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

	if err := run(log, *specPath); err != nil {
		log.Error("init failed", "err", err)
		// PID 1 must never `return` to userspace — kernel panics if it does.
		// Power off cleanly so the host sees a clean shutdown rather than a hang.
		poweroff(log, 3*time.Second)
	}
	poweroff(log, 0)
}

func run(log *slog.Logger, specPath string) error {
	log.Info("weft-init starting", "pid", os.Getpid(), "spec", specPath)
	os.Setenv("PATH", guestPath) // resolve crun (and friends) from the initramfs
	// WEFT_BUNDLE_NAMESPACES is read by bundler.namespacesFromEnv when the
	// generated bundle is built. Unset (production default) means the
	// conventional Docker-style {pid,network,ipc,uts,mount} set; the host
	// can set it via `weft.env=WEFT_BUNDLE_NAMESPACES=...` on the cmdline
	// to bisect TCG/clone3 issues — see the open finding in
	// [[qemu-microvm-9p]] where any namespace flag hangs clone3 under
	// QEMU/TCG arm64 (so production needs Apple-VZ or KVM, not TCG).
	if v, ok := cmdlineEnv("WEFT_BUNDLE_NAMESPACES"); ok {
		os.Setenv("WEFT_BUNDLE_NAMESPACES", v)
	}

	if err := mountPseudoFS(log); err != nil {
		return fmt.Errorf("pseudo-fs: %w", err)
	}

	if err := mountConfigShare(log, specPath); err != nil {
		return fmt.Errorf("config share: %w", err)
	}

	spec, err := pod.Load(specPath)
	if err != nil {
		// Convention documented on mountConfigShare: when no pod.json
		// arrives (the single-container `weft microvm run <image>`
		// shorthand emits no config share, only `weft.rootfs=<t>:<tag>`
		// on the cmdline), synthesise an implicit one-container pod
		// pointing at that rootfs share. This is what makes the
		// `run`-mode datapath equivalent to a multi-container pod with
		// one entry — same mountShares/prepareBundles/supervisor flow.
		if os.IsNotExist(err) {
			if synth := synthSingleContainerPod(); synth != nil {
				spec = synth
				log.Info("synthesised single-container pod from cmdline", "rootfs_tag", synth.Containers[0].RootfsTag)
			} else {
				return fmt.Errorf("load pod spec: %w (and no weft.rootfs= cmdline fallback)", err)
			}
		} else {
			return fmt.Errorf("load pod spec: %w", err)
		}
	}
	log.Info("pod loaded", "pod_id", spec.PodID, "containers", len(spec.Containers))

	if err := mountShares(log, spec); err != nil {
		return fmt.Errorf("shares: %w", err)
	}

	if err := network.Apply(spec.Network); err != nil {
		return fmt.Errorf("network: %w", err)
	}

	// The overlay can come from the pod spec itself or, when the host
	// provisions it independently, from a standalone wireguard.json the
	// config share drops next to pod.json.
	wg := spec.WireGuard
	if wg == nil {
		if wg, err = pod.LoadWireGuard(defaultWireGuardPath); err != nil {
			return fmt.Errorf("wireguard config: %w", err)
		}
	}
	if wg != nil {
		if err := network.ApplyWireGuard(wg); err != nil {
			return fmt.Errorf("wireguard: %w", err)
		}
		log.Info("wireguard overlay up", "address", wg.Address, "peers", len(wg.Peers))
	}

	bundles, err := prepareBundles(log, spec)
	if err != nil {
		return fmt.Errorf("bundles: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reaper := supervisor.NewReaper(log)
	go reaper.Run(ctx)

	// crun ships in the initramfs at /bin/crun (placed by the runner via
	// initbuild.PodInitrd) and is resolved from $PATH — no embed/extract.
	rt := crun.New()

	// Sanity-poke the OCI runtime before handing it the namespaced
	// container create. Logs the version string (and any exec/dynamic-
	// link failure) so a hang inside `crun create` is distinguishable
	// from "crun never ran at all" — the latter surfaces here as an
	// immediate error rather than a silent block past prepareBundles.
	// Cheap: one exec + stdout copy, no namespace or cgroup work.
	if out, err := exec.Command("crun", "--version").CombinedOutput(); err != nil {
		log.Warn("crun --version probe failed", "err", err, "out", string(out))
	} else {
		log.Info("crun probe", "version", strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0]))
	}

	sup := supervisor.New(log, rt, reaper, spec, bundles)

	// Forward termination signals from the hypervisor (sent on
	// guest shutdown request) into a graceful Stop.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		log.Info("shutdown signal received")
		sup.Stop(ctx, stopGrace)
		cancel()
	}()

	return sup.Run(ctx)
}

// mountPseudoFS sets up the kernel filesystems a container runtime
// expects. Idempotent: existing mounts are skipped.
func mountPseudoFS(log *slog.Logger) error {
	type m struct {
		source, target, fstype string
		flags                  uintptr
		data                   string
	}
	mounts := []m{
		{"proc", "/proc", "proc", 0, ""},
		{"sysfs", "/sys", "sysfs", 0, ""},
		{"devtmpfs", "/dev", "devtmpfs", 0, "mode=0755"},
		{"devpts", "/dev/pts", "devpts", 0, "newinstance,ptmxmode=0666"},
		{"tmpfs", "/dev/shm", "tmpfs", 0, "mode=1777"},
		{"tmpfs", "/run", "tmpfs", 0, "mode=0755"},
		{"cgroup2", "/sys/fs/cgroup", "cgroup2", 0, "nsdelegate"},
	}
	for _, x := range mounts {
		// MkdirAll can fail under sysfs (read-only to userspace) when
		// the kernel hasn't pre-populated the path — e.g. /sys/fs/cgroup
		// isn't always there before cgroup2 is mounted. Demote the
		// failure to a warning; if the dir really is missing the mount
		// below will fail too and that branch already logs+continues.
		if err := os.MkdirAll(x.target, 0o755); err != nil {
			log.Warn("mkdir failed (continuing)", "target", x.target, "err", err)
		}
		if err := syscall.Mount(x.source, x.target, x.fstype, x.flags, x.data); err != nil {
			if err == syscall.EBUSY {
				continue // already mounted
			}
			log.Warn("mount failed (continuing)", "target", x.target, "fs", x.fstype, "err", err)
		}
	}
	return nil
}

// mountConfigShare mounts the host-directory config share that carries
// pod.json, following the kernel cmdline convention
// "weft.config=<transport>:<tag>", at the spec's parent dir
// (/run/weft/cfg). Mounted read-only on a dedicated sub-dir so /run/weft
// itself stays writable for the rootfs/, shares/, bundles/ and crun-
// runtime trees mountShares + prepareBundles populate next. Mirrors
// weft-microvm-init's "weft.rootfs=virtiofs:<tag>" convention.
//
// Transport is virtio-fs by default (Apple-VZ backend). The QEMU backend
// passes "weft.transport=9p" on the cmdline so the share is mounted with
// the 9p kernel client instead — see [[qemu-microvm-9p]] for why.
//
// Skipped when --spec points somewhere other than the default
// (dev/test boots where the file is already present), or when no
// weft.config token is on the cmdline (spec baked into initramfs).
func mountConfigShare(log *slog.Logger, specPath string) error {
	if specPath != defaultPodSpecPath {
		return nil
	}
	tag := stripTransportPrefix(cmdlineValue("weft.config"))
	if tag == "" {
		return nil
	}
	dir := filepath.Dir(specPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	fstype, data := shareMountTransport()
	if err := syscall.Mount(tag, dir, fstype, syscall.MS_RDONLY, data); err != nil {
		return fmt.Errorf("%s config %s → %s: %w", fstype, tag, dir, err)
	}
	log.Info("config share mounted", "tag", tag, "at", dir, "fstype", fstype)
	return nil
}

// shareMountTransport picks the (fs type, mount-data) pair to use for
// rootfs/config/data shares, based on the kernel cmdline
// `weft.transport=...` hint set by the host hypervisor backend.
//
//   - virtio-fs (default, Apple-VZ backend on macOS): fstype "virtiofs",
//     no extra mount data — the VZ framework wires the virtiofs device.
//   - 9p (QEMU backend, where virtio-fs needs the Linux-only virtiofsd
//     daemon and can't be used on a macOS host): fstype "9p" with
//     "trans=virtio,version=9p2000.L" so the kernel binds to the
//     virtio-9p transport rather than e.g. tcp.
//
// Pure / side-effect-free apart from reading /proc/cmdline once.
func shareMountTransport() (fstype, data string) {
	switch cmdlineValue("weft.transport") {
	case "9p":
		return "9p", "trans=virtio,version=9p2000.L"
	default:
		return "virtiofs", ""
	}
}

// synthSingleContainerPod builds an in-memory pod.Spec from the kernel
// cmdline when no pod.json file is present. It implements the convention
// the mountConfigShare doc-comment refers to: the `weft microvm run
// <image>` shorthand emits only `weft.rootfs=<transport>:<tag>` on the
// guest cmdline (no config share, no pod.json), and weft-init turns that
// into a one-container pod that runs /bin/sh against the share's rootfs.
//
// Returns nil when there's nothing to synthesise from — the caller treats
// that as "really no spec, surface the load error". When the cmdline does
// carry an weft.rootfs value, the synthesised spec re-uses the normal
// mountShares/prepareBundles/supervisor flow; only the source of the
// spec differs.
func synthSingleContainerPod() *pod.Spec {
	tag := stripTransportPrefix(cmdlineValue("weft.rootfs"))
	if tag == "" {
		return nil
	}
	// The mount_point is what prepareBundles' fallback path also expects
	// (/run/weft/rootfs/<id>), so the same code path handles both
	// explicitly-mounted shares and this synthesised one.
	const id = "main"
	return &pod.Spec{
		PodID: "single",
		Containers: []pod.Container{
			{
				ID:        id,
				RootfsTag: tag,
				// /bin/sh is universal across busybox/musl distros (alpine,
				// debian, …) and gives an immediate, observable proof that
				// the rootfs share is mounted and exec-able. Override-able
				// once weft microvm run grows a pod-spec emission path.
				Command: []string{"/bin/sh"},
			},
		},
		Shares: []pod.Share{
			{Tag: tag, MountPoint: "/run/weft/rootfs/" + id},
		},
	}
}

// stripTransportPrefix removes a leading "<transport>:" from cmdline values
// like weft.config=virtiofs:cfg or weft.config=9p:cfg — anything before the
// first colon is treated as a (now redundant) transport hint and discarded.
// Values without a colon pass through verbatim, so "weft.config=cfg" still
// works and the cmdline-level weft.transport= hint owns the transport
// decision exclusively.
func stripTransportPrefix(v string) string {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		return v[i+1:]
	}
	return v
}

// cmdlineEnv extracts one environment binding from the merged weft.env
// cmdline value, e.g. cmdline `weft.env=K1=V1:K2=V2:WEFT_BUNDLE_NAMESPACES=`
// → cmdlineEnv("WEFT_BUNDLE_NAMESPACES") returns ("", true). The colon
// delimiter mirrors weft/adapter.go's mergeProjectEnv format. Returns
// (_, false) when the key isn't present — the caller decides whether
// missing means "use the default" or "intentionally empty".
func cmdlineEnv(key string) (string, bool) {
	raw := cmdlineValue("weft.env")
	if raw == "" {
		return "", false
	}
	pfx := key + "="
	for _, kv := range strings.Split(raw, ":") {
		if v, ok := strings.CutPrefix(kv, pfx); ok {
			return v, true
		}
	}
	return "", false
}

// cmdlineValue returns the value of the first key=<value> token on
// /proc/cmdline, or "" if absent.
func cmdlineValue(key string) string {
	b, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}
	for _, tok := range strings.Fields(string(b)) {
		if v, ok := strings.CutPrefix(tok, key+"="); ok {
			return v
		}
	}
	return ""
}

// mountShares mounts the host-directory shares declared in the pod spec
// at their requested paths. These typically carry container rootfs
// directories prepared on the host. The transport (virtio-fs vs 9p) is
// chosen once per VM via shareMountTransport() — see [[qemu-microvm-9p]].
func mountShares(log *slog.Logger, spec *pod.Spec) error {
	fstype, data := shareMountTransport()
	for _, sh := range spec.Shares {
		if err := os.MkdirAll(sh.MountPoint, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", sh.MountPoint, err)
		}
		flags := uintptr(0)
		if sh.Readonly {
			flags |= syscall.MS_RDONLY
		}
		if err := syscall.Mount(sh.Tag, sh.MountPoint, fstype, flags, data); err != nil {
			return fmt.Errorf("%s %s → %s: %w", fstype, sh.Tag, sh.MountPoint, err)
		}
		log.Info("share mounted", "tag", sh.Tag, "at", sh.MountPoint, "ro", sh.Readonly, "fstype", fstype)
	}
	return nil
}

// prepareBundles generates an OCI bundle (config.json + rootfs
// pointer) for each container in the pod. The rootfs is resolved
// from the matching virtio-fs share ; the bundler writes the
// config.json under /run/weft/bundles/<id>/ and that's the
// directory the OCI runtime is invoked against.
func prepareBundles(log *slog.Logger, spec *pod.Spec) (map[string]string, error) {
	out := make(map[string]string, len(spec.Containers))
	for i := range spec.Containers {
		c := &spec.Containers[i]
		rootfs := resolveRootfs(spec, c)
		if rootfs == "" {
			return nil, fmt.Errorf("container %q: no rootfs (no share with tag %q)", c.ID, c.RootfsTag)
		}
		bundleDir, err := bundler.Build(spec.PodID, c, rootfs)
		if err != nil {
			return nil, fmt.Errorf("container %q: %w", c.ID, err)
		}
		out[c.ID] = bundleDir
		log.Info("bundle built", "container", c.ID, "bundle", bundleDir, "rootfs", rootfs)
	}
	return out, nil
}

func resolveRootfs(spec *pod.Spec, c *pod.Container) string {
	for _, sh := range spec.Shares {
		if sh.Tag == c.RootfsTag {
			return sh.MountPoint
		}
	}
	// Fallback: a host that prefers initrd-unpacked rootfs can
	// place it directly at this conventional path.
	fallback := filepath.Join("/run/weft/rootfs", c.ID)
	if _, err := os.Stat(fallback); err == nil {
		return fallback
	}
	return ""
}

// poweroff issues the Linux reboot syscall after an optional delay.
// PID 1 must never exit ; this is the canonical way to bring the
// guest down so the hypervisor sees a clean state.
func poweroff(log *slog.Logger, delay time.Duration) {
	if delay > 0 {
		time.Sleep(delay)
	}
	log.Info("powering off")
	syscall.Sync()
	if err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF); err != nil {
		log.Error("reboot syscall failed", "err", err)
		// Last resort: spin forever rather than returning to the kernel.
		select {}
	}
}
