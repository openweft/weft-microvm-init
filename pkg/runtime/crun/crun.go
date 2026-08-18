// Package crun implements runtime.Runtime by exec'ing the `crun`
// binary. crun is preferred over runc in micro-VM environments
// because it's a ~500KB static C binary with measurably faster
// container start (~2× vs runc on cold boot) — important when the
// VM boot budget is in the hundreds of milliseconds.
//
// The same code works against `runc` by passing a different Binary;
// surface is identical except for one trivial flag difference that
// we paper over.
package crun

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/openweft/weft-microvm-init/pkg/runtime"
)

// Runtime is an OCI runtime invoked as an external binary.
type Runtime struct {
	// Binary is the absolute path of the runtime executable. Defaults
	// to "crun" (PATH lookup) when empty.
	Binary string
	// Root is the runtime state directory (default /run/weft/<binary>).
	Root string
}

func New() *Runtime { return &Runtime{Binary: "crun", Root: "/run/weft/crun"} }

// NewRunc returns a Runtime configured for the runc binary. Use
// when you want the all-Go runtime ecosystem at the cost of a
// small cgo bootstrap in runc itself (the nsenter constructor) ;
// pair with a runc binary built CGO_ENABLED=1 -tags=. The CLI
// surface is identical to crun.
func NewRunc() *Runtime { return &Runtime{Binary: "runc", Root: "/run/weft/runc"} }

func (r *Runtime) Name() string {
	if r.Binary == "" {
		return "crun"
	}
	return r.Binary
}

func (r *Runtime) cmd(ctx context.Context, args ...string) *exec.Cmd {
	full := []string{}
	if r.Root != "" {
		full = append(full, "--root", r.Root)
	}
	full = append(full, args...)
	return exec.CommandContext(ctx, r.binary(), full...)
}

func (r *Runtime) binary() string {
	if r.Binary == "" {
		return "crun"
	}
	return r.Binary
}

func (r *Runtime) Create(ctx context.Context, id, bundleDir string, stdio runtime.Stdio) error {
	// --no-pivot: PID 1 here lives on the INITRAMFS, and the kernel refuses
	// pivot_root when the old root is the initial ramfs -- crun comes back with
	// a bare "pivot_root: Invalid argument". --no-pivot switches it to
	// MS_MOVE + chroot, which is what runc grew the same flag for. The guest is
	// a single-container microVM, so the weaker isolation of chroot is bounded
	// by the VM boundary that is already there.
	c := r.cmd(ctx, "create", "--no-pivot", "--bundle", bundleDir, id)
	c.Stdin = stdio.Stdin
	c.Stdout = stdio.Stdout
	c.Stderr = stdio.Stderr
	if out, err := combinedRun(c); err != nil {
		return fmt.Errorf("%s create %s: %w: %s", r.Name(), id, err, out)
	}
	return nil
}

func (r *Runtime) Start(ctx context.Context, id string) error {
	c := r.cmd(ctx, "start", id)
	if out, err := combinedRun(c); err != nil {
		return fmt.Errorf("%s start %s: %w: %s", r.Name(), id, err, out)
	}
	return nil
}

func (r *Runtime) State(ctx context.Context, id string) (string, int, error) {
	c := r.cmd(ctx, "state", id)
	out, err := combinedRun(c)
	if err != nil {
		// Both crun and runc print "container <id> does not exist" on stderr ;
		// surface that as ("", 0, nil) so callers can treat it as "gone".
		if strings.Contains(string(out), "does not exist") {
			return "", 0, nil
		}
		return "", 0, fmt.Errorf("%s state %s: %w: %s", r.Name(), id, err, out)
	}
	status, pid := parseState(out)
	return status, pid, nil
}

func (r *Runtime) Kill(ctx context.Context, id, signal string) error {
	c := r.cmd(ctx, "kill", id, signal)
	if out, err := combinedRun(c); err != nil {
		return fmt.Errorf("%s kill %s %s: %w: %s", r.Name(), id, signal, err, out)
	}
	return nil
}

func (r *Runtime) Delete(ctx context.Context, id string) error {
	c := r.cmd(ctx, "delete", "--force", id)
	if out, err := combinedRun(c); err != nil {
		return fmt.Errorf("%s delete %s: %w: %s", r.Name(), id, err, out)
	}
	return nil
}

// combinedRun runs cmd and returns combined stdout+stderr regardless
// of error, so the caller can include diagnostics in the wrap.
func combinedRun(cmd *exec.Cmd) ([]byte, error) {
	var buf bytes.Buffer
	if cmd.Stdout == nil {
		cmd.Stdout = &buf
	}
	if cmd.Stderr == nil {
		cmd.Stderr = &buf
	}
	err := cmd.Run()
	return buf.Bytes(), err
}

// parseState extracts {status, pid} from `crun state` JSON without
// pulling in a JSON dep. The output is small and predictable:
//
//	{"ociVersion":"1.0.0","id":"foo","pid":1234,"status":"running",...}
//
// A misformatted result yields ("", 0) — the caller will retry.
func parseState(out []byte) (string, int) {
	var status string
	var pid int
	if i := bytes.Index(out, []byte(`"status":"`)); i >= 0 {
		rest := out[i+len(`"status":"`):]
		if j := bytes.IndexByte(rest, '"'); j > 0 {
			status = string(rest[:j])
		}
	}
	if i := bytes.Index(out, []byte(`"pid":`)); i >= 0 {
		rest := out[i+len(`"pid":`):]
		end := 0
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		if end > 0 {
			pid, _ = strconv.Atoi(string(rest[:end]))
		}
	}
	return status, pid
}
