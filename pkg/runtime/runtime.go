// Package runtime is the abstraction over the OCI runtime binary
// (crun, runc, youki) that weft-init exec's to create containers.
//
// weft-init never enters container namespaces itself ; it stays a
// clean PID 1 that exec()s a runtime which becomes the parent of
// the workload. The runtime returns once the container is running
// (detached mode) ; weft-init then supervises via PID and the
// runtime's `state` / `kill` / `delete` subcommands.
package runtime

import (
	"context"
	"io"
)

// Runtime is the surface weft-init needs from any OCI runtime.
// Implementations should be cheap to construct ; the heavy lifting
// is in Create/Start.
type Runtime interface {
	// Name is a short identifier ("crun", "runc"). Used in logs.
	Name() string

	// Create writes the OCI bundle at bundleDir (config.json +
	// rootfs/) into the runtime's state and creates the container
	// in the "created" state. Stdio is wired to the given pipes ;
	// pass nil for /dev/null.
	Create(ctx context.Context, id, bundleDir string, stdio Stdio) error

	// Start transitions a created container to "running". Returns
	// once the container's entrypoint has been exec'd.
	Start(ctx context.Context, id string) error

	// State returns the container's runtime state ("created",
	// "running", "stopped"). Empty string + nil error means
	// "unknown to the runtime" (already deleted).
	State(ctx context.Context, id string) (status string, pid int, err error)

	// Kill sends a signal to the container's init process. signal
	// is a name like "TERM", "KILL", "HUP".
	Kill(ctx context.Context, id, signal string) error

	// Delete removes the container's state. Must be called once
	// the container is stopped, otherwise the runtime leaks state
	// directories.
	Delete(ctx context.Context, id string) error
}

// Stdio wires container fd 0/1/2 to host-side readers/writers.
// Any field may be nil ; the runtime substitutes /dev/null.
type Stdio struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}
