//go:build linux

// Package supervisor owns the two PID-1 responsibilities of
// weft-init: (1) reaping every orphaned child the kernel reparents
// to us, and (2) supervising the user-declared containers — start,
// watch, restart per policy, stop cleanly.
//
// Splitting them matters: the reaper must run unconditionally even
// for processes we never started (containerd-style runtimes fork
// helpers we don't track), whereas the supervisor only watches the
// PIDs it knows about.
package supervisor

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// Reaper consumes SIGCHLD and Wait4()'s every child the kernel
// hands us. Exits the goroutine cleanly when ctx is cancelled.
//
// Reaped child PIDs and their status are published on the returned
// channel so the per-container Supervisor can correlate exits to
// containers it cares about. The channel is closed when the reaper
// exits.
type Reaper struct {
	log    *slog.Logger
	events chan Reaped
}

// Reaped is one zombie collection event.
type Reaped struct {
	PID    int
	Status syscall.WaitStatus
	Rusage syscall.Rusage
}

func NewReaper(log *slog.Logger) *Reaper {
	return &Reaper{log: log, events: make(chan Reaped, 64)}
}

// Events returns the channel of reaped children. Receivers MUST
// drain it ; a full buffer drops events to the log (zombies are
// already cleaned, only correlation is lost).
func (r *Reaper) Events() <-chan Reaped { return r.events }

// Run blocks until ctx is cancelled. It must be called exactly
// once. Subscribes to SIGCHLD before doing the initial drain so we
// don't miss any signal that arrived before we were ready.
func (r *Reaper) Run(ctx context.Context) {
	defer close(r.events)
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGCHLD)
	defer signal.Stop(sigCh)

	// Initial drain — covers the race where children exited
	// before we started listening.
	r.drain()

	for {
		select {
		case <-ctx.Done():
			r.drain()
			return
		case <-sigCh:
			r.drain()
		}
	}
}

func (r *Reaper) drain() {
	for {
		var ws syscall.WaitStatus
		var ru syscall.Rusage
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, &ru)
		if err != nil || pid <= 0 {
			// ECHILD = "no more children" ; EINTR = retry safe via loop exit.
			return
		}
		ev := Reaped{PID: pid, Status: ws, Rusage: ru}
		select {
		case r.events <- ev:
		default:
			r.log.Warn("reaper event channel full, dropping correlation", "pid", pid)
		}
	}
}
