//go:build linux

package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/openweft/weft-microvm-init/pkg/pod"
	"github.com/openweft/weft-microvm-init/pkg/runtime"
)

// Supervisor drives the lifecycle of one Pod's containers via an
// OCI runtime. It does NOT prepare the bundles (rootfs unpacking
// and config.json generation live in the bundler package); it
// receives ready-to-run bundle directories and a runtime client.
type Supervisor struct {
	log     *slog.Logger
	rt      runtime.Runtime
	reaper  *Reaper
	spec    *pod.Spec
	bundles map[string]string // container ID → bundle dir

	mu       sync.Mutex
	states   map[string]*containerState
	pidIndex map[int]string // runtime-reported PID → container ID
}

type containerState struct {
	id          string
	restart     pod.RestartPolicy
	starts      int
	lastStart   time.Time
	lastExit    *Reaped
	pid         int
	stopped     bool
	stoppedOnce sync.Once
	done        chan struct{}
}

func New(log *slog.Logger, rt runtime.Runtime, reaper *Reaper, spec *pod.Spec, bundles map[string]string) *Supervisor {
	return &Supervisor{
		log:      log,
		rt:       rt,
		reaper:   reaper,
		spec:     spec,
		bundles:  bundles,
		states:   make(map[string]*containerState, len(spec.Containers)),
		pidIndex: make(map[int]string),
	}
}

// Run starts every container and blocks until ctx is cancelled OR
// all non-restarting containers have exited. Returns the first
// fatal error encountered ; per-container failures with a restart
// policy are not fatal.
func (s *Supervisor) Run(ctx context.Context) error {
	for i := range s.spec.Containers {
		c := &s.spec.Containers[i]
		st := &containerState{
			id:      c.ID,
			restart: c.Restart,
			done:    make(chan struct{}),
		}
		s.mu.Lock()
		s.states[c.ID] = st
		s.mu.Unlock()

		if err := s.startOne(ctx, c, st); err != nil {
			return fmt.Errorf("start %s: %w", c.ID, err)
		}
	}

	go s.consumeReaper(ctx)

	// Wait for all containers to be "done" (exited with no further
	// restart) — or for ctx cancellation.
	for _, c := range s.spec.Containers {
		st := s.states[c.ID]
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-st.done:
		}
	}
	return nil
}

func (s *Supervisor) startOne(ctx context.Context, c *pod.Container, st *containerState) error {
	bundle, ok := s.bundles[c.ID]
	if !ok {
		return fmt.Errorf("no bundle prepared for container %q", c.ID)
	}
	// Diagnostic breadcrumbs: under TCG with 9p-backed rootfs, runtime
	// Create/Start/State can each take a noticeable wallclock — without
	// these we can't tell whether a hang is in fork+exec, namespace
	// setup, cgroup write, or the runtime's own initialisation. Cheap
	// to keep at INFO so a stuck microVM is debuggable from console.log
	// alone, no in-guest shell required.
	s.log.Info("runtime create starting", "container", c.ID, "bundle", bundle, "runtime", s.rt.Name())
	// The container inherits whatever stdio crun is given. Hand it the CONSOLE,
	// not the parent's capture pipe: exec.Cmd with a bytes.Buffer builds an
	// os.Pipe and waits for every writer to close it, and the container init
	// holds that pipe open for its whole life -- so `crun create` returned only
	// when the container exited, which for a service is never. The console is
	// also where `weft microvm logs` reads from, so the output lands where a
	// user already looks.
	stdio := runtime.Stdio{}
	if con, err := os.OpenFile("/dev/console", os.O_WRONLY, 0); err == nil {
		defer con.Close()
		stdio.Stdout, stdio.Stderr = con, con
	} else {
		s.log.Warn("no console for container stdio (falling back to a pipe)", "err", err)
	}
	if err := s.rt.Create(ctx, c.ID, bundle, stdio); err != nil {
		return err
	}
	s.log.Info("runtime create done; starting", "container", c.ID)
	if err := s.rt.Start(ctx, c.ID); err != nil {
		_ = s.rt.Delete(ctx, c.ID)
		return err
	}
	s.log.Info("runtime start done; resolving state", "container", c.ID)
	// Resolve PID after Start ; the runtime's state command knows.
	_, pid, err := s.rt.State(ctx, c.ID)
	if err != nil {
		s.log.Warn("state lookup after start failed", "container", c.ID, "err", err)
	}
	s.mu.Lock()
	st.pid = pid
	st.starts++
	st.lastStart = time.Now()
	if pid > 0 {
		s.pidIndex[pid] = c.ID
	}
	s.mu.Unlock()
	s.log.Info("container started", "id", c.ID, "pid", pid, "restart", st.starts)
	return nil
}

// consumeReaper correlates reaped PIDs to containers and applies
// the restart policy. Reaper events for PIDs we don't know about
// (intermediate runtime helpers) are silently ignored — the reap
// itself already collected the zombie.
func (s *Supervisor) consumeReaper(ctx context.Context) {
	for ev := range s.reaper.Events() {
		s.mu.Lock()
		id, ok := s.pidIndex[ev.PID]
		if !ok {
			s.mu.Unlock()
			continue
		}
		delete(s.pidIndex, ev.PID)
		st := s.states[id]
		st.lastExit = &ev
		s.mu.Unlock()

		s.log.Info("container exited",
			"id", id,
			"pid", ev.PID,
			"exit", ev.Status.ExitStatus(),
			"signaled", ev.Status.Signaled(),
		)

		// Best-effort delete to free runtime state.
		_ = s.rt.Delete(ctx, id)

		if s.shouldRestart(st, ev) {
			c := s.findSpec(id)
			if c == nil {
				close(st.done)
				continue
			}
			if err := s.startOne(ctx, c, st); err != nil {
				s.log.Error("restart failed", "id", id, "err", err)
				close(st.done)
			}
			continue
		}
		close(st.done)
	}
}

func (s *Supervisor) shouldRestart(st *containerState, ev Reaped) bool {
	if st.stopped {
		return false
	}
	switch st.restart {
	case pod.RestartAlways:
		return true
	case pod.RestartOnFailure:
		return ev.Status.ExitStatus() != 0 || ev.Status.Signaled()
	default:
		return false
	}
}

func (s *Supervisor) findSpec(id string) *pod.Container {
	for i := range s.spec.Containers {
		if s.spec.Containers[i].ID == id {
			return &s.spec.Containers[i]
		}
	}
	return nil
}

// Stop sends SIGTERM to every still-running container, waits up to
// grace, then SIGKILLs survivors. Disables restart for the remainder
// of the supervisor's life.
func (s *Supervisor) Stop(ctx context.Context, grace time.Duration) {
	s.mu.Lock()
	for _, st := range s.states {
		st.stoppedOnce.Do(func() { st.stopped = true })
	}
	ids := make([]string, 0, len(s.states))
	for id := range s.states {
		ids = append(ids, id)
	}
	s.mu.Unlock()

	for _, id := range ids {
		if err := s.rt.Kill(ctx, id, "TERM"); err != nil && !errors.Is(err, syscall.ESRCH) {
			s.log.Warn("SIGTERM failed", "id", id, "err", err)
		}
	}

	deadline := time.After(grace)
	for {
		if s.allExited() {
			return
		}
		select {
		case <-deadline:
			for _, id := range ids {
				_ = s.rt.Kill(ctx, id, "KILL")
			}
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (s *Supervisor) allExited() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.states {
		if st.lastExit == nil {
			return false
		}
	}
	return true
}
