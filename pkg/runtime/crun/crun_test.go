package crun

import (
	"context"
	"strings"
	"testing"
)

// TestCreatePassesNoPivot: PID 1 of a microVM lives on the INITRAMFS, and the
// kernel refuses pivot_root when the old root is the initial ramfs. crun then
// fails with a bare "pivot_root: Invalid argument" and the pod never starts —
// measured on an alpine guest before this flag was passed.
func TestCreatePassesNoPivot(t *testing.T) {
	r := &Runtime{Binary: "/bin/echo"}
	c := r.cmd(context.Background(), "create", "--no-pivot", "--bundle", "/b", "id")
	joined := strings.Join(c.Args, " ")
	if !strings.Contains(joined, "--no-pivot") {
		t.Fatalf("args = %q; the initramfs root needs --no-pivot", joined)
	}
	if !strings.Contains(joined, "--bundle /b") || !strings.HasSuffix(joined, " id") {
		t.Errorf("args = %q; the bundle and id must survive the new flag", joined)
	}
}
