package pod

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, dir, body string) {
	t.Helper()
	d := filepath.Join(dir, ".weft-microvm")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "config.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEnrichFromImage_DistrolessLikeConfig(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, root, `{
	  "process": {
	    "args": ["/usr/local/bin/weft-loom", "serve", "--config", "/etc/weft-loom/config.hcl"],
	    "env": ["PATH=/bin", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"],
	    "cwd": "/app",
	    "user": {"uid": 65532, "gid": 65532}
	  }
	}`)

	c := &Container{ID: "main", RootfsTag: "rootfs0"}
	if err := EnrichFromImage(c, root); err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if got := c.Command; len(got) != 4 || got[0] != "/usr/local/bin/weft-loom" {
		t.Errorf("Command = %v ; want resolved entrypoint", got)
	}
	if c.Workdir != "/app" {
		t.Errorf("Workdir = %q ; want /app", c.Workdir)
	}
	if c.User != "65532:65532" {
		t.Errorf("User = %q ; want 65532:65532", c.User)
	}
	if v, ok := c.Env["PATH"]; !ok || v != "/bin" {
		t.Errorf("Env[PATH] = %q ok=%v ; want /bin", v, ok)
	}
}

func TestEnrichFromImage_HostCommandWins(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, root, `{"process":{"args":["/from-image"]}}`)
	c := &Container{ID: "x", Command: []string{"/from-manifest", "arg"}}
	if err := EnrichFromImage(c, root); err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if c.Command[0] != "/from-manifest" {
		t.Errorf("host Command was overridden: %v", c.Command)
	}
}

func TestEnrichFromImage_MissingConfigIsErrNotExist(t *testing.T) {
	root := t.TempDir() // no .weft-microvm/config.json
	c := &Container{ID: "x"}
	err := EnrichFromImage(c, root)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v ; want os.ErrNotExist", err)
	}
}

func TestEnrichFromImage_EmptyArgsIsError(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, root, `{"process":{"args":[]}}`)
	c := &Container{ID: "x"}
	if err := EnrichFromImage(c, root); err == nil {
		t.Error("want error for empty process.args")
	}
}

func TestEnrichFromImage_RootUserNotInjected(t *testing.T) {
	// uid=0,gid=0 means "host didn't constrain it" : leave c.User empty
	// so the bundler keeps its own zero default rather than inject
	// "0:0" and confuse downstream readers.
	root := t.TempDir()
	writeConfig(t, root, `{"process":{"args":["/x"],"user":{"uid":0,"gid":0}}}`)
	c := &Container{ID: "x"}
	if err := EnrichFromImage(c, root); err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if c.User != "" {
		t.Errorf("User = %q ; want empty for uid=0/gid=0", c.User)
	}
}
