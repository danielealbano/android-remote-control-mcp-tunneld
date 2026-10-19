package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

// captureStdout redirects os.Stdout for the duration of fn and returns what was written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, err := io.ReadAll(r)
		if err != nil {
			tunneltest.Logger().Warn("captured stdout read failed", "err", err)
		}
		done <- string(b)
	}()
	fn()
	tunneltest.CloseOrLog(t, w)
	os.Stdout = orig
	return <-done
}

func TestCLIVersion(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()
	os.Args = []string{"tunneld", "version"}

	out := captureStdout(t, main)
	if !strings.Contains(out, "tunneld") || !strings.Contains(out, version) {
		t.Errorf("version output = %q, want to contain %q", out, version)
	}
}

func TestCLIServeDispatch(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "ca.pem")
	key := filepath.Join(dir, "ca-key.pem")
	digest := filepath.Join(dir, "signers.txt")
	for _, f := range []string{cert, key, digest} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var (
		mu     sync.Mutex
		called bool
		gotCfg config.ServeCmd
	)
	origRun := runServe
	defer func() { runServe = origRun }()
	runServe = func(ctx context.Context, cfg config.ServeCmd, logger *slog.Logger, ver string) error {
		mu.Lock()
		called, gotCfg = true, cfg
		mu.Unlock()
		return nil
	}

	t.Setenv("TUNNELD_S3_BUCKET", "tunneld")
	origArgs := os.Args
	defer func() { os.Args = origArgs }()
	// The E2E Validate requires the S3/mesh/attestation/ACME families; supply the full set so the
	// dispatch seam is reached (the legacy --client-ip-header flag no longer exists).
	os.Args = []string{
		"tunneld", "serve",
		"--ca-cert", cert,
		"--ca-key", key,
		"--attest-signer-digest-file", digest,
		"--mesh-advertise", "node-a:9443",
		"--s3-endpoint", "http://localhost:9000",
		"--s3-access-key", "access",
		"--s3-secret-key", "secret",
		"--acme-email", "ops@example.test",
		"--acme-account-dir", dir,
		"--acme-dns-provider", "cloudflare",
		"--conn-log-dir", t.TempDir(),
		"--dialback-advertise", "203.0.113.10:443",
	}

	main()

	mu.Lock()
	defer mu.Unlock()
	if !called {
		t.Fatal("serve did not dispatch to runServe seam")
	}
	if gotCfg.S3Bucket != "tunneld" {
		t.Errorf("dispatched cfg.S3Bucket = %q, want tunneld", gotCfg.S3Bucket)
	}
	if gotCfg.CACert != cert {
		t.Errorf("dispatched cfg.CACert = %q, want %q", gotCfg.CACert, cert)
	}
}

func TestServe_ReturnsRunErrorAfterClosingLogs(t *testing.T) {
	origRun := runServe
	defer func() { runServe = origRun }()
	runErr := errors.New("bind failed")
	runServe = func(context.Context, config.ServeCmd, *slog.Logger, string) error { return runErr }
	logPath := filepath.Join(t.TempDir(), "tunneld.log")
	err := serve(config.ServeCmd{Log: []string{"output=" + logPath + ";level=info"}})
	if !errors.Is(err, runErr) {
		t.Fatalf("serve = %v, want the run error returned (not an exit) so the log sinks close first", err)
	}
}
