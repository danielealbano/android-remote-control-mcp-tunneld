package attest

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSignerAllowlistParseAndAllowed(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "signers.txt")
	content := "# release key\n" +
		"69d22b2adf3698ffe801e90fe03ae0d073392c0128690717686e7eaadb039829\n" +
		"\n" +
		"AABBCC   # inline comment\n"
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := LoadSignerAllowlist(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Allowed("69d22b2adf3698ffe801e90fe03ae0d073392c0128690717686e7eaadb039829") {
		t.Error("release digest should be allowed")
	}
	if !a.Allowed("aabbcc") { // case-insensitive
		t.Error("aabbcc should be allowed (case-insensitive)")
	}
	if a.Allowed("deadbeef") {
		t.Error("unlisted digest must not be allowed")
	}
}

func TestSignerAllowlistRejectsBadHex(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bad.txt")
	_ = os.WriteFile(f, []byte("nothex!!\n"), 0o600)
	if _, err := LoadSignerAllowlist(f, nil); err == nil {
		t.Error("invalid hex digest should fail to load")
	}
}

func TestSignerAllowlistHotReload(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "signers.txt")
	if err := os.WriteFile(f, []byte("aabbcc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := LoadSignerAllowlist(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Allowed("ddeeff") {
		t.Fatal("ddeeff not yet listed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { a.Watch(ctx, 10*time.Millisecond); close(done) }()

	// Rewrite with a new digest and bump mtime.
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(f, []byte("aabbcc\nddeeff\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Second)
	_ = os.Chtimes(f, future, future)

	deadline := time.After(2 * time.Second)
	for !a.Allowed("ddeeff") {
		select {
		case <-deadline:
			t.Fatal("hot reload did not pick up the new digest")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

// TestSignerAllowlistReloadFailureLogged verifies that when a CHANGED file fails to reload (corrupt
// content), the watcher keeps the last-known-good set AND logs the failure at Warn so a bad operator
// deploy is not silently swallowed.
func TestSignerAllowlistReloadFailureLogged(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "signers.txt")
	if err := os.WriteFile(f, []byte("aabbcc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ch := &captureHandler{}
	a, err := LoadSignerAllowlist(f, slog.New(ch))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { a.Watch(ctx, 10*time.Millisecond); close(done) }()

	// Replace with invalid-hex content and bump mtime: the reload must fail and be logged.
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(f, []byte("nothex!!\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Second)
	_ = os.Chtimes(f, future, future)

	waitFor(t, 2*time.Second, func() bool { return ch.count(slog.LevelWarn) > 0 })
	if !a.Allowed("aabbcc") {
		t.Fatal("a failed reload must keep the last-known-good set")
	}
	cancel()
	<-done
}

// TestSigners_VanishedFileKeepsSet verifies a deleted allowlist file keeps the previous digests and logs
// an Error (the security-critical file must never silently allow everyone).
func TestSigners_VanishedFileKeepsSet(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "signers.txt")
	if err := os.WriteFile(f, []byte("aabbcc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ch := &captureHandler{}
	a, err := LoadSignerAllowlist(f, slog.New(ch))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { a.Watch(ctx, 10*time.Millisecond); close(done) }()

	time.Sleep(20 * time.Millisecond)
	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool { return ch.count(slog.LevelError) > 0 })
	if !a.Allowed("aabbcc") {
		t.Fatal("a vanished allowlist file must keep the last-known-good set")
	}
	cancel()
	<-done
}
