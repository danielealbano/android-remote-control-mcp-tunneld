package ban

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestWatcher_InitialDoesNotFireOnReload pins the new contract: the single startup load applies the bans
// but fires ZERO reload callbacks (no live connections exist yet); the first change-driven tick fires one.
func TestWatcher_InitialDoesNotFireOnReload(t *testing.T) {
	dir := t.TempDir()
	f := writeBan(t, dir, "bans.txt", "ip 1.1.1.1\n")
	e := NewEngine()
	var reloads int32
	cb := func(*Engine) { atomic.AddInt32(&reloads, 1) }
	w := NewWatcher(e, []string{f}, "", 0, testLog())
	w.Initial()
	// Initial takes no onReload; it fires zero callbacks.
	if atomic.LoadInt32(&reloads) != 0 {
		t.Fatalf("Initial must fire zero reload callbacks, got %d", reloads)
	}
	if _, ok := e.Match(mustAddr("1.1.1.1")); !ok {
		t.Fatal("Initial must still apply the bans")
	}
	// The FIRST change-driven tick fires the first callback.
	writeBan(t, dir, "bans.txt", "ip 2.2.2.2\n")
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(f, future, future); err != nil {
		t.Fatal(err)
	}
	w.tick(cb)
	if atomic.LoadInt32(&reloads) != 1 {
		t.Fatalf("the first change-driven tick must fire onReload once, got %d", reloads)
	}
}

// TestWatcher_TornReadNeverGoesLive verifies that when the input keeps changing across ALL retry attempts
// (a persistent torn read), NO snapshot is committed — the previous bans stay live and no callback fires.
func TestWatcher_TornReadNeverGoesLive(t *testing.T) {
	dir := t.TempDir()
	f := writeBan(t, dir, "bans.txt", "ip 1.1.1.1\n")
	e := NewEngine()
	w := NewWatcher(e, []string{f}, "", 0, testLog())
	w.Initial()
	if _, ok := e.Match(mustAddr("1.1.1.1")); !ok {
		t.Fatal("Initial must apply the bans")
	}
	var reloads int32
	cb := func(*Engine) { atomic.AddInt32(&reloads, 1) }
	// Seed the baseline and script a stat seam whose fingerprint changes on EVERY read: the tick sees a
	// change, and each build's post-read fingerprint differs from the pre-read one — the 3-attempt retry
	// budget is exhausted without a stable read, so nothing commits.
	base := time.Now()
	w.last = map[string]fileState{f: {exists: true, modTime: base, size: 11}}
	var calls int
	w.stat = func(string) fileState {
		calls++
		return fileState{exists: true, modTime: base.Add(time.Duration(calls) * time.Second), size: 11}
	}
	w.tick(cb)
	if atomic.LoadInt32(&reloads) != 0 {
		t.Errorf("a persistently torn read must NOT commit or fire onReload, got %d", reloads)
	}
	// The previous bans remain enforced (the live snapshot was never replaced).
	if _, ok := e.Match(mustAddr("1.1.1.1")); !ok {
		t.Error("previous bans must remain enforced when no stable read commits")
	}
}

// TestWatcher_SingleLoadNoDoubleExpansion verifies that after Initial(), an UNCHANGED tick does NOT
// rebuild/re-commit/re-expand: it fires no reload callback AND leaves the live snapshot pointer exactly
// as Initial() set it (a re-commit — the double-expansion this guards against — would swap the pointer).
// (The removal of the separate startup pre-load in server.Run is covered by the integration tier.)
func TestWatcher_SingleLoadNoDoubleExpansion(t *testing.T) {
	dir := t.TempDir()
	f := writeBan(t, dir, "bans.txt", "ip 1.1.1.1\n")
	e := NewEngine()
	var reloads int32
	cb := func(*Engine) { atomic.AddInt32(&reloads, 1) }
	w := NewWatcher(e, []string{f}, "", 0, testLog())
	w.Initial()
	snapAfterInitial := e.current.Load() // the single startup load's snapshot
	w.tick(cb)                           // no change since Initial → must not rebuild/re-commit/reload
	if atomic.LoadInt32(&reloads) != 0 {
		t.Errorf("an unchanged tick after Initial must not reload, got %d", reloads)
	}
	if e.current.Load() != snapAfterInitial {
		t.Error("an unchanged tick must NOT swap in a new snapshot (no re-load / re-expansion)")
	}
}

func TestWatcher_StatPath_LogsUnexpectedStatError(t *testing.T) {
	dir := t.TempDir()
	notDir := writeBan(t, dir, "plain.txt", "")
	tests := []struct {
		name    string
		path    string
		wantLog bool
	}{
		{name: "absent file is silent", path: filepath.Join(dir, "absent.txt")},
		{name: "stat failure is logged", path: filepath.Join(notDir, "child"), wantLog: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			log, buf := captureLog()
			w := &watcher{log: log}
			if st := w.statePath(tc.path); st.exists {
				t.Fatalf("statePath(%q) must report the file as missing", tc.path)
			}
			logged := strings.Contains(buf.String(), `msg="ban input file stat failed (treated as missing)"`)
			if logged != tc.wantLog {
				t.Fatalf("logged = %v, want %v; log = %q", logged, tc.wantLog, buf.String())
			}
		})
	}
}

func TestWatcher_LoadAndReloadLogged(t *testing.T) {
	dir := t.TempDir()
	a := writeBan(t, dir, "a.txt", "ip 1.1.1.1\n")
	b := writeBan(t, dir, "b.txt", "tunnel-name abcdef2345\n")
	var buf bytes.Buffer
	w := NewWatcher(NewEngine(), []string{a, b}, "", 0, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	logLine := func(msg string) string {
		t.Helper()
		for _, line := range strings.Split(buf.String(), "\n") {
			if strings.Contains(line, `msg="`+msg+`"`) {
				return line
			}
		}
		t.Fatalf("no %q line; log = %q", msg, buf.String())
		return ""
	}

	w.Initial()
	if line := logLine("ban files loaded"); !strings.Contains(line, "prefixes=1 tunnel_names=1") {
		t.Fatalf("startup load line = %q, want prefixes=1 tunnel_names=1", line)
	}

	buf.Reset()
	writeBan(t, dir, "b.txt", "tunnel-name abcdef2345\ncidr 2.2.2.0/24\n")
	w.tick(nil)
	line := logLine("ban files reloaded")
	if !strings.Contains(line, b) || strings.Contains(line, a) {
		t.Fatalf("reload line = %q, want only %q listed as changed", line, b)
	}
	if !strings.Contains(line, "prefixes=2 tunnel_names=1") {
		t.Fatalf("reload line = %q, want prefixes=2 tunnel_names=1", line)
	}
}
