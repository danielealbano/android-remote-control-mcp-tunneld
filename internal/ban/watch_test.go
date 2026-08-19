package ban

import (
	"os"
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
	w := NewWatcher(e, []string{f}, "", 0, discardLog())
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
	w := NewWatcher(e, []string{f}, "", 0, discardLog())
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

// TestWatcher_SingleLoadNoDoubleExpansion verifies Initial loads exactly once and an UNCHANGED tick is a
// no-op (no re-commit / re-expansion) — the double-load that used to happen at startup is gone.
func TestWatcher_SingleLoadNoDoubleExpansion(t *testing.T) {
	dir := t.TempDir()
	f := writeBan(t, dir, "bans.txt", "ip 1.1.1.1\n")
	e := NewEngine()
	var reloads int32
	cb := func(*Engine) { atomic.AddInt32(&reloads, 1) }
	w := NewWatcher(e, []string{f}, "", 0, discardLog())
	w.Initial()
	w.tick(cb) // no change since Initial → must not reload
	if atomic.LoadInt32(&reloads) != 0 {
		t.Errorf("an unchanged tick after Initial must not reload, got %d", reloads)
	}
}
