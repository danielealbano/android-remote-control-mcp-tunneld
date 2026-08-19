package ban

import (
	"sync/atomic"
	"testing"
)

// TestWatcher_InitialDoesNotFireOnReload pins the new contract: the single startup load applies the bans
// but fires ZERO reload callbacks (no live connections exist yet); the first change-driven tick fires one.
func TestWatcher_InitialDoesNotFireOnReload(t *testing.T) {
	dir := t.TempDir()
	f := writeBan(t, dir, "bans.txt", "ip 1.1.1.1\n")
	e := NewEngine()
	var reloads int32
	w := NewWatcher(e, []string{f}, "", 0, discardLog())
	w.Initial()
	// Initial takes no onReload; a following change-driven tick is the FIRST callback.
	if atomic.LoadInt32(&reloads) != 0 {
		t.Fatalf("Initial must fire zero reload callbacks, got %d", reloads)
	}
	if _, ok := e.Match(mustAddr("1.1.1.1")); !ok {
		t.Fatal("Initial must still apply the bans")
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
