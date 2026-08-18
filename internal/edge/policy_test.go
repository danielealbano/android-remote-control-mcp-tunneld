package edge

import (
	"context"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// TestEdge_Splice_MinRateKill covers the min-rate connection policy: a connection whose rolling-window
// traffic stays below --limit-conn-min-rate is dropped once past the grace period (idle disabled here so
// the min-rate kill is unambiguously what fires). rollingWindow is shrunk so the test needs no real wait.
func TestEdge_Splice_MinRateKill(t *testing.T) {
	prev := rollingWindow
	rollingWindow = 200 * time.Millisecond
	t.Cleanup(func() { rollingWindow = prev })

	cfg := baseConfig()
	cfg.IdleTimeout = 0 // disable idle so the min-rate kill is what fires
	cfg.MinRate = 1000
	cfg.MinGrace = 100 * time.Millisecond
	te := newTestEdge(t, cfg, nil, nil)

	client := newScriptConn("203.0.113.9", nil) // blocks on Read until closed → zero traffic
	far := newScriptConn("203.0.113.9", nil)
	as := &activeStream{tunnel: "t", started: time.Now(), cancel: func() {}}
	as.lastAct.Store(time.Now().UnixNano())

	reason := te.e.splice(context.Background(), "t", client, far, as)
	if reason != store.CloseMinRate {
		t.Fatalf("a sub-min-rate connection past grace must be killed with %q, got %q", store.CloseMinRate, reason)
	}
}

func TestEdge_EvictLeastActive_AllProtected_NoVictim(t *testing.T) {
	cfg := baseConfig()
	cfg.EvictIdle = time.Hour // nothing is idle
	cfg.ProtectRate = 1       // everything with recent>=1 is protected
	te := newTestEdge(t, cfg, nil, nil)
	base := time.Unix(1_700_000_000, 0)
	te.e.now = func() time.Time { return base }

	s := &activeStream{tunnel: "t1", cancel: func() {}}
	s.lastAct.Store(base.UnixNano())
	s.recent.Store(100)
	te.e.trackStream(s)

	if te.e.evictLeastActive("t1") {
		t.Fatal("a fully-protected, non-idle tunnel must have no evictable victim")
	}
}

func TestEdge_EvictLeastActive_PicksIdleVictim(t *testing.T) {
	cfg := baseConfig()
	cfg.EvictIdle = 100 * time.Millisecond
	cfg.ProtectRate = 1000
	te := newTestEdge(t, cfg, nil, nil)
	base := time.Unix(1_700_000_000, 0)
	te.e.now = func() time.Time { return base }

	protectedCancelled := false
	idleCancelled := false
	busy := &activeStream{tunnel: "t1", cancel: func() { protectedCancelled = true }}
	busy.lastAct.Store(base.UnixNano())
	busy.recent.Store(5000)
	idle := &activeStream{tunnel: "t1", cancel: func() { idleCancelled = true }}
	idle.lastAct.Store(base.Add(-time.Second).UnixNano())
	idle.recent.Store(0)
	te.e.trackStream(busy)
	te.e.trackStream(idle)

	if !te.e.evictLeastActive("t1") {
		t.Fatal("expected an eviction")
	}
	if protectedCancelled {
		t.Fatal("the protected busy stream must NOT be evicted")
	}
	if !idleCancelled {
		t.Fatal("the idle unprotected stream must be evicted")
	}
}
