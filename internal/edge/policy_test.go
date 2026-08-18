package edge

import (
	"testing"
	"time"
)

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
