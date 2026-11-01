package edge

import (
	"context"
	"sync"
	"sync/atomic"
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
	te := newTestEdge(t, cfg, nil)

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
	te := newTestEdge(t, cfg, nil)
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
	te := newTestEdge(t, cfg, nil)
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

func policyStream(base time.Time, tunnel string, idle time.Duration, recent int64) *activeStream {
	s := &activeStream{tunnel: tunnel, cancel: func() {}}
	s.lastAct.Store(base.Add(-idle).UnixNano())
	s.recent.Store(recent)
	return s
}

func newPolicyEdge(t *testing.T, base time.Time) *testEdge {
	t.Helper()
	cfg := baseConfig()
	cfg.EvictIdle = time.Minute
	cfg.ProtectRate = 1000
	te := newTestEdge(t, cfg, nil)
	te.e.now = func() time.Time { return base }
	return te
}

func TestEdge_SlotCandidate_MostIdleEvictable(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name     string
		streams  func() []*activeStream
		wantIdle time.Duration
		wantOK   bool
	}{
		{
			name: "most idle low-rate stream of the tunnel",
			streams: func() []*activeStream {
				return []*activeStream{
					policyStream(base, "t1", time.Second, 0),
					policyStream(base, "t1", 3*time.Second, 0),
					policyStream(base, "t1", 5*time.Second, 5000),
					policyStream(base, "t2", 30*time.Second, 0),
				}
			},
			wantIdle: 3 * time.Second, wantOK: true,
		},
		{
			name: "only a protected stream",
			streams: func() []*activeStream {
				return []*activeStream{policyStream(base, "t1", 5*time.Second, 5000)}
			},
		},
		{
			name:    "no stream",
			streams: func() []*activeStream { return nil },
		},
		{
			name: "most idle stream already evicted",
			streams: func() []*activeStream {
				evicted := policyStream(base, "t1", 3*time.Second, 0)
				evicted.evicted.Store(true)
				return []*activeStream{policyStream(base, "t1", time.Second, 0), evicted}
			},
			wantIdle: time.Second, wantOK: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			te := newPolicyEdge(t, base)
			for _, s := range tc.streams() {
				te.e.trackStream(s)
			}
			idle, ok := te.e.SlotCandidate("t1")
			if idle != tc.wantIdle || ok != tc.wantOK {
				t.Fatalf("SlotCandidate = (%v, %v), want (%v, %v)", idle, ok, tc.wantIdle, tc.wantOK)
			}
		})
	}
}

func TestEdge_FreeSlot_EvictsMostIdle(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_700_000_000, 0)
	te := newPolicyEdge(t, base)
	var cancelled []string
	var releases int
	victim := policyStream(base, "t1", 3*time.Second, 0)
	victim.cancel = func() { cancelled = append(cancelled, "victim") }
	victim.release = func() { releases++ }
	other := policyStream(base, "t1", time.Second, 0)
	other.cancel = func() { cancelled = append(cancelled, "other") }
	te.e.trackStream(victim)
	te.e.trackStream(other)

	if idle, ok := te.e.SlotCandidate("t1"); !ok || idle != 3*time.Second {
		t.Fatalf("SlotCandidate = (%v, %v), want (3s, true)", idle, ok)
	}
	if !te.e.FreeSlot("t1") {
		t.Fatal("FreeSlot must evict the most idle stream")
	}
	if len(cancelled) != 1 || cancelled[0] != "victim" || !victim.evicted.Load() || releases != 1 {
		t.Fatalf("FreeSlot must cancel only the reported stream, mark it evicted and release it once: cancelled=%v evicted=%v releases=%d",
			cancelled, victim.evicted.Load(), releases)
	}

	empty := newPolicyEdge(t, base)
	empty.e.trackStream(policyStream(base, "t1", 5*time.Second, 5000))
	if empty.e.FreeSlot("t1") {
		t.Fatal("FreeSlot must report false when nothing is evictable")
	}
}

func TestEdge_EvictLeastActive_SkipsAlreadyEvicted(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_700_000_000, 0)
	te := newPolicyEdge(t, base)
	var cancelled []string
	first := policyStream(base, "t1", 3*time.Second, 0)
	first.evicted.Store(true)
	first.cancel = func() { cancelled = append(cancelled, "first") }
	second := policyStream(base, "t1", time.Second, 0)
	second.cancel = func() { cancelled = append(cancelled, "second") }
	te.e.trackStream(first)
	te.e.trackStream(second)

	if !te.e.evictLeastActive("t1") {
		t.Fatal("the next least-active stream must be evicted")
	}
	if len(cancelled) != 1 || cancelled[0] != "second" {
		t.Fatalf("only the not-yet-evicted stream may be cancelled, got %v", cancelled)
	}
	if te.e.evictLeastActive("t1") {
		t.Fatal("with every candidate already evicted nothing may be evicted")
	}
	if len(cancelled) != 1 {
		t.Fatalf("no further stream may be cancelled, got %v", cancelled)
	}
}

func TestEdge_FreeSlot_ConcurrentCallsPickDistinctVictims(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_700_000_000, 0)
	te := newPolicyEdge(t, base)
	var cancels [2]atomic.Int32
	for i := range cancels {
		s := policyStream(base, "t1", time.Duration(i+1)*time.Second, 0)
		s.cancel = func() { cancels[i].Add(1) }
		te.e.trackStream(s)
	}

	var wg sync.WaitGroup
	var freed atomic.Int32
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if te.e.FreeSlot("t1") {
				freed.Add(1)
			}
		}()
	}
	wg.Wait()

	if freed.Load() != 2 || cancels[0].Load() != 1 || cancels[1].Load() != 1 {
		t.Fatalf("two concurrent calls must each evict a distinct stream: freed=%d cancels=[%d %d]",
			freed.Load(), cancels[0].Load(), cancels[1].Load())
	}
	if te.e.FreeSlot("t1") {
		t.Fatal("a third call must find nothing left to evict")
	}
}
