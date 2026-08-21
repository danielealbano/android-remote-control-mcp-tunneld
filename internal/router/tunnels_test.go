package router

import (
	"context"
	"testing"
)

func TestRegistry_ScanTunnels_OneStepCursor(t *testing.T) {
	reg, _ := newReg(t)
	ctx := context.Background()
	for _, n := range []string{"a", "b", "c"} {
		_ = reg.BindRoute(ctx, n, "node1", "fp", "conn-"+n)
	}
	// Iterate the cursor to completion, collecting names across the SCAN steps (prefix stripped).
	seen := map[string]bool{}
	var cursor uint64
	for {
		names, next, err := reg.ScanTunnels(ctx, cursor, 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range names {
			seen[n] = true
		}
		if next == 0 {
			break
		}
		cursor = next
	}
	if !seen["a"] || !seen["b"] || !seen["c"] {
		t.Errorf("ScanTunnels missed names: %v", seen)
	}
}

func TestRegistry_TunnelMeta_OmitsNonRoutable(t *testing.T) {
	reg, _ := newReg(t)
	ctx := context.Background()
	_ = reg.BindRoute(ctx, "live", "node1", "fp", "conn1")
	_ = reg.AddTraffic(ctx, "live", 100, 50)
	_ = reg.AddTraffic(ctx, "orphan", 7, 0) // byte-only orphan (no node) → not routable
	meta, err := reg.TunnelMeta(ctx, []string{"live", "orphan", "missing"})
	if err != nil {
		t.Fatal(err)
	}
	if len(meta) != 1 {
		t.Fatalf("TunnelMeta must report live routes only, got %v", meta)
	}
	m := meta["live"]
	if m.Node != "node1" || m.BytesIn != 100 || m.BytesOut != 50 {
		t.Errorf("live meta = %+v", m)
	}
	if _, ok := meta["orphan"]; ok {
		t.Error("a byte-only orphan (no node) must be omitted")
	}
}
