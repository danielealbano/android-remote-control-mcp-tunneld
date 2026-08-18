package router

import (
	"context"
	"testing"
	"time"
)

func TestRegisterLookupNodeAndTTL(t *testing.T) {
	reg, mr := newReg(t)
	ctx := context.Background()
	if err := reg.RegisterNode(ctx, "nodeA", "10.0.0.1:9443", 30*time.Second); err != nil {
		t.Fatal(err)
	}
	adv, ok, err := reg.LookupNode(ctx, "nodeA")
	if err != nil || !ok || adv != "10.0.0.1:9443" {
		t.Fatalf("lookup node: adv=%q ok=%v err=%v", adv, ok, err)
	}
	mr.FastForward(31 * time.Second)
	if _, ok, _ := reg.LookupNode(ctx, "nodeA"); ok {
		t.Error("node should have expired")
	}
}

func TestRefreshNodeExtendsTTL(t *testing.T) {
	reg, mr := newReg(t)
	ctx := context.Background()
	_ = reg.RegisterNode(ctx, "n", "a:1", 30*time.Second)
	mr.FastForward(20 * time.Second)
	_ = reg.RefreshNode(ctx, "n", "a:1", 30*time.Second)
	mr.FastForward(20 * time.Second) // 40s since register, but only 20s since refresh
	if _, ok, _ := reg.LookupNode(ctx, "n"); !ok {
		t.Error("refresh should keep the node registered")
	}
}

func TestNodesEnumerates(t *testing.T) {
	reg, _ := newReg(t)
	ctx := context.Background()
	_ = reg.RegisterNode(ctx, "a", "10.0.0.1:9443", time.Minute)
	_ = reg.RegisterNode(ctx, "b", "10.0.0.2:9443", time.Minute)
	nodes, err := reg.Nodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if nodes["a"] != "10.0.0.1:9443" || nodes["b"] != "10.0.0.2:9443" || len(nodes) != 2 {
		t.Errorf("Nodes() = %v", nodes)
	}
}

func TestBindLookupRouteRoundTrip(t *testing.T) {
	reg, _ := newReg(t)
	ctx := context.Background()
	start := time.Unix(1_700_000_000, 500)
	if err := reg.BindRoute(ctx, "abc", "nodeA", "sha256:fp", "conn1", start); err != nil {
		t.Fatal(err)
	}
	node, fp, cid, got, ok, err := reg.LookupRoute(ctx, "abc")
	if err != nil || !ok {
		t.Fatalf("lookup route: ok=%v err=%v", ok, err)
	}
	if node != "nodeA" || fp != "sha256:fp" || cid != "conn1" {
		t.Errorf("route fields = %q/%q/%q", node, fp, cid)
	}
	if !got.Equal(start) {
		t.Errorf("startedAt = %v, want %v", got, start)
	}
}

func TestBindRouteFingerprintGuard(t *testing.T) {
	reg, _ := newReg(t)
	ctx := context.Background()
	start := time.Unix(1, 0)
	_ = reg.BindRoute(ctx, "abc", "nodeA", "fp1", "conn1", start)
	if err := reg.BindRoute(ctx, "abc", "nodeB", "fp2", "conn2", start); err != ErrNameHeldByOther {
		t.Errorf("different fingerprint should conflict, got %v", err)
	}
}

func TestSelfHealRoutePreservesEpoch(t *testing.T) {
	reg, mr := newReg(t)
	ctx := context.Background()
	start := time.Unix(1_700_000_000, 0)
	// Route lapsed (TTL): self-heal re-binds preserving the epoch.
	res, err := reg.BindRouteIfAbsentOrOwner(ctx, "abc", "nodeA", "fp", "conn1", start)
	if err != nil || res != SelfHealBound {
		t.Fatalf("self-heal bound: res=%v err=%v", res, err)
	}
	_, _, _, got, ok, _ := reg.LookupRoute(ctx, "abc")
	if !ok || !got.Equal(start) {
		t.Errorf("epoch not preserved: got=%v ok=%v", got, ok)
	}
	// A different connID must NOT clobber.
	res, _ = reg.BindRouteIfAbsentOrOwner(ctx, "abc", "nodeB", "fp", "conn2", start.Add(time.Hour))
	if res != SelfHealNotOwner {
		t.Errorf("different connID should be not-owner, got %v", res)
	}
	_ = mr
}
