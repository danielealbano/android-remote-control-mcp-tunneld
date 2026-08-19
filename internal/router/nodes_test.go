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

func TestDeregisterNodeRemovesKey(t *testing.T) {
	reg, _ := newReg(t)
	ctx := context.Background()
	if err := reg.RegisterNode(ctx, "node-d", "10.0.0.4:9443", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := reg.DeregisterNode(ctx, "node-d"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := reg.LookupNode(ctx, "node-d"); ok {
		t.Fatal("a deregistered node must not resolve")
	}
	// Idempotent: deregistering an absent node is not an error.
	if err := reg.DeregisterNode(ctx, "node-d"); err != nil {
		t.Fatal(err)
	}
}
