package router

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

func TestRegisterLookupNodeAndTTL(t *testing.T) {
	reg, mr := newReg(t)
	ctx := context.Background()
	if err := reg.RegisterNode(ctx, "nodeA", NodeInfo{Advertise: "10.0.0.1:9443"}, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	adv, ok, err := reg.LookupNode(ctx, "nodeA")
	if err != nil || !ok || adv != "10.0.0.1:9443" {
		t.Fatalf("lookup node: adv=%q ok=%v err=%v", adv, ok, err)
	}
	mr.FastForward(31 * time.Second)
	if _, ok, err := reg.LookupNode(ctx, "nodeA"); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Error("node should have expired")
	}
}

func TestRefreshNodeExtendsTTL(t *testing.T) {
	reg, mr := newReg(t)
	ctx := context.Background()
	if err := reg.RegisterNode(ctx, "n", NodeInfo{Advertise: "a:1"}, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(20 * time.Second)
	if err := reg.RefreshNode(ctx, "n", NodeInfo{Advertise: "a:1"}, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(20 * time.Second) // 40s since register, but only 20s since refresh
	if _, ok, err := reg.LookupNode(ctx, "n"); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Error("refresh should keep the node registered")
	}
}

// TestRegistry_RegisterAndListNodes_JSON: the full NodeInfo round-trips through node:{id} JSON and Nodes().
func TestRegistry_RegisterAndListNodes_JSON(t *testing.T) {
	reg, _ := newReg(t)
	ctx := context.Background()
	a := NodeInfo{Advertise: "10.0.0.1:9443", Hostname: "host-a", Version: "v1", StartedAt: "2026-08-21T00:00:00Z", LastHeartbeat: "2026-08-21T00:00:10Z"}
	if err := reg.RegisterNode(ctx, "a", a, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := reg.RegisterNode(ctx, "b", NodeInfo{Advertise: "10.0.0.2:9443", Hostname: "host-b"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	nodes, err := reg.Nodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("Nodes() len = %d, want 2: %v", len(nodes), nodes)
	}
	if nodes["a"] != a {
		t.Errorf("node a round-trip = %+v, want %+v", nodes["a"], a)
	}
	if nodes["b"].Advertise != "10.0.0.2:9443" || nodes["b"].Hostname != "host-b" {
		t.Errorf("node b = %+v", nodes["b"])
	}
}

// TestRegistry_Node_TTLExpiry: a node not refreshed drops from Nodes() after its TTL.
func TestRegistry_Node_TTLExpiry(t *testing.T) {
	reg, mr := newReg(t)
	ctx := context.Background()
	if err := reg.RegisterNode(ctx, "a", NodeInfo{Advertise: "10.0.0.1:9443"}, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(31 * time.Second)
	nodes, err := reg.Nodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := nodes["a"]; ok {
		t.Error("an expired node must drop from Nodes()")
	}
}

func TestDeregisterNodeRemovesKey(t *testing.T) {
	reg, _ := newReg(t)
	ctx := context.Background()
	if err := reg.RegisterNode(ctx, "node-d", NodeInfo{Advertise: "10.0.0.4:9443"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := reg.DeregisterNode(ctx, "node-d"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := reg.LookupNode(ctx, "node-d"); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("a deregistered node must not resolve")
	}
	// Idempotent: deregistering an absent node is not an error.
	if err := reg.DeregisterNode(ctx, "node-d"); err != nil {
		t.Fatal(err)
	}
}

func TestRegistry_Nodes_LogsMalformedEntry(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	var buf bytes.Buffer
	reg, err := NewRegistry(rdb, 30*time.Second, WithLogger(slog.New(slog.NewTextHandler(&buf, nil))))
	if err != nil {
		t.Fatal(err)
	}
	if err := mr.Set("node:broken", "{"); err != nil {
		t.Fatal(err)
	}
	if err := reg.RegisterNode(context.Background(), "ok", NodeInfo{Advertise: "10.0.0.1:9443"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	nodes, err := reg.Nodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes["ok"].Advertise != "10.0.0.1:9443" {
		t.Fatalf("Nodes() = %v, want only the well-formed node", nodes)
	}
	if !strings.Contains(buf.String(), `msg="malformed node registry entry skipped" key=node:broken`) {
		t.Fatalf("the skipped entry must be logged; log = %q", buf.String())
	}
}

func TestNewRegistry_RejectsNilLogger(t *testing.T) {
	if _, err := NewRegistry(nil, time.Second, WithLogger(nil)); err == nil {
		t.Fatal("a nil logger must be rejected")
	}
}
