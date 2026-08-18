package server

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
)

// TestHeartbeatNodeSurvivesTransientError: one failing refresh must not kill the heartbeat — the node
// re-registers on the next tick (RefreshNode is a plain SET).
func TestHeartbeatNodeSurvivesTransientError(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	reg := router.NewRegistry(rdb, time.Minute)
	logger := slog.New(slog.DiscardHandler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = heartbeatNode(ctx, reg, "node-t", "10.0.0.1:9443", 30*time.Millisecond, logger)
		close(done)
	}()

	waitNode := func(want bool) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			_, ok, _ := reg.LookupNode(context.Background(), "node-t")
			if ok == want {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("node registration did not reach %v in time", want)
	}
	waitNode(true)

	// Force refresh errors long enough for the TTL to lapse, then heal Valkey.
	mr.SetError("transient outage")
	time.Sleep(100 * time.Millisecond)
	mr.SetError("")
	mr.FastForward(time.Minute) // expire any stale entry: only a LIVE heartbeat re-registers it

	waitNode(true) // the loop survived the errors and re-registered

	cancel()
	<-done
}

// TestValidNameFunc: the CN validator accepts EXACTLY the generator's shape (prefix + --name-length
// base32 chars) and rejects everything else.
func TestValidNameFunc(t *testing.T) {
	cfg := config.ServeCmd{EnrollHost: "enroll.example.test", ControlHost: "connect.example.test",
		NamePrefix: "", NameLength: 12}
	valid := validNameFunc(cfg)

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "generator shape", in: "abcdef234567", want: true},
		{name: "too short", in: "abc234", want: false},
		{name: "too long", in: "abcdef2345678", want: false},
		{name: "uppercase rejected", in: "Abcdef234567", want: false},
		{name: "non-base32 digit rejected", in: "abcdef234501", want: false}, // 0,1 not in [a-z2-7]
		{name: "dash rejected", in: "abcdef-34567", want: false},
		{name: "reserved enroll label", in: "enroll", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := valid(tc.in); got != tc.want {
				t.Fatalf("valid(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}

	// A prefix participates in both the length and the literal match.
	cfgP := cfg
	cfgP.NamePrefix = "t-"
	validP := validNameFunc(cfgP)
	if !validP("t-abcdef234567") || validP("abcdef234567") || validP("x-abcdef234567") {
		t.Fatal("the prefix must be enforced literally")
	}
}
