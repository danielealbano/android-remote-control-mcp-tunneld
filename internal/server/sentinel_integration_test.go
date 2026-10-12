//go:build integration

package server

import (
	"context"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

func TestIntegration_ValkeySentinel(t *testing.T) {
	sentinelURL, masterURL := tunneltest.StartValkeySentinel(t)
	startIntegrationServer(t, func(c *config.ServeCmd) { c.RedisURL = sentinelURL })
	master := newRedis(t, masterURL)
	deadline := time.Now().Add(10 * time.Second)
	for {
		keys, err := master.Keys(context.Background(), "node:*").Result()
		if err != nil {
			t.Fatalf("list node keys on the Sentinel master: %v", err)
		}
		if len(keys) == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the node registry key must land on the master Sentinel reports, got %v", keys)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
