package router

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

var errInjected = errors.New("injected valkey failure")

func newLoggedReg(t *testing.T) (*Registry, *miniredis.Miniredis, *redis.Client, *bytes.Buffer) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	var buf bytes.Buffer
	reg, err := NewRegistry(rdb, 30*time.Second, WithLogger(slog.New(slog.NewTextHandler(&buf, nil))))
	if err != nil {
		t.Fatal(err)
	}
	return reg, mr, rdb, &buf
}

func TestRegistry_Release_LogsFailures(t *testing.T) {
	tests := []struct {
		name      string
		fail      string
		cancelled bool
		want      string
	}{
		{name: "ownership check fails", fail: "get", want: `msg="route lock release check failed (lock expires by TTL)" tunnel=n`},
		{name: "delete fails", fail: "del", want: `msg="route lock release failed (lock expires by TTL)" tunnel=n`},
		{name: "cancelled caller check is silent", fail: "get", cancelled: true},
		{name: "cancelled caller delete is silent", fail: "del", cancelled: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg, mr, rdb, buf := newLoggedReg(t)
			if err := mr.Set(lockKey("n"), "tok"); err != nil {
				t.Fatal(err)
			}
			rdb.AddHook(tunneltest.FailCommands(errInjected, tc.fail))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			reg.release(ctx, "n", "tok")
			if tc.want == "" {
				if buf.Len() != 0 {
					t.Fatalf("a release failure caused by the caller's cancellation must not be logged; log = %q", buf.String())
				}
				return
			}
			if !strings.Contains(buf.String(), tc.want) || !strings.Contains(buf.String(), errInjected.Error()) {
				t.Fatalf("the release failure must be logged with its cause; log = %q", buf.String())
			}
		})
	}
}

func TestRegistry_Release_AbsentLockIsSilent(t *testing.T) {
	reg, _, _, buf := newLoggedReg(t)
	reg.release(context.Background(), "n", "tok")
	if buf.Len() != 0 {
		t.Fatalf("an already-expired lock is not a failure; log = %q", buf.String())
	}
}
