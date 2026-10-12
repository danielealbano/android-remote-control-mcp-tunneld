package limit

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

func newLoggedLimiter(t *testing.T) (*Limiter, *miniredis.Miniredis, *redis.Client, *bytes.Buffer) {
	t.Helper()
	rdb, mr := newTestRedis(t)
	var buf bytes.Buffer
	l := NewLimiter(rdb, 0, 0, 0, time.Hour,
		WithLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))))
	return l, mr, rdb, &buf
}

func TestLimiter_ReleaseConcLock_LogsFailures(t *testing.T) {
	tests := []struct {
		name      string
		fail      string
		cancelled bool
		want      string
	}{
		{name: "ownership check fails", fail: "get", want: `msg="stream-cap lock release check failed (lock expires by TTL)" tunnel=n`},
		{name: "delete fails", fail: "del", want: `msg="stream-cap lock release failed (lock expires by TTL)" tunnel=n`},
		{name: "cancelled caller check is silent", fail: "get", cancelled: true},
		{name: "cancelled caller delete is silent", fail: "del", cancelled: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l, mr, rdb, buf := newLoggedLimiter(t)
			if err := mr.Set(concLockKey("n"), "tok"); err != nil {
				t.Fatal(err)
			}
			rdb.AddHook(tunneltest.FailCommands(errInjected, tc.fail))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			l.releaseConcLock(ctx, "n", "tok")
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
