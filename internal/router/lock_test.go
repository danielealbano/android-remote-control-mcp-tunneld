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
	t.Parallel()
	tests := []struct {
		name      string
		fail      string
		cancelled bool
		want      string
	}{
		{name: "ownership check fails", fail: "get", want: `msg="could not check the route lock before releasing it; it expires on its own" tunnel=n`},
		{name: "delete fails", fail: "del", want: `msg="could not release the route lock; it expires on its own" tunnel=n`},
		{name: "ownership check fails after the caller was cancelled", fail: "get", cancelled: true, want: `msg="could not check the route lock before releasing it; it expires on its own" tunnel=n`},
		{name: "delete fails after the caller was cancelled", fail: "del", cancelled: true, want: `msg="could not release the route lock; it expires on its own" tunnel=n`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
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
			if !strings.Contains(buf.String(), tc.want) || !strings.Contains(buf.String(), errInjected.Error()) {
				t.Fatalf("the release failure must be logged with its cause; log = %q", buf.String())
			}
		})
	}
}

func TestRegistry_WithLock_CancelledHolderReleases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		replace func(mr *miniredis.Miniredis) error
		want    string
	}{
		{name: "lock still held", replace: func(*miniredis.Miniredis) error { return nil }},
		{name: "lock already expired", replace: func(mr *miniredis.Miniredis) error { mr.Del(lockKey("n")); return nil }},
		{name: "another holder took the lock", replace: func(mr *miniredis.Miniredis) error { return mr.Set(lockKey("n"), "someone-else") }, want: "someone-else"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg, mr, _, buf := newLoggedReg(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := reg.withLock(ctx, "n", func() error { cancel(); return tc.replace(mr) }); err != nil {
				t.Fatal(err)
			}
			got := ""
			if mr.Exists(lockKey("n")) {
				v, err := mr.Get(lockKey("n"))
				if err != nil {
					t.Fatal(err)
				}
				got = v
			}
			if got != tc.want {
				t.Fatalf("lock after the holder's ctx was cancelled = %q, want %q", got, tc.want)
			}
			if buf.Len() != 0 {
				t.Fatalf("a release after the holder's ctx was cancelled must not log; log = %q", buf.String())
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
