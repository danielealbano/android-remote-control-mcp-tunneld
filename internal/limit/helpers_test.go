package limit

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb, mr
}

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// freezeClock pins the window limiter's clock so a burst never straddles a real window boundary
// (deterministic + instant). Restored on cleanup. Callers must not run in parallel.
func freezeClock(t *testing.T) {
	t.Helper()
	base := time.Unix(1_700_000_000, 0)
	nowFunc = func() time.Time { return base }
	t.Cleanup(func() { nowFunc = time.Now })
}
