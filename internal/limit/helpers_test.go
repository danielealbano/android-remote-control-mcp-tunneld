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

// newFrozenLimiter builds a Limiter with a FROZEN clock (deterministic + instant) so a window burst never
// straddles a real second/minute boundary. Returns the limiter + its miniredis (for Keys/TTL/FastForward).
func newFrozenLimiter(t *testing.T) (*Limiter, *miniredis.Miniredis) {
	t.Helper()
	rdb, mr := newTestRedis(t)
	l := NewLimiter(rdb, 125000, 1<<40, 1<<40, time.Hour)
	l.SetClock(func() time.Time { return time.Unix(1_700_000_000, 0) })
	return l, mr
}
