package limit

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
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
