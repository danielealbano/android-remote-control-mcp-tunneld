package limit

import (
	"context"
	"fmt"
	"strconv"

	"github.com/redis/go-redis/v9"
)

func concKey(name string) string { return "conc:" + name }

func (l *Limiter) AcquireStream(ctx context.Context, name, member string, maxN int) (bool, error) {
	now := l.now()
	key := concKey(name)
	pipe := l.rdb.Pipeline()
	pipe.ZRemRangeByScore(ctx, key, "-inf", strconv.FormatInt(now.UnixMilli(), 10))
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(now.Add(l.streamTTL).UnixMilli()), Member: member})
	card := pipe.ZCard(ctx, key)
	pipe.PExpire(ctx, key, l.streamTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, fmt.Errorf("stream-cap acquire for %s: %w", name, err)
	}
	if card.Val() <= int64(maxN) {
		return true, nil
	}
	if err := l.rdb.ZRem(ctx, key, member).Err(); err != nil {
		l.logger.Debug("stream-cap rollback failed (the member expires with its score)", "tunnel", name, "err", err)
	}
	return false, nil
}

func (l *Limiter) ReleaseStream(ctx context.Context, name, member string) error {
	if err := l.rdb.ZRem(ctx, concKey(name), member).Err(); err != nil {
		return fmt.Errorf("stream-cap release for %s: %w", name, err)
	}
	return nil
}
