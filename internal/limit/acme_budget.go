package limit

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

type Rate struct {
	Count  int
	Period time.Duration
	Burst  int
}

type Bucket struct {
	Key      string
	Capacity float64
	Refill   time.Duration
}

func (r Rate) Bucket(key string) Bucket {
	refill := r.Period
	if r.Count > 0 {
		refill = r.Period / time.Duration(r.Count)
	}
	return Bucket{Key: key, Capacity: float64(r.Burst), Refill: refill}
}

const (
	budgetLockTTL     = 2 * time.Second
	budgetLockTries   = 100
	budgetLockBackoff = 10 * time.Millisecond
	budgetKeyMargin   = time.Hour
	inflightKeyMargin = time.Minute
)

var ErrBudgetLockContended = errors.New("limit: acme budget lock contended")

func budgetKey(b Bucket) string                { return "acme-budget:" + b.Key }
func inflightKey(b Bucket, node string) string { return "acme:inflight:" + b.Key + ":" + node }
func budgetLockKey(ca string) string           { return "lock:acme-budget:" + ca }

type bucketState struct {
	tokens float64
	at     time.Time
}

func (b Bucket) tokensAt(s bucketState, now time.Time) float64 {
	if now.Before(s.at) || b.Refill <= 0 {
		return s.tokens
	}
	return min(b.Capacity, s.tokens+float64(now.Sub(s.at))/float64(b.Refill))
}

func (b Bucket) waitFor(s bucketState, now time.Time, need float64) time.Duration {
	if need > b.Capacity {
		return b.Refill
	}
	if now.Before(s.at) {
		return s.at.Sub(now) + time.Duration((need-s.tokens)*float64(b.Refill))
	}
	return time.Duration((need - b.tokensAt(s, now)) * float64(b.Refill))
}

func (b Bucket) spend(s bucketState, now time.Time) bucketState {
	if now.Before(s.at) {
		return bucketState{tokens: s.tokens - 1, at: s.at}
	}
	return bucketState{tokens: b.tokensAt(s, now) - 1, at: now}
}

func (l *Limiter) withBudgetLock(ctx context.Context, ca string, fn func() error) error {
	token := mintToken()
	for range budgetLockTries {
		ok, err := l.rdb.SetNX(ctx, budgetLockKey(ca), token, budgetLockTTL).Result()
		if err != nil {
			return fmt.Errorf("acme budget lock %s: %w", ca, err)
		}
		if ok {
			defer l.releaseBudgetLock(ctx, ca, token)
			return fn()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(budgetLockBackoff):
		}
	}
	return ErrBudgetLockContended
}

func (l *Limiter) releaseBudgetLock(ctx context.Context, ca, token string) {
	v, err := l.rdb.Get(ctx, budgetLockKey(ca)).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) && ctx.Err() == nil {
			l.logger.Warn("acme budget lock release check failed (lock expires by TTL)", "ca", ca, "err", err)
		}
		return
	}
	if v != token {
		return
	}
	if err := l.rdb.Del(ctx, budgetLockKey(ca)).Err(); err != nil && ctx.Err() == nil {
		l.logger.Warn("acme budget lock release failed (lock expires by TTL)", "ca", ca, "err", err)
	}
}

func (l *Limiter) parseBucket(b Bucket, vals []any, now time.Time) bucketState {
	if len(vals) != 2 || vals[0] == nil || vals[1] == nil {
		return bucketState{tokens: b.Capacity, at: now}
	}
	ts, okT := vals[0].(string)
	as, okA := vals[1].(string)
	t, errT := strconv.ParseFloat(ts, 64)
	at, errA := strconv.ParseInt(as, 10, 64)
	if !okT || !okA || errT != nil || errA != nil {
		l.logger.Warn("unparseable acme budget (treated as full)", "bucket", b.Key, "err", errors.Join(errT, errA))
		return bucketState{tokens: b.Capacity, at: now}
	}
	return bucketState{tokens: t, at: time.UnixMilli(at)}
}

func (l *Limiter) readBuckets(ctx context.Context, bs []Bucket, now time.Time) ([]bucketState, error) {
	pipe := l.rdb.Pipeline()
	cmds := make([]*redis.SliceCmd, len(bs))
	for i, b := range bs {
		cmds[i] = pipe.HMGet(ctx, budgetKey(b), "t", "at")
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("read acme budgets: %w", err)
	}
	out := make([]bucketState, len(bs))
	for i, b := range bs {
		out[i] = l.parseBucket(b, cmds[i].Val(), now)
	}
	return out, nil
}

func writeBucket(ctx context.Context, pipe redis.Pipeliner, b Bucket, s bucketState, now time.Time) {
	key := budgetKey(b)
	pipe.HSet(ctx, key, "t", strconv.FormatFloat(s.tokens, 'f', -1, 64), "at", strconv.FormatInt(s.at.UnixMilli(), 10))
	ttl := time.Duration((b.Capacity-min(s.tokens, b.Capacity))*float64(b.Refill)) + budgetKeyMargin
	if s.at.After(now) {
		ttl += s.at.Sub(now)
	}
	pipe.PExpire(ctx, key, ttl)
}

func (l *Limiter) inflightCounts(ctx context.Context, bs []Bucket, live []string, now time.Time) ([]int64, error) {
	out := make([]int64, len(bs))
	if len(live) == 0 {
		return out, nil
	}
	pipe := l.rdb.Pipeline()
	floor := strconv.FormatInt(now.UnixMilli(), 10)
	cmds := make([][]*redis.IntCmd, len(bs))
	for i, b := range bs {
		for _, node := range live {
			key := inflightKey(b, node)
			pipe.ZRemRangeByScore(ctx, key, "-inf", floor)
			cmds[i] = append(cmds[i], pipe.ZCard(ctx, key))
		}
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("count in-flight acme orders: %w", err)
	}
	for i := range bs {
		for _, c := range cmds[i] {
			out[i] += c.Val()
		}
	}
	return out, nil
}

func (l *Limiter) ReserveACME(ctx context.Context, ca string, bs []Bucket, node, member string, deadline time.Time, live []string) (bool, time.Duration, error) {
	if len(bs) == 0 {
		return true, 0, nil
	}
	var (
		ok   bool
		wait time.Duration
	)
	err := l.withBudgetLock(ctx, ca, func() error {
		now := l.now()
		states, err := l.readBuckets(ctx, bs, now)
		if err != nil {
			return err
		}
		held, err := l.inflightCounts(ctx, bs, live, now)
		if err != nil {
			return err
		}
		for i, b := range bs {
			if b.tokensAt(states[i], now)-float64(held[i]) < 1 {
				wait = max(wait, b.waitFor(states[i], now, float64(held[i])+1), time.Second)
			}
		}
		if wait > 0 {
			return nil
		}
		pipe := l.rdb.Pipeline()
		for _, b := range bs {
			key := inflightKey(b, node)
			pipe.ZAdd(ctx, key, redis.Z{Score: float64(deadline.UnixMilli()), Member: member})
			pipe.ExpireNX(ctx, key, deadline.Sub(now)+inflightKeyMargin)
			pipe.ExpireGT(ctx, key, deadline.Sub(now)+inflightKeyMargin)
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("reserve acme budget: %w", err)
		}
		ok = true
		return nil
	})
	return ok, wait, err
}

func (l *Limiter) CommitACME(ctx context.Context, ca string, b Bucket, node, member string) error {
	return l.withBudgetLock(ctx, ca, func() error {
		now := l.now()
		states, err := l.readBuckets(ctx, []Bucket{b}, now)
		if err != nil {
			return err
		}
		pipe := l.rdb.Pipeline()
		writeBucket(ctx, pipe, b, b.spend(states[0], now), now)
		pipe.ZRem(ctx, inflightKey(b, node), member)
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("spend acme budget %s: %w", b.Key, err)
		}
		return nil
	})
}

func (l *Limiter) ReleaseACME(ctx context.Context, bs []Bucket, node, member string) error {
	if len(bs) == 0 {
		return nil
	}
	pipe := l.rdb.Pipeline()
	for _, b := range bs {
		pipe.ZRem(ctx, inflightKey(b, node), member)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("release acme budget: %w", err)
	}
	return nil
}

func (l *Limiter) TakeACME(ctx context.Context, ca string, bs []Bucket) (time.Duration, error) {
	if len(bs) == 0 {
		return 0, nil
	}
	var wait time.Duration
	err := l.withBudgetLock(ctx, ca, func() error {
		now := l.now()
		states, err := l.readBuckets(ctx, bs, now)
		if err != nil {
			return err
		}
		for i, b := range bs {
			if b.tokensAt(states[i], now) < 1 {
				wait = max(wait, b.waitFor(states[i], now, 1), time.Millisecond)
			}
		}
		if wait > 0 {
			return nil
		}
		pipe := l.rdb.Pipeline()
		for i, b := range bs {
			writeBucket(ctx, pipe, b, b.spend(states[i], now), now)
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("take acme request budget: %w", err)
		}
		return nil
	})
	return wait, err
}

func (l *Limiter) ResyncACME(ctx context.Context, ca string, bs []Bucket, retryAfter time.Duration) error {
	if len(bs) == 0 {
		return nil
	}
	return l.withBudgetLock(ctx, ca, func() error {
		now := l.now()
		pipe := l.rdb.Pipeline()
		for _, b := range bs {
			writeBucket(ctx, pipe, b, bucketState{tokens: 0, at: now.Add(retryAfter - b.Refill)}, now)
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("resync acme budgets: %w", err)
		}
		return nil
	})
}

func (l *Limiter) ACMEBudgetLevel(ctx context.Context, b Bucket, live []string) (float64, error) {
	if b.Capacity <= 0 {
		return 0, nil
	}
	now := l.now()
	states, err := l.readBuckets(ctx, []Bucket{b}, now)
	if err != nil {
		return 0, err
	}
	held, err := l.inflightCounts(ctx, []Bucket{b}, live, now)
	if err != nil {
		return 0, err
	}
	return max(0, min(1, (b.tokensAt(states[0], now)-float64(held[0]))/b.Capacity)), nil
}
