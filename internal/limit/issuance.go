package limit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// The issuance counter iss:{name} counts SUCCESSFUL public-cert issuances per rolling 7-day window. One
// in-flight issuance per tunnel is the only real case, so concurrent /api/v1/issue calls are serialized by a
// SETNX iss_lock:{name} lock: the holder gates against the weekly cap and only a successful order increments
// the counter, so a failed/crashed order never burns the window and self-releases via the lock TTL.

const (
	issLockTTL   = 15 * time.Second // 3 missed 5s beats; a crashed order releases within this
	issLockBeat  = 5 * time.Second  // IssuanceHeartbeatLoop refresh cadence
	issWindowTTL = 7 * 24 * time.Hour
)

var ErrIssuanceInFlight = errors.New("limit: another issuance for this name is in flight")

func issuanceKey(name string) string { return "iss:" + name }
func issLockKey(name string) string  { return "iss_lock:" + name }

// IssuanceBegin serializes issuance per tunnel via a SETNX lock (only one in-flight order per tunnel) and
// gates against the weekly success cap under that lock. Returns the lock token as orderID for
// HeartbeatLoop/End. ok=false = cap reached.
func (l *Limiter) IssuanceBegin(ctx context.Context, name string, maxN int) (ok bool, orderID string, err error) {
	token := mintToken()
	got, err := l.rdb.SetNX(ctx, issLockKey(name), token, issLockTTL).Result()
	if err != nil {
		return false, "", err
	}
	if !got {
		return false, "", ErrIssuanceInFlight // another issuance in flight
	}
	n, err := l.rdb.Get(ctx, issuanceKey(name)).Int()
	if err != nil && !errors.Is(err, redis.Nil) {
		return false, "", errors.Join(fmt.Errorf("issuance count read: %w", err), l.releaseIssLock(ctx, name, token))
	}
	if n >= maxN {
		if rerr := l.releaseIssLock(ctx, name, token); rerr != nil && ctx.Err() == nil { // over cap — release and refuse
			l.logger.Warn("issuance lock release failed (lock expires by TTL)", "tunnel", name, "err", rerr)
		}
		return false, "", nil
	}
	return true, token, nil
}

// IssuanceHeartbeatLoop refreshes the lock TTL every issLockBeat until ctx is done, so a live (slow ACME)
// order keeps the lock; a crash stops the refresh and the lock self-expires.
func (l *Limiter) IssuanceHeartbeatLoop(ctx context.Context, name, orderID string) {
	t := time.NewTicker(issLockBeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.refreshIssLock(ctx, name, orderID)
		}
	}
}

// Refresh the lock TTL while we still hold it. The GET(value==orderID) then PEXPIRE is a benign,
// rare TOCTOU: if the lock expired and another order re-acquired it between the two commands, the
// PEXPIRE extends the new holder's TTL — harmless and self-healing under the posture. Best-effort;
// a failure is logged.
func (l *Limiter) refreshIssLock(ctx context.Context, name, orderID string) {
	v, err := l.rdb.Get(ctx, issLockKey(name)).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) && ctx.Err() == nil {
			l.logger.Warn("issuance lock refresh check failed (lock may expire; a retry could then start)",
				"tunnel", name, "err", err)
		}
		return
	}
	if v == orderID {
		if err := l.rdb.PExpire(ctx, issLockKey(name), issLockTTL).Err(); err != nil && ctx.Err() == nil {
			l.logger.Warn("issuance lock refresh failed (lock may expire; a retry could then start)",
				"tunnel", name, "err", err)
		}
	}
}

// IssuanceEnd releases the lock (success AND failure — failed orders never burn the window).
func (l *Limiter) IssuanceEnd(ctx context.Context, name, orderID string) error {
	return l.releaseIssLock(ctx, name, orderID)
}

func (l *Limiter) releaseIssLock(ctx context.Context, name, token string) error {
	v, err := l.rdb.Get(ctx, issLockKey(name)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil
		}
		return fmt.Errorf("issuance lock release check: %w", err)
	}
	if v != token {
		return nil
	}
	if err := l.rdb.Del(ctx, issLockKey(name)).Err(); err != nil {
		return fmt.Errorf("issuance lock release: %w", err)
	}
	return nil
}

// IssuanceRecord increments the rolling-7d success counter (called ONLY after a public cert issues, under
// the still-held lock). INCR + EXPIRE NX (TTL anchored at the first success in the window).
func (l *Limiter) IssuanceRecord(ctx context.Context, name string) error {
	pipe := l.rdb.Pipeline()
	pipe.Incr(ctx, issuanceKey(name))
	pipe.ExpireNX(ctx, issuanceKey(name), issWindowTTL)
	_, err := pipe.Exec(ctx)
	return err
}
