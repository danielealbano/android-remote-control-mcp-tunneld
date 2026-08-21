package limit

import (
	"context"
	"errors"
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

func issuanceKey(name string) string { return "iss:" + name }
func issLockKey(name string) string  { return "iss_lock:" + name }

// IssuanceBegin serializes issuance per tunnel via a SETNX lock (only one in-flight order per tunnel) and
// gates against the weekly success cap under that lock. Returns the lock token as orderID for
// HeartbeatLoop/End. ok=false = another order in flight OR cap reached.
func (l *Limiter) IssuanceBegin(ctx context.Context, name string, maxN int) (ok bool, orderID string, err error) {
	token := mintToken()
	got, err := l.rdb.SetNX(ctx, issLockKey(name), token, issLockTTL).Result()
	if err != nil {
		return false, "", err
	}
	if !got {
		return false, "", nil // another issuance in flight
	}
	n, err := l.rdb.Get(ctx, issuanceKey(name)).Int()
	if err != nil && !errors.Is(err, redis.Nil) {
		l.releaseIssLock(ctx, name, token)
		return false, "", err
	}
	if n >= maxN {
		l.releaseIssLock(ctx, name, token) // over cap — release and refuse
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
			// Refresh the lock TTL while we still hold it. The GET(value==orderID) then PEXPIRE is a benign,
			// rare TOCTOU: if the lock expired and another order re-acquired it between the two commands, the
			// PEXPIRE extends the new holder's TTL — harmless and self-healing under the posture. Best-effort;
			// a failure is logged.
			if v, err := l.rdb.Get(ctx, issLockKey(name)).Result(); err == nil && v == orderID {
				if err := l.rdb.PExpire(ctx, issLockKey(name), issLockTTL).Err(); err != nil {
					l.logger.Warn("issuance lock refresh failed (lock may expire; a retry could then start)",
						"tunnel", name, "err", err)
				}
			}
		}
	}
}

// IssuanceEnd releases the lock (success AND failure — failed orders never burn the window).
func (l *Limiter) IssuanceEnd(ctx context.Context, name, orderID string) error {
	l.releaseIssLock(ctx, name, orderID)
	return nil
}

func (l *Limiter) releaseIssLock(ctx context.Context, name, token string) {
	if v, err := l.rdb.Get(ctx, issLockKey(name)).Result(); err == nil && v == token {
		_ = l.rdb.Del(ctx, issLockKey(name)).Err()
	}
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
