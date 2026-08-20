package limit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/redis/go-redis/v9"
)

// The issuance counter iss:{name} is consumed ONLY on a SUCCESSFUL public-cert issuance (via
// IssuanceRecord), so the per-tunnel/week cap counts successes only. The pre-issuance gate reserves a
// short-lived INFLIGHT slot (iss_inflight:{name}) so concurrent /api/v1/issue calls cannot both pass a cap
// that they only commit against at the end — a crashed order's slot self-expires, and a failed order
// never burns the weekly window.

const (
	// issuanceSlotTTL is the per-slot deadline: a crashed node's order slot self-expires after this
	// and is purged lazily by the next acquire — no cleanup goroutine.
	issuanceSlotTTL = 30 * time.Second
	// issuanceHeartbeatEvery refreshes a live order's slot deadline (3 missed beats = expiry).
	issuanceHeartbeatEvery = 10 * time.Second
	// issuanceKeyTTLMargin pads the hash key's own TTL past the newest slot deadline.
	issuanceKeyTTLMargin = 30 * time.Second
)

func issuanceKey(name string) string { return "iss:" + name }
func inflightKey(name string) string { return "iss_inflight:" + name }

// issuanceBeginScript purges expired slots, gates committed+inflight against the cap, and inserts
// this order's slot — all in ONE script so concurrent /api/v1/issue calls cannot both pass.
// KEYS[1]=iss:{name} KEYS[2]=iss_inflight:{name} ARGV: maxN, nowMs, orderID, slotTTLms, keyTTLms.
var issuanceBeginScript = redis.NewScript(`
local now = tonumber(ARGV[2])
local fields = redis.call('HGETALL', KEYS[2])
local inflight = 0
for i = 1, #fields, 2 do
  if tonumber(fields[i+1]) < now then
    redis.call('HDEL', KEYS[2], fields[i])
  else
    inflight = inflight + 1
  end
end
local committed = tonumber(redis.call('GET', KEYS[1]) or '0')
if committed + inflight >= tonumber(ARGV[1]) then
  return 0
end
redis.call('HSET', KEYS[2], ARGV[3], now + tonumber(ARGV[4]))
redis.call('PEXPIRE', KEYS[2], ARGV[5])
return 1
`)

// issuanceHeartbeatScript refreshes ONLY a still-present slot (an expired-and-purged slot must not
// resurrect). KEYS[1]=iss_inflight:{name} ARGV: orderID, nowMs, slotTTLms, keyTTLms.
var issuanceHeartbeatScript = redis.NewScript(`
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 1 then
  redis.call('HSET', KEYS[1], ARGV[1], tonumber(ARGV[2]) + tonumber(ARGV[3]))
  redis.call('PEXPIRE', KEYS[1], ARGV[4])
end
return 1
`)

// IssuanceBegin reserves an in-flight issuance slot for name (committed successes + live slots < maxN).
// It returns the minted order id used by IssuanceHeartbeatLoop/IssuanceEnd to refer to this slot.
func (l *Limiter) IssuanceBegin(ctx context.Context, name string, maxN int) (ok bool, orderID string, err error) {
	orderID, err = newOrderID()
	if err != nil {
		return false, "", err
	}
	now := l.now().UnixMilli()
	res, err := issuanceBeginScript.Run(ctx, l.rdb, []string{issuanceKey(name), inflightKey(name)},
		maxN, now, orderID, issuanceSlotTTL.Milliseconds(),
		(issuanceSlotTTL + issuanceKeyTTLMargin).Milliseconds()).Int64()
	if err != nil {
		return false, "", err
	}
	return res == 1, orderID, nil
}

// IssuanceHeartbeatLoop refreshes the slot every issuanceHeartbeatEvery until ctx is done.
func (l *Limiter) IssuanceHeartbeatLoop(ctx context.Context, name, orderID string) {
	ticker := time.NewTicker(issuanceHeartbeatEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.issuanceHeartbeat(ctx, name, orderID)
		}
	}
}

// issuanceHeartbeat refreshes the slot once. The 30s slot TTL is intentionally short (a Valkey blip is a
// real problem — fail fast and let the phone retry via the documented 503/retry_after path); a failed
// heartbeat is LOGGED so a voided slot (which could let a second concurrent order start) is diagnosable,
// not silent.
func (l *Limiter) issuanceHeartbeat(ctx context.Context, name, orderID string) {
	now := l.now().UnixMilli()
	if err := issuanceHeartbeatScript.Run(ctx, l.rdb, []string{inflightKey(name)},
		orderID, now, issuanceSlotTTL.Milliseconds(),
		(issuanceSlotTTL + issuanceKeyTTLMargin).Milliseconds()).Err(); err != nil {
		l.logger.Warn("issuance slot heartbeat failed (slot may expire; a concurrent order could then start)",
			"tunnel", name, "order", orderID, "err", err)
	}
}

// IssuanceEnd frees the slot (called on success AND failure — failed orders never burn the window).
func (l *Limiter) IssuanceEnd(ctx context.Context, name, orderID string) error {
	return l.rdb.HDel(ctx, inflightKey(name), orderID).Err()
}

// recordIssuanceScript INCRs the counter and sets a 7d TTL on the first increment (a sliding 7d window
// anchored at the first issuance in it).
var recordIssuanceScript = redis.NewScript(`
local c = redis.call('INCR', KEYS[1])
if c == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return c
`)

// IssuanceRecord atomically increments the rolling-7d per-tunnel issuance counter (called ONLY after a
// public cert is successfully issued).
func (l *Limiter) IssuanceRecord(ctx context.Context, name string) error {
	return recordIssuanceScript.Run(ctx, l.rdb, []string{issuanceKey(name)}, (7 * 24 * time.Hour).Milliseconds()).Err()
}

// newOrderID mints a per-order identifier (4 crypto/rand bytes, 8 lowercase hex) used as the inflight
// hash field for one /api/v1/issue call.
func newOrderID() (string, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}
