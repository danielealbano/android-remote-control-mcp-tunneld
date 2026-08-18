package router

import (
	"context"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// The Plan-3 route methods ADD a startedAt field (the tunnel-session start = the phone control
// connection's establishment time, unix nanos) to the route record. startedAt is the conn-id epoch:
// any edge node minting a public conn id for a tunnel reads it from the LookupRoute it already does.
// These are added ALONGSIDE the Plan-1 Bind/Lookup/BindIfAbsentOrOwner (kept until the US13 teardown).

var bindRouteScript = redis.NewScript(`
local fp = redis.call('HGET', KEYS[1], 'fingerprint')
if fp and fp ~= ARGV[2] then
  return 'conflict'
end
redis.call('HSET', KEYS[1], 'node', ARGV[1], 'fingerprint', ARGV[2], 'connID', ARGV[3], 'startedAt', ARGV[4])
redis.call('PEXPIRE', KEYS[1], ARGV[5])
return 'ok'
`)

var selfHealRouteScript = redis.NewScript(`
local v = redis.call('HMGET', KEYS[1], 'node', 'fingerprint', 'connID')
if v[1] == false then
  redis.call('HSET', KEYS[1], 'node', ARGV[1], 'fingerprint', ARGV[2], 'connID', ARGV[3], 'startedAt', ARGV[4])
  redis.call('PEXPIRE', KEYS[1], ARGV[5])
  return 'bound'
end
if v[2] ~= ARGV[2] then
  return 'conflict'
end
if v[3] ~= ARGV[3] then
  return 'not-owner'
end
redis.call('HSET', KEYS[1], 'node', ARGV[1], 'fingerprint', ARGV[2], 'connID', ARGV[3], 'startedAt', ARGV[4])
redis.call('PEXPIRE', KEYS[1], ARGV[5])
return 'bound'
`)

// BindRoute writes route:{name} with node, fingerprint, per-connection connID, and the tunnel-session
// startedAt (fingerprint guard → ErrNameHeldByOther). Heartbeat/Unbind are shared with Plan-1 and
// stay owner-conditional on connID.
func (r *Registry) BindRoute(ctx context.Context, name, nodeID, fingerprint, connID string, startedAt time.Time) error {
	res, err := bindRouteScript.Run(ctx, r.rdb, []string{key(name)},
		nodeID, fingerprint, connID, strconv.FormatInt(startedAt.UnixNano(), 10), r.ttl.Milliseconds()).Text()
	if err != nil {
		return err
	}
	if res == "conflict" {
		return ErrNameHeldByOther
	}
	return nil
}

// BindRouteIfAbsentOrOwner is the epoch-preserving self-heal variant used by the phone heartbeat's
// "missing" path: it binds only if the key is absent or still owned by this connID (same fingerprint).
func (r *Registry) BindRouteIfAbsentOrOwner(ctx context.Context, name, nodeID, fingerprint, connID string, startedAt time.Time) (SelfHealResult, error) {
	res, err := selfHealRouteScript.Run(ctx, r.rdb, []string{key(name)},
		nodeID, fingerprint, connID, strconv.FormatInt(startedAt.UnixNano(), 10), r.ttl.Milliseconds()).Text()
	if err != nil {
		return SelfHealNotOwner, err
	}
	switch res {
	case "bound":
		return SelfHealBound, nil
	case "not-owner":
		return SelfHealNotOwner, nil
	default: // "conflict"
		return SelfHealConflict, ErrNameHeldByOther
	}
}

// LookupRoute returns the owning node, the identity-cert fingerprint, the phone-connection connID, and
// the tunnel-session startedAt (the conn-id epoch), or ok=false when no tunnel is bound.
func (r *Registry) LookupRoute(ctx context.Context, name string) (nodeID, fingerprint, connID string, startedAt time.Time, ok bool, err error) {
	vals, err := r.rdb.HMGet(ctx, key(name), "node", "fingerprint", "connID", "startedAt").Result()
	if err != nil {
		return "", "", "", time.Time{}, false, err
	}
	node, _ := vals[0].(string)
	fp, _ := vals[1].(string)
	cid, _ := vals[2].(string)
	if node == "" {
		return "", "", "", time.Time{}, false, nil
	}
	if s, _ := vals[3].(string); s != "" {
		if ns, perr := strconv.ParseInt(s, 10, 64); perr == nil {
			startedAt = time.Unix(0, ns)
		}
	}
	return node, fp, cid, startedAt, true, nil
}
