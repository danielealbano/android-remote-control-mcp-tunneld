package router

import (
	"context"
	"errors"

	"github.com/redis/go-redis/v9"
)

// ErrConnIDCollision is returned by BindRoute when the connID it is asked to bind equals the connID
// already stored for the name (a re-roll signal): the caller re-mints the connID and retries.
var ErrConnIDCollision = errors.New("router: connID collides with the current route owner")

var bindRouteScript = redis.NewScript(`
local fp = redis.call('HGET', KEYS[1], 'fingerprint')
if fp and fp ~= ARGV[2] then
  return 'conflict'
end
if redis.call('HGET', KEYS[1], 'connID') == ARGV[3] then
  return 'reroll'
end
redis.call('HSET', KEYS[1], 'node', ARGV[1], 'fingerprint', ARGV[2], 'connID', ARGV[3])
redis.call('PEXPIRE', KEYS[1], ARGV[4])
return 'ok'
`)

var selfHealRouteScript = redis.NewScript(`
local v = redis.call('HMGET', KEYS[1], 'node', 'fingerprint', 'connID')
if v[1] == false then
  redis.call('HSET', KEYS[1], 'node', ARGV[1], 'fingerprint', ARGV[2], 'connID', ARGV[3])
  redis.call('PEXPIRE', KEYS[1], ARGV[4])
  return 'bound'
end
if v[2] ~= ARGV[2] then
  return 'conflict'
end
if v[3] ~= ARGV[3] then
  return 'not-owner'
end
redis.call('HSET', KEYS[1], 'node', ARGV[1], 'fingerprint', ARGV[2], 'connID', ARGV[3])
redis.call('PEXPIRE', KEYS[1], ARGV[4])
return 'bound'
`)

// BindRoute writes route:{name} with node, fingerprint, and per-connection connID (fingerprint guard →
// ErrNameHeldByOther; a connID equal to the currently-stored one → ErrConnIDCollision, the re-roll
// signal). Heartbeat/Unbind stay owner-conditional on connID.
func (r *Registry) BindRoute(ctx context.Context, name, nodeID, fingerprint, connID string) error {
	res, err := bindRouteScript.Run(ctx, r.rdb, []string{key(name)},
		nodeID, fingerprint, connID, r.ttl.Milliseconds()).Text()
	if err != nil {
		return err
	}
	switch res {
	case "conflict":
		return ErrNameHeldByOther
	case "reroll":
		return ErrConnIDCollision
	default:
		return nil
	}
}

// BindRouteIfAbsentOrOwner is the self-heal variant used by the phone heartbeat's "missing" path: it
// binds only if the key is absent or still owned by this connID (same fingerprint).
func (r *Registry) BindRouteIfAbsentOrOwner(ctx context.Context, name, nodeID, fingerprint, connID string) (SelfHealResult, error) {
	res, err := selfHealRouteScript.Run(ctx, r.rdb, []string{key(name)},
		nodeID, fingerprint, connID, r.ttl.Milliseconds()).Text()
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

// LookupRoute returns the owning node, the identity-cert fingerprint, and the phone-connection connID,
// or ok=false when no tunnel is bound.
func (r *Registry) LookupRoute(ctx context.Context, name string) (nodeID, fingerprint, connID string, ok bool, err error) {
	vals, err := r.rdb.HMGet(ctx, key(name), "node", "fingerprint", "connID").Result()
	if err != nil {
		return "", "", "", false, err
	}
	node, _ := vals[0].(string)
	fp, _ := vals[1].(string)
	cid, _ := vals[2].(string)
	if node == "" {
		return "", "", "", false, nil
	}
	return node, fp, cid, true, nil
}
