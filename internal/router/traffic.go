package router

import (
	"context"
	"time"
)

// orphanTTL bounds a byte-only key that a post-disconnect flush may create on a gone route: it is
// non-routable (LookupRoute keys on `node`) and self-expires. Live routes keep their own r.ttl.
const orphanTTL = 30 * time.Second

// AddTraffic adds bytes to tunnel:{name} WITHOUT resurrecting a dead route: HINCRBY on a live key updates
// it (EXPIRE NX no-ops, the route's own TTL stands); HINCRBY on a gone key creates a byte-only, non-routable
// key that EXPIRE NX gives a short TTL so it self-expires. Off the data plane (recorder flusher only).
func (r *Registry) AddTraffic(ctx context.Context, name string, bytesIn, bytesOut int64) error {
	pipe := r.rdb.Pipeline()
	if bytesIn != 0 {
		pipe.HIncrBy(ctx, key(name), "bytes_in", bytesIn)
	}
	if bytesOut != 0 {
		pipe.HIncrBy(ctx, key(name), "bytes_out", bytesOut)
	}
	pipe.ExpireNX(ctx, key(name), orphanTTL) // no-op on a live route (already has a TTL); caps an orphan
	_, err := pipe.Exec(ctx)
	return err
}
