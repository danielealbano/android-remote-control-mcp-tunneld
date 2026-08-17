package limit

import (
	"sync"
	"time"
)

const defaultBucketIdle = 10 * time.Minute

// BucketRegistry hands out THE SAME per-tunnel (up, down) bucket pair for a given name within this
// process, so the ingress paced body-reader and the WS chunk pacing draw from ONE budget when
// co-located on the same replica (docs/ARCHITECTURE.md §4). Unpinned entries idle longer than the
// idle window are evicted (bounded memory across ephemeral tunnel names); a live connection pins its
// pair (see Pin) so it is never evicted mid-connection.
//
// Cross-replica exactness is deliberately NOT attempted (user decision) — a distributed bucket would
// put a synchronous Redis call on the data plane per 32 KiB slice.
type BucketRegistry struct {
	mu   sync.Mutex
	m    map[string]*bucketEntry
	bps  int64
	idle time.Duration
	now  func() time.Time
}

type bucketEntry struct {
	up, down   *TokenBucket
	lastAccess time.Time
	pins       int
}

// NewBucketRegistry builds a registry minting buckets at bytesPerSec, using the real clock and the
// default idle-eviction window.
func NewBucketRegistry(bytesPerSec int64) *BucketRegistry {
	return newBucketRegistry(bytesPerSec, defaultBucketIdle, time.Now)
}

func newBucketRegistry(bytesPerSec int64, idle time.Duration, now func() time.Time) *BucketRegistry {
	return &BucketRegistry{
		m:    map[string]*bucketEntry{},
		bps:  bytesPerSec,
		idle: idle,
		now:  now,
	}
}

// Pair returns the SAME (up, down) bucket instances for name, creating them on demand, and lazily
// evicts UNPINNED entries idle past the idle window. A live WS connection pins its pair (see Pin) so
// it is never evicted mid-connection — the ingress paced reader and the WS leg keep sharing ONE
// budget (docs/ARCHITECTURE.md §4).
func (r *BucketRegistry) Pair(name string) (up, down *TokenBucket) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for k, e := range r.m {
		if e.pins == 0 && now.Sub(e.lastAccess) > r.idle {
			delete(r.m, k)
		}
	}
	e := r.ensure(name)
	e.lastAccess = now
	return e.up, e.down
}

// Pin returns name's pair and increments its pin count so the entry survives idle eviction until the
// matching Unpin. Called by the WS manager at bind.
func (r *BucketRegistry) Pin(name string) (up, down *TokenBucket) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.ensure(name)
	e.pins++
	e.lastAccess = r.now()
	return e.up, e.down
}

// Unpin drops one pin previously taken by Pin. Called by the WS manager at teardown.
func (r *BucketRegistry) Unpin(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.m[name]; ok && e.pins > 0 {
		e.pins--
	}
}

func (r *BucketRegistry) ensure(name string) *bucketEntry {
	e, ok := r.m[name]
	if !ok {
		u, d := NewTunnelBandwidth(r.bps)
		e = &bucketEntry{up: u, down: d}
		r.m[name] = e
	}
	return e
}
