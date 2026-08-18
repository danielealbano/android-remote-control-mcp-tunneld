// Package admin holds per-tunnel live counters (bytes in/out) in Redis with a TTL, feeding
// the internal /admin/tunnels endpoint. TunnelStat lives here (not in metrics) to break the
// metrics↔admin import cycle: metrics imports admin, admin imports nothing from metrics.
package admin

import (
	"context"
	"sort"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// TunnelStat is one tunnel's aggregate counters.
type TunnelStat struct {
	Name     string `json:"name"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
}

// Store reads/writes the per-tunnel tcnt:{name} hash (fields bytes_in, bytes_out).
type Store struct {
	rdb redis.UniversalClient
	ttl time.Duration
}

// NewStore constructs a Store; ttl bounds how long an idle tunnel's counters persist.
func NewStore(rdb redis.UniversalClient, ttl time.Duration) *Store {
	return &Store{rdb: rdb, ttl: ttl}
}

// incrScript does HINCRBY + PEXPIRE in ONE Lua script so the key is always TTL'd (same invariant as
// the rate/concurrency limiters).
var incrScript = redis.NewScript(`
redis.call('HINCRBY', KEYS[1], ARGV[1], ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1
`)

// Incr adds n to a tunnel counter field (bytes_in|bytes_out) — the WRITE path, called only
// by the PromRecorder background flusher (never synchronously on the data plane).
func (s *Store) Incr(ctx context.Context, name, field string, n int64) error {
	return incrScript.Run(ctx, s.rdb, []string{"tcnt:" + name}, field, n, s.ttl.Milliseconds()).Err()
}

// TopN returns the top-n tunnels by total bytes (in+out), descending.
func (s *Store) TopN(ctx context.Context, n int) ([]TunnelStat, error) {
	var stats []TunnelStat
	seen := map[string]struct{}{}
	var cursor uint64
	for {
		keys, next, err := s.rdb.Scan(ctx, cursor, "tcnt:*", 100).Result()
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			if _, dup := seen[k]; dup {
				continue // SCAN may deliver a key more than once — count it once
			}
			seen[k] = struct{}{}
			h, err := s.rdb.HGetAll(ctx, k).Result()
			if err != nil {
				return nil, err
			}
			if len(h) == 0 {
				continue // key expired between SCAN and HGETALL — skip the phantom
			}
			stats = append(stats, TunnelStat{
				Name:     k[len("tcnt:"):],
				BytesIn:  atoi64(h["bytes_in"]),
				BytesOut: atoi64(h["bytes_out"]),
			})
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].BytesIn+stats[i].BytesOut > stats[j].BytesIn+stats[j].BytesOut
	})
	if n > 0 && len(stats) > n {
		stats = stats[:n]
	}
	return stats, nil
}

func atoi64(s string) int64 {
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}
