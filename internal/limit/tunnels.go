package limit

import (
	"context"
	"strconv"

	"github.com/redis/go-redis/v9"
)

// TunnelStat is the live per-tunnel window snapshot for the admin stats endpoint.
type TunnelStat struct {
	Conc    int64 `json:"conc"`
	BwIn    int64 `json:"bw_in"` // bytes in the last COMPLETE second (sec-1)
	BwOut   int64 `json:"bw_out"`
	DayIn   int64 `json:"day_in"`
	DayOut  int64 `json:"day_out"`
	WeekIn  int64 `json:"week_in"`
	WeekOut int64 `json:"week_out"`
}

// TunnelWindows batch-reads conc + last-complete-second bandwidth + day/week traffic for names, computing
// every key from name + clock (no metric-keyspace SCAN). These are GLOBAL shared counters, so the values
// are the cross-replica aggregate. conc:{name} is a HASH, read via HMGET (MGET can't read a hash); the
// six string windows are one MGET — both in a single pipeline.
func (l *Limiter) TunnelWindows(ctx context.Context, names []string) (map[string]TunnelStat, error) {
	if len(names) == 0 {
		return map[string]TunnelStat{}, nil
	}
	sec := l.now().Unix()
	prev := strconv.FormatInt(sec-1, 10) // last complete second
	d := strconv.FormatInt(sec/86400, 10)
	w := strconv.FormatInt(sec/86400/7, 10)
	const perName = 6 // six string windows; conc:{name} is a HASH, read via HMGET below
	keys := make([]string, 0, len(names)*perName)
	for _, n := range names {
		keys = append(keys,
			"bw:"+n+":in:"+prev, "bw:"+n+":out:"+prev,
			"traf:"+n+":in:day:"+d, "traf:"+n+":out:day:"+d,
			"traf:"+n+":in:week:"+w, "traf:"+n+":out:week:"+w,
		)
	}
	pipe := l.rdb.Pipeline()
	concCmds := make([]*redis.SliceCmd, len(names))
	for i, n := range names {
		concCmds[i] = pipe.HMGet(ctx, "conc:"+n, "count") // HMGET on a missing key/field → [nil], no error
	}
	mget := pipe.MGet(ctx, keys...)
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, err
	}
	vals := mget.Val()
	out := make(map[string]TunnelStat, len(names))
	for i, n := range names {
		b := i * perName
		var conc int64
		if cv := concCmds[i].Val(); len(cv) > 0 {
			conc = atoiCap(cv[0]) // atoiCap treats nil / non-string as 0
		}
		out[n] = TunnelStat{
			Conc: conc, BwIn: atoiCap(vals[b]), BwOut: atoiCap(vals[b+1]),
			DayIn: atoiCap(vals[b+2]), DayOut: atoiCap(vals[b+3]),
			WeekIn: atoiCap(vals[b+4]), WeekOut: atoiCap(vals[b+5]),
		}
	}
	return out, nil
}
