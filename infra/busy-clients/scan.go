package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"path"
	"strings"
	"sync"
	"time"

	"go4.org/netipx"
	"golang.org/x/sync/errgroup"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/bucket"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/report"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

const (
	logsPrefix    = "tunnel-logs/"
	logNameLayout = "20060102T150405.000000000Z"
	window        = 24 * time.Hour
	fileMargin    = 10 * time.Minute
	parallelReads = 16
	maxLineBytes  = 1 << 20
	ipv6Bits      = 64
)

const crashedMsg = "reading a connection log crashed, so this run stops without sending an alert or changing the list of alerted addresses"

type tally struct {
	files, connections, malformed int
}

func fileStart(key string) (time.Time, bool) {
	stamp, _, ok := strings.Cut(path.Base(key), "-")
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(logNameLayout, stamp)
	return t, err == nil
}

func dayPrefixes(from, to time.Time) []string {
	from, to = from.UTC(), to.UTC()
	var out []string
	for d := time.Date(from.Year(), from.Month(), from.Day(), 0, 0, 0, 0, time.UTC); !d.After(to); d = d.AddDate(0, 0, 1) {
		out = append(out, fmt.Sprintf("%s%04d/%02d/%02d/", logsPrefix, d.Year(), d.Month(), d.Day()))
	}
	return out
}

func addressOf(a netip.Addr) string {
	if a.Is4() {
		return a.String()
	}
	return netip.PrefixFrom(a, ipv6Bits).Masked().String()
}

func (j *job) logKeys(ctx context.Context, from, to time.Time) ([]string, error) {
	oldest := from.Add(-fileMargin)
	var keys []string
	for _, prefix := range dayPrefixes(oldest, to) {
		listed, err := j.Store.List(ctx, prefix)
		if err != nil {
			return nil, fmt.Errorf("list the connection logs under %s: %w", prefix, err)
		}
		for _, key := range listed {
			start, ok := fileStart(key)
			if !ok {
				j.Logger.Warn("a connection log has a name that does not start with its time, so it is not read", "node", j.Node, "key", key)
				continue
			}
			if !start.Before(oldest) && !start.After(to) {
				keys = append(keys, key)
			}
		}
	}
	return keys, nil
}

func (j *job) scan(ctx context.Context, from, to time.Time, skip *netipx.IPSet) (map[string]*usage, tally, error) {
	keys, err := j.logKeys(ctx, from, to)
	if err != nil {
		return nil, tally{}, err
	}
	var (
		mu    sync.Mutex
		total = map[string]*usage{}
		t     = tally{files: len(keys)}
		errs  []error
	)
	var g errgroup.Group
	g.SetLimit(parallelReads)
	for _, key := range keys {
		g.Go(func() (err error) {
			defer func() {
				if err != nil && (ctx.Err() == nil || !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)) {
					mu.Lock()
					errs = append(errs, err)
					mu.Unlock()
				}
			}()
			rctx := report.WithScope(ctx)
			report.SetAttrs(rctx, slog.String("key", key))
			defer report.RecoverWith(rctx, j.Logger, "reading a connection log", crashedMsg, func() {
				err = fmt.Errorf("reading the connection log %s crashed", key)
			})
			part, connections, malformed, err := j.readLog(rctx, key, from, to, skip)
			if err != nil {
				return err
			}
			if malformed > 0 {
				j.Logger.Warn("a connection log has lines that are not connection events, so they are not counted",
					"node", j.Node, "key", key, "lines", malformed)
			}
			mu.Lock()
			merge(total, part)
			t.connections += connections
			t.malformed += malformed
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		mu.Lock()
		defer mu.Unlock()
		if len(errs) == 0 {
			return nil, tally{}, err
		}
		return nil, tally{}, errors.Join(errs...)
	}
	return total, t, nil
}

func (j *job) readLog(ctx context.Context, key string, from, to time.Time, skip *netipx.IPSet) (map[string]*usage, int, int, error) {
	body, err := j.Store.Get(ctx, key)
	if errors.Is(err, bucket.ErrNotFound) {
		return nil, 0, 0, nil
	}
	if err != nil {
		return nil, 0, 0, fmt.Errorf("read the connection log %s: %w", key, err)
	}
	part := map[string]*usage{}
	connections, malformed := 0, 0
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var ev store.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			malformed++
			continue
		}
		if ev.Event != "start" || ev.Type != "public" || ev.TSStart.Before(from) || ev.TSStart.After(to) {
			continue
		}
		addr, err := netip.ParseAddr(ev.SrcIP)
		if err != nil {
			malformed++
			continue
		}
		addr = addr.Unmap()
		if skip.Contains(addr) {
			continue
		}
		connections++
		add(part, addr, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, 0, 0, fmt.Errorf("read the lines of the connection log %s: %w", key, err)
	}
	return part, connections, malformed, nil
}

func add(m map[string]*usage, a netip.Addr, ev store.Event) {
	key := addressOf(a)
	u := m[key]
	if u == nil {
		u = &usage{address: key, lookup: a, tunnels: map[string]struct{}{}, fingerprints: map[string]struct{}{}, first: ev.TSStart, last: ev.TSStart}
		m[key] = u
	}
	u.connections++
	u.tunnels[ev.Tunnel] = struct{}{}
	if ev.TLSFP != "" {
		u.fingerprints[ev.TLSFP] = struct{}{}
	}
	if ev.TSStart.Before(u.first) {
		u.first, u.lookup = ev.TSStart, a
	}
	if ev.TSStart.After(u.last) {
		u.last = ev.TSStart
	}
}

func merge(dst, src map[string]*usage) {
	for key, s := range src {
		d := dst[key]
		if d == nil {
			dst[key] = s
			continue
		}
		d.connections += s.connections
		for name := range s.tunnels {
			d.tunnels[name] = struct{}{}
		}
		for fp := range s.fingerprints {
			d.fingerprints[fp] = struct{}{}
		}
		if s.first.Before(d.first) {
			d.first, d.lookup = s.first, s.lookup
		}
		if s.last.After(d.last) {
			d.last = s.last
		}
	}
}
