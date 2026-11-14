package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"time"

	"go4.org/netipx"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/telegram"
)

const (
	defaultTimeout = 120 * time.Second
	dateLayout     = "2006-01-02"
)

type objectStore interface {
	List(ctx context.Context, prefix string) ([]string, error)
	Get(ctx context.Context, key string) ([]byte, error)
	Put(ctx context.Context, key string, body []byte) error
}

type messenger interface {
	Send(ctx context.Context, html string) error
}

type rangeLoader func(ctx context.Context) ([]netip.Prefix, error)

type jobConfig struct {
	Store     objectStore
	Messages  messenger
	Ranges    rangeLoader
	Locate    locator
	Exclude   []string
	Rule      rule
	DailyHour int
	Node      string
	Location  *time.Location
	Logger    *slog.Logger
}

type job struct {
	jobConfig
	exclude []netip.Prefix
	now     func() time.Time
	timeout time.Duration
	pause   time.Duration
	sleep   func(context.Context, time.Duration) error
}

type jobOption func(*job) error

func withClock(now func() time.Time) jobOption {
	return func(j *job) error {
		if now == nil {
			return errors.New("the clock is missing")
		}
		j.now = now
		return nil
	}
}

func withTimeout(d time.Duration) jobOption {
	return func(j *job) error {
		if d <= 0 {
			return fmt.Errorf("the time limit %s is not positive", d)
		}
		j.timeout = d
		return nil
	}
}

func withPause(pause time.Duration, sleep func(context.Context, time.Duration) error) jobOption {
	return func(j *job) error {
		if sleep == nil {
			return errors.New("the sleep function is missing")
		}
		j.pause, j.sleep = pause, sleep
		return nil
	}
}

func newJob(cfg jobConfig, opts ...jobOption) (*job, error) {
	switch {
	case cfg.Store == nil:
		return nil, errors.New("the object store is missing")
	case cfg.Messages == nil:
		return nil, errors.New("the messenger is missing")
	case cfg.Ranges == nil:
		return nil, errors.New("the address range loader is missing")
	case cfg.Locate == nil:
		return nil, errors.New("the address locator is missing")
	case cfg.DailyHour < 0 || cfg.DailyHour > 23:
		return nil, fmt.Errorf("the hour of the daily line %d is not between 0 and 23", cfg.DailyHour)
	case cfg.Node == "":
		return nil, errors.New("the node name is empty")
	case cfg.Location == nil:
		return nil, errors.New("the time zone is missing")
	case cfg.Logger == nil:
		return nil, errors.New("the logger is missing")
	}
	if err := cfg.Rule.validate(); err != nil {
		return nil, err
	}
	exclude, err := parseExclude(cfg.Exclude)
	if err != nil {
		return nil, err
	}
	j := &job{jobConfig: cfg, exclude: exclude, now: time.Now, timeout: defaultTimeout, pause: time.Second, sleep: telegram.Sleep}
	for _, opt := range opts {
		if err := opt(j); err != nil {
			return nil, err
		}
	}
	return j, nil
}

func parseExclude(entries []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(entries))
	for _, e := range entries {
		if e == "" {
			return nil, errors.New("the exclude list has an empty entry")
		}
		p, err := parseRange(e)
		if err != nil {
			return nil, fmt.Errorf("the excluded entry %q is not an address or a CIDR range: %w", e, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func (j *job) run(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, j.timeout)
	defer cancel()
	err := j.check(cctx)
	if err != nil && errors.Is(cctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("the run did not finish within %s: %w", j.timeout, err)
	}
	return err
}

func (j *job) check(ctx context.Context) error {
	now := j.now()
	list, err := j.load(ctx)
	if err != nil {
		return err
	}
	ranges, err := j.Ranges(ctx)
	if err != nil {
		return fmt.Errorf("load the ChatGPT and Claude address ranges: %w", err)
	}
	skip, err := j.skipSet(ranges)
	if err != nil {
		return err
	}
	usages, t, err := j.scan(ctx, now.Add(-window), now, skip)
	if err != nil {
		return err
	}
	fresh := j.newlyFlagged(usages, list)
	if len(fresh) > 0 {
		if err := j.sendAlert(ctx, now, fresh, &list); err != nil {
			return err
		}
	}
	local := now.In(j.Location)
	today := local.Format(dateLayout)
	daily := local.Hour() >= j.DailyHour && list.LastDaily != today
	if daily {
		if err := j.Messages.Send(ctx, dailyLine(j.Node, list.since(now.Add(-window)), len(list.Addresses))); err != nil {
			return fmt.Errorf("send the daily line: %w", err)
		}
		list.LastDaily = today
		if err := j.save(ctx, list); err != nil {
			return fmt.Errorf("the daily line was sent but not recorded, so the next run sends it again: %w", err)
		}
	}
	j.Logger.Info("checked the connection logs for busy clients", "node", j.Node, "new_addresses", len(fresh), "daily_line", daily,
		"files", t.files, "connections", t.connections, "addresses", len(usages), "malformed_lines", t.malformed,
		"alerted_on_file", len(list.Addresses))
	return nil
}

func (j *job) skipSet(ranges []netip.Prefix) (*netipx.IPSet, error) {
	var b netipx.IPSetBuilder
	for _, p := range ranges {
		b.AddPrefix(p)
	}
	for _, p := range j.exclude {
		b.AddPrefix(p)
	}
	s, err := b.IPSet()
	if err != nil {
		return nil, fmt.Errorf("build the set of addresses left out: %w", err)
	}
	return s, nil
}

func (j *job) newlyFlagged(usages map[string]*usage, list alertedList) []*usage {
	var out []*usage
	for _, u := range usages {
		if _, done := list.Addresses[u.address]; done {
			continue
		}
		if j.Rule.flags(u) {
			out = append(out, u)
		}
	}
	slices.SortFunc(out, func(a, b *usage) int {
		if c := cmp.Compare(b.connections, a.connections); c != 0 {
			return c
		}
		return strings.Compare(a.address, b.address)
	})
	return out
}

func (j *job) sendAlert(ctx context.Context, now time.Time, fresh []*usage, list *alertedList) error {
	addrs := make([]netip.Addr, len(fresh))
	for i, u := range fresh {
		addrs[i] = u.lookup
	}
	places := j.Locate(ctx, addrs)
	msgs, rows := alert{node: j.Node, now: now.In(j.Location), fresh: fresh, places: places}.
		messages(telegram.Limits{Blocks: telegram.MessageBlocks, Runes: telegram.MessageRunes})
	done := 0
	for i, msg := range msgs {
		if i > 0 {
			if err := j.sleep(ctx, j.pause); err != nil {
				return fmt.Errorf("wait before part %d of %d of the alert: %w", i+1, len(msgs), err)
			}
		}
		if err := j.Messages.Send(ctx, msg); err != nil {
			return fmt.Errorf("send part %d of %d of the alert: %w", i+1, len(msgs), err)
		}
		for _, u := range fresh[done : done+rows[i]] {
			list.Addresses[u.address] = now.UTC()
		}
		done += rows[i]
		if err := j.save(ctx, *list); err != nil {
			return fmt.Errorf("part %d of %d of the alert was sent but its addresses could not be saved, so the next run sends them again: %w", i+1, len(msgs), err)
		}
	}
	j.Logger.Info("sent the busy-clients alert", "node", j.Node, "messages", len(msgs), "new_addresses", len(fresh))
	return nil
}
