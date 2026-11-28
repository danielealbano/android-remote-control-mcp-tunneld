package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/atomicfile"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/bucket"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/report"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

const crashedMsg = "reading a list of phones seen crashed, so this run stops and neither the cache nor the dashboard file is updated"

const (
	listSchema     = 1
	parallelReads  = 16
	defaultTimeout = 100 * time.Second
	day            = 24 * time.Hour
)

var windows = []struct {
	label string
	span  time.Duration
}{
	{"24h", day},
	{"7d", 7 * day},
	{"30d", 30 * day},
}

var listKey = regexp.MustCompile(`^` + regexp.QuoteMeta(store.PhonesSeenPrefix) + `(\d{4}/\d{2}/\d{2})/[0-9a-f]+\.json$`)

type objectStore interface {
	ListObjects(ctx context.Context, prefix string) ([]bucket.Object, error)
	Get(ctx context.Context, key string) ([]byte, error)
}

type jobConfig struct {
	Store     objectStore
	CacheFile string
	Textfile  string
	Logger    *slog.Logger
}

type job struct {
	jobConfig
	now     func() time.Time
	timeout time.Duration
	write   fileWriter
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

func withWriter(write fileWriter) jobOption {
	return func(j *job) error {
		if write == nil {
			return errors.New("the file writer is missing")
		}
		j.write = write
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

func newJob(cfg jobConfig, opts ...jobOption) (*job, error) {
	switch {
	case cfg.Store == nil:
		return nil, errors.New("the object store is missing")
	case cfg.CacheFile == "":
		return nil, errors.New("the cache file path is empty")
	case cfg.Textfile == "":
		return nil, errors.New("the dashboard file path is empty")
	case cfg.Logger == nil:
		return nil, errors.New("the logger is missing")
	}
	j := &job{jobConfig: cfg, now: time.Now, timeout: defaultTimeout, write: atomicfile.Write}
	for _, opt := range opts {
		if err := opt(j); err != nil {
			return nil, err
		}
	}
	return j, nil
}

func (j *job) run(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, j.timeout)
	defer cancel()
	err := j.update(cctx)
	if err != nil && errors.Is(cctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("the run did not finish within %s: %w", j.timeout, err)
	}
	return err
}

type tally struct {
	listed, read, skipped int
}

func (j *job) update(ctx context.Context) error {
	now := j.now().UTC()
	c := j.loadCache()
	next, t, err := j.refresh(ctx, c, now)
	if err != nil {
		return err
	}
	n := count(next, now)
	if err := j.saveCache(next); err != nil {
		if errors.Is(err, atomicfile.ErrNotFlushed) {
			j.Logger.Warn("saved this node's cache but could not flush it to disk, so a crash could lose it and the next run would then read the lists again", "cache_file", j.CacheFile, "err", err)
		} else {
			j.Logger.Warn("could not save this node's cache, so the next run reads the lists again", "cache_file", j.CacheFile, "err", err)
		}
	}
	if err := writeTextfile(j.write, j.Textfile, n, j.now()); err != nil {
		if !errors.Is(err, atomicfile.ErrNotFlushed) {
			return fmt.Errorf("write the dashboard file: %w", err)
		}
		j.Logger.Warn("wrote this node's dashboard file but could not flush it to disk, so a crash could lose it until the next run", "textfile", j.Textfile, "err", err)
	}
	j.Logger.Info("counted the active users for the dashboard", "dau", n.active["24h"], "wau", n.active["7d"], "mau", n.active["30d"],
		"rdau", n.recurring["24h"], "rwau", n.recurring["7d"], "rmau", n.recurring["30d"],
		"lists_listed", t.listed, "lists_read", t.read, "lists_skipped", t.skipped, "textfile", j.Textfile)
	return nil
}

func (j *job) refresh(ctx context.Context, c cache, now time.Time) (cache, tally, error) {
	objs, err := j.Store.ListObjects(ctx, store.PhonesSeenPrefix)
	if err != nil {
		return cache{}, tally{}, fmt.Errorf("list the lists of phones seen: %w", err)
	}
	oldest := now.Truncate(day).Add(-2 * windows[len(windows)-1].span)
	next := cache{Schema: cacheSchema, Lists: map[string]cachedList{}}
	var (
		toRead []bucket.Object
		t      = tally{listed: len(objs)}
	)
	for _, o := range objs {
		m := listKey.FindStringSubmatch(o.Key)
		if m == nil {
			j.Logger.Warn("found an object that is not a list of phones seen under the lists' folder, so it is not counted", "key", o.Key)
			t.skipped++
			continue
		}
		listDay, err := time.Parse("2006/01/02", m[1])
		if err != nil {
			j.Logger.Warn("found a list of phones seen whose folder is not a real day, so it is not counted", "key", o.Key, "err", err)
			t.skipped++
			continue
		}
		if listDay.Before(oldest) {
			continue
		}
		if cached, ok := c.Lists[o.Key]; ok && o.ETag != "" && cached.ETag == o.ETag {
			next.Lists[o.Key] = cached
			continue
		}
		toRead = append(toRead, o)
	}
	var (
		mu   sync.Mutex
		errs []error
		g    errgroup.Group
	)
	g.SetLimit(parallelReads)
	for _, o := range toRead {
		g.Go(func() (err error) {
			defer func() {
				if err != nil && (ctx.Err() == nil || !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)) {
					mu.Lock()
					errs = append(errs, err)
					mu.Unlock()
				}
			}()
			rctx := report.WithScope(ctx)
			report.SetAttrs(rctx, slog.String("key", o.Key))
			defer report.RecoverWith(rctx, j.Logger, "reading a list of phones seen", crashedMsg, func() {
				err = fmt.Errorf("reading the list of phones seen %s crashed", o.Key)
			})
			list, ok, err := j.read(rctx, o)
			mu.Lock()
			defer mu.Unlock()
			if ok {
				next.Lists[o.Key] = list
				t.read++
			} else if err == nil {
				t.skipped++
			}
			return err
		})
	}
	if err := g.Wait(); err != nil {
		mu.Lock()
		defer mu.Unlock()
		if len(errs) == 0 {
			return cache{}, tally{}, err
		}
		return cache{}, tally{}, errors.Join(errs...)
	}
	return next, t, nil
}

func (j *job) read(ctx context.Context, o bucket.Object) (cachedList, bool, error) {
	body, err := j.Store.Get(ctx, o.Key)
	if errors.Is(err, bucket.ErrNotFound) {
		j.Logger.Info("a list of phones seen was removed between listing and reading it, so it is not counted", "key", o.Key)
		return cachedList{}, false, nil
	}
	if err != nil {
		return cachedList{}, false, fmt.Errorf("read the list of phones seen %s: %w", o.Key, err)
	}
	var f store.PhonesSeenFile
	if err := json.Unmarshal(body, &f); err != nil {
		j.Logger.Warn("could not decode a list of phones seen, so it is not counted; it is read again on the next run", "key", o.Key, "err", err)
		return cachedList{}, false, nil
	}
	if f.Schema != listSchema {
		j.Logger.Warn("found a list of phones seen in another format, so it is not counted; it is read again on the next run", "key", o.Key, "schema", f.Schema)
		return cachedList{}, false, nil
	}
	for name, s := range f.Phones {
		if s.First.IsZero() || s.Last.Before(s.First) {
			j.Logger.Warn("found a list of phones seen with a phone whose first or last time is missing or out of order, so the list is not counted; it is read again on the next run", "key", o.Key, "phone", name)
			return cachedList{}, false, nil
		}
	}
	return cachedList{ETag: o.ETag, Phones: f.Phones}, true, nil
}

type counts struct {
	active, recurring map[string]int
}

func count(c cache, now time.Time) counts {
	seen := map[string][]store.PhoneSeen{}
	for _, list := range c.Lists {
		for name, s := range list.Phones {
			seen[name] = append(seen[name], s)
		}
	}
	n := counts{active: make(map[string]int, len(windows)), recurring: make(map[string]int, len(windows))}
	for _, w := range windows {
		from, before := now.Add(-w.span), now.Add(-2*w.span)
		for _, spans := range seen {
			if !slices.ContainsFunc(spans, func(s store.PhoneSeen) bool { return s.Last.After(from) }) {
				continue
			}
			n.active[w.label]++
			if slices.ContainsFunc(spans, func(s store.PhoneSeen) bool { return s.Last.After(before) && !s.First.After(from) }) {
				n.recurring[w.label]++
			}
		}
	}
	return n
}
