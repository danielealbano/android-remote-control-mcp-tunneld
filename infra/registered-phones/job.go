package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/atomicfile"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/bucket"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/report"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

const crashedMsg = "reading a name record crashed, so this run stops and neither the state nor the dashboard file is updated"

const (
	namesPrefix    = "names/"
	parallelReads  = 16
	clockSkew      = time.Hour
	defaultTimeout = 100 * time.Second
)

type objectStore interface {
	ListObjects(ctx context.Context, prefix string) ([]bucket.Object, error)
	Get(ctx context.Context, key string) ([]byte, error)
	Put(ctx context.Context, key string, body []byte) error
}

type jobConfig struct {
	Store         objectStore
	EnrolledSince time.Time
	StateFile     string
	Textfile      string
	Logger        *slog.Logger
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

type tally struct {
	listed, read, added int
}

func newJob(cfg jobConfig, opts ...jobOption) (*job, error) {
	switch {
	case cfg.Store == nil:
		return nil, errors.New("the object store is missing")
	case cfg.EnrolledSince.IsZero():
		return nil, errors.New("the first counted day is missing")
	case cfg.StateFile == "":
		return nil, errors.New("the state file path is empty")
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

func (j *job) update(ctx context.Context) error {
	start := j.now()
	s, err := j.loadState(ctx)
	if err != nil {
		return err
	}
	t, err := j.count(ctx, &s)
	if err != nil {
		return err
	}
	s.ReadFrom = start.Add(-clockSkew)
	if err := j.saveState(ctx, s); err != nil {
		return err
	}
	if err := writeTextfile(j.write, j.Textfile, len(s.Names), j.now()); err != nil {
		if !errors.Is(err, atomicfile.ErrNotFlushed) {
			return fmt.Errorf("write the dashboard file: %w", err)
		}
		j.Logger.Warn("wrote this node's dashboard file but could not flush it to disk, so a crash could lose it until the next run", "textfile", j.Textfile, "err", err)
	}
	j.Logger.Info("counted the registered phones for the dashboard", "registered", len(s.Names), "new", t.added,
		"names_listed", t.listed, "names_read", t.read, "enrolled_since", s.EnrolledSince, "read_from", s.ReadFrom, "textfile", j.Textfile)
	return nil
}

func (j *job) count(ctx context.Context, s *state) (tally, error) {
	objs, err := j.Store.ListObjects(ctx, namesPrefix)
	if err != nil {
		return tally{}, fmt.Errorf("list the name registry: %w", err)
	}
	var (
		mu    sync.Mutex
		found = map[string]time.Time{}
		errs  []error
	)
	read := 0
	var g errgroup.Group
	g.SetLimit(parallelReads)
	for _, o := range objs {
		name := strings.TrimPrefix(o.Key, namesPrefix)
		if name == "" {
			continue
		}
		if _, counted := s.Names[name]; counted {
			continue
		}
		if !o.LastModified.IsZero() && o.LastModified.Before(s.ReadFrom) {
			continue
		}
		read++
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
			defer report.RecoverWith(rctx, j.Logger, "reading a name record", crashedMsg, func() {
				err = fmt.Errorf("reading the name record %s crashed", o.Key)
			})
			enrolled, ok, err := j.counts(rctx, o.Key)
			if ok {
				mu.Lock()
				found[name] = enrolled
				mu.Unlock()
			}
			return err
		})
	}
	if err := g.Wait(); err != nil {
		mu.Lock()
		defer mu.Unlock()
		if len(errs) == 0 {
			return tally{}, err
		}
		return tally{}, errors.Join(errs...)
	}
	for name, enrolled := range found {
		s.Names[name] = enrolled
	}
	return tally{listed: len(objs), read: read, added: len(found)}, nil
}

func (j *job) counts(ctx context.Context, key string) (time.Time, bool, error) {
	body, err := j.Store.Get(ctx, key)
	if errors.Is(err, bucket.ErrNotFound) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("read the name record %s: %w", key, err)
	}
	var rec store.NameRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return time.Time{}, false, fmt.Errorf("decode the name record %s: %w", key, err)
	}
	return rec.EnrolledAt, rec.CA != "" && !rec.EnrolledAt.Before(j.EnrolledSince), nil
}
