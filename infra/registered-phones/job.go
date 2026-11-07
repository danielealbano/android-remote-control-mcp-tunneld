package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/bucket"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/report"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

const (
	namesPrefix    = "names/"
	parallelReads  = 16
	clockSkew      = time.Hour
	defaultTimeout = 100 * time.Second
)

type objectStore interface {
	ListObjects(ctx context.Context, prefix string) ([]bucket.Object, error)
	Get(ctx context.Context, key string) ([]byte, error)
}

type jobConfig struct {
	Store         objectStore
	EnrolledSince time.Time
	Textfile      string
	Logger        *slog.Logger
}

type job struct {
	jobConfig
	now     func() time.Time
	timeout time.Duration
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

type tally struct {
	registered, listed, read int
}

func newJob(cfg jobConfig, opts ...jobOption) (*job, error) {
	switch {
	case cfg.Store == nil:
		return nil, errors.New("the object store is missing")
	case cfg.EnrolledSince.IsZero():
		return nil, errors.New("the first counted day is missing")
	case cfg.Textfile == "":
		return nil, errors.New("the dashboard file path is empty")
	case cfg.Logger == nil:
		return nil, errors.New("the logger is missing")
	}
	j := &job{jobConfig: cfg, now: time.Now, timeout: defaultTimeout}
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
	t, err := j.count(cctx)
	if err != nil {
		if errors.Is(cctx.Err(), context.DeadlineExceeded) {
			err = fmt.Errorf("the count did not finish within %s: %w", j.timeout, err)
		}
		return removeTextfile(j.Textfile, err)
	}
	if err := writeTextfile(j.Textfile, t.registered, j.now()); err != nil {
		return removeTextfile(j.Textfile, fmt.Errorf("write the dashboard file: %w", err))
	}
	j.Logger.Info("counted the registered phones for the dashboard", "registered", t.registered, "names_listed", t.listed,
		"names_read", t.read, "enrolled_since", j.EnrolledSince.Format(dateLayout), "textfile", j.Textfile)
	return nil
}

func (j *job) count(ctx context.Context) (tally, error) {
	objs, err := j.Store.ListObjects(ctx, namesPrefix)
	if err != nil {
		return tally{}, fmt.Errorf("list the name registry: %w", err)
	}
	oldest := j.EnrolledSince.Add(-clockSkew)
	var n atomic.Int64
	read := 0
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(parallelReads)
	for _, o := range objs {
		if !o.LastModified.IsZero() && o.LastModified.Before(oldest) {
			continue
		}
		read++
		g.Go(func() (err error) {
			rctx := report.WithScope(gctx)
			report.SetAttrs(rctx, slog.String("key", o.Key))
			defer report.Recover(rctx, j.Logger, "reading a name record", func() {
				err = fmt.Errorf("reading the name record %s crashed", o.Key)
			})
			ok, err := j.counts(rctx, o.Key)
			if ok {
				n.Add(1)
			}
			return err
		})
	}
	if err := g.Wait(); err != nil {
		return tally{}, err
	}
	return tally{registered: int(n.Load()), listed: len(objs), read: read}, nil
}

func (j *job) counts(ctx context.Context, key string) (bool, error) {
	body, err := j.Store.Get(ctx, key)
	if errors.Is(err, bucket.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read the name record %s: %w", key, err)
	}
	var rec store.NameRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return false, fmt.Errorf("decode the name record %s: %w", key, err)
	}
	return rec.CA != "" && !rec.EnrolledAt.Before(j.EnrolledSince), nil
}
