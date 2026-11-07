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
	namesPrefix   = "names/"
	parallelReads = 16
)

type objectStore interface {
	List(ctx context.Context, prefix string) ([]string, error)
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
}

func newJob(cfg jobConfig) (*job, error) {
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
	return &job{jobConfig: cfg}, nil
}

func (j *job) run(ctx context.Context) error {
	registered, names, err := j.count(ctx)
	if err != nil {
		return removeTextfile(j.Textfile, err)
	}
	if err := writeTextfile(j.Textfile, registered); err != nil {
		return removeTextfile(j.Textfile, fmt.Errorf("write the dashboard file: %w", err))
	}
	j.Logger.Info("counted the registered phones for the dashboard", "registered", registered, "names_read", names,
		"enrolled_since", j.EnrolledSince.Format(dateLayout), "textfile", j.Textfile)
	return nil
}

func (j *job) count(ctx context.Context) (registered, names int, err error) {
	keys, err := j.Store.List(ctx, namesPrefix)
	if err != nil {
		return 0, 0, fmt.Errorf("list the name registry: %w", err)
	}
	var n atomic.Int64
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(parallelReads)
	for _, key := range keys {
		g.Go(func() (err error) {
			defer report.Recover(gctx, j.Logger, "reading a name record", func() {
				err = fmt.Errorf("reading the name record %s crashed", key)
			})
			ok, err := j.counts(gctx, key)
			if ok {
				n.Add(1)
			}
			return err
		})
	}
	if err := g.Wait(); err != nil {
		return 0, 0, err
	}
	return int(n.Load()), len(keys), nil
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
