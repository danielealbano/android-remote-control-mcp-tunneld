package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

const (
	listKey        = "refused-apps/attempts.json"
	evidencePrefix = "rejected-enroll/"
)

type objectStore interface {
	List(ctx context.Context, prefix string) ([]string, error)
	Get(ctx context.Context, key string) ([]byte, error)
	Put(ctx context.Context, key string, body []byte) error
}

type messenger interface {
	Send(ctx context.Context, html string) error
}

type revocationLoader func(ctx context.Context) (revocationList, error)

type jobConfig struct {
	Store       objectStore
	Messages    messenger
	Revocations revocationLoader
	Node        string
	Location    *time.Location
	Textfile    string
	HideApps    []string
	Logger      *slog.Logger
}

type job struct {
	jobConfig
	hidden map[string]bool
	now    func() time.Time
	pause  time.Duration
	sleep  func(context.Context, time.Duration) error
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
	case cfg.Revocations == nil:
		return nil, errors.New("the revocation list loader is missing")
	case cfg.Node == "":
		return nil, errors.New("the node name is empty")
	case cfg.Location == nil:
		return nil, errors.New("the time zone is missing")
	case cfg.Textfile == "":
		return nil, errors.New("the dashboard file path is empty")
	case cfg.Logger == nil:
		return nil, errors.New("the logger is missing")
	}
	hidden := make(map[string]bool, len(cfg.HideApps))
	for _, app := range cfg.HideApps {
		if app == "" {
			return nil, errors.New("the list of hidden apps has an empty entry")
		}
		hidden[app] = true
	}
	j := &job{jobConfig: cfg, hidden: hidden, now: time.Now, pause: time.Second, sleep: sleepContext}
	for _, opt := range opts {
		if err := opt(j); err != nil {
			return nil, err
		}
	}
	return j, nil
}

func (j *job) run(ctx context.Context) error {
	today := j.now().In(j.Location)
	day := today.Format(dateLayout)
	list, err := j.load(ctx)
	if err != nil {
		return err
	}
	if list.LastReport == day {
		j.Logger.Info("today's refused-apps report was already sent, so this run does nothing", "node", j.Node, "day", day)
		return nil
	}
	revocations, err := j.Revocations(ctx)
	if err != nil {
		return fmt.Errorf("load the attestation revocation list: %w", err)
	}
	keys, err := j.Store.List(ctx, evidencePrefix)
	if err != nil {
		return fmt.Errorf("list the refusal records: %w", err)
	}
	known := make(map[string]bool, len(list.Apps))
	for app := range list.Apps {
		known[app] = true
	}
	idx := list.index()
	var fresh []newAttempt
	hiddenAttempts := 0
	for _, key := range keys {
		body, err := j.Store.Get(ctx, key)
		if errors.Is(err, errNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read the refusal record %s: %w", key, err)
		}
		var ev store.RejectedEnrollment
		if err := json.Unmarshal(body, &ev); err != nil {
			return fmt.Errorf("decode the refusal record %s: %w", key, err)
		}
		app, a := toAttempt(ev, revocations)
		if !list.add(idx, app, a) {
			continue
		}
		if j.hidden[app] {
			hiddenAttempts++
			continue
		}
		fresh = append(fresh, newAttempt{app: app, a: a})
	}
	msgs, err := report{node: j.Node, today: today, lastReport: list.LastReport, known: known, fresh: fresh}.
		messages(messageLimits{blocks: richMessageBlocks, runes: richMessageRunes})
	if err != nil {
		return err
	}
	if err := j.send(ctx, msgs); err != nil {
		return fmt.Errorf("send the report: %w", err)
	}
	list.LastReport = day
	body, err := json.Marshal(list)
	if err != nil {
		return fmt.Errorf("encode the attempt list: %w", err)
	}
	if err := j.Store.Put(ctx, listKey, body); err != nil {
		return fmt.Errorf("the report was sent but the attempt list could not be saved, so the next run sends these attempts again: %w", err)
	}
	if err := writeTextfile(j.Textfile, list.without(j.hidden)); err != nil {
		return fmt.Errorf("write the dashboard file: %w", err)
	}
	j.Logger.Info("sent the refused-apps report", "node", j.Node, "day", day, "messages", len(msgs), "new_attempts", len(fresh), "hidden_attempts", hiddenAttempts, "attempts_on_file", list.count())
	return nil
}

func (j *job) load(ctx context.Context) (attemptList, error) {
	body, err := j.Store.Get(ctx, listKey)
	if errors.Is(err, errNotFound) {
		j.Logger.Info("no attempt list is stored yet, so this run starts a new one", "node", j.Node, "key", listKey)
		return attemptList{Apps: map[string][]attempt{}}, nil
	}
	if err != nil {
		return attemptList{}, fmt.Errorf("read the attempt list: %w", err)
	}
	var list attemptList
	if err := json.Unmarshal(body, &list); err != nil {
		return attemptList{}, fmt.Errorf("decode the attempt list %s: %w", listKey, err)
	}
	if list.Apps == nil {
		list.Apps = map[string][]attempt{}
	}
	return list, nil
}

func (j *job) send(ctx context.Context, msgs []string) error {
	for i, msg := range msgs {
		if i > 0 {
			if err := j.sleep(ctx, j.pause); err != nil {
				return err
			}
		}
		if err := j.Messages.Send(ctx, msg); err != nil {
			return fmt.Errorf("message %d of %d: %w", i+1, len(msgs), err)
		}
	}
	return nil
}
