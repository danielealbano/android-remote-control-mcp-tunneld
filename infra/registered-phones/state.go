package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/atomicfile"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/bucket"
)

const stateKey = "registered-phones/state.json"

type state struct {
	EnrolledSince string               `json:"enrolled_since"`
	ReadFrom      time.Time            `json:"read_from"`
	Names         map[string]time.Time `json:"names"`
}

func decodeState(body []byte, where string) (state, error) {
	var s state
	if err := json.Unmarshal(body, &s); err != nil {
		return state{}, fmt.Errorf("decode the state %s, so the run stops without changing it: %w", where, err)
	}
	if s.EnrolledSince == "" || s.ReadFrom.IsZero() {
		return state{}, fmt.Errorf("the state %s has no first counted day or no read-from time, so the run stops without changing it", where)
	}
	if s.Names == nil {
		s.Names = map[string]time.Time{}
	}
	return s, nil
}

func (j *job) bucketState(ctx context.Context) (state, bool, error) {
	body, err := j.Store.Get(ctx, stateKey)
	if errors.Is(err, bucket.ErrNotFound) {
		return state{}, false, nil
	}
	if err != nil {
		return state{}, false, fmt.Errorf("read the state from the bucket: %w", err)
	}
	s, err := decodeState(body, "in the bucket at "+stateKey)
	return s, err == nil, err
}

func (j *job) nodeState() (state, bool, error) {
	body, err := os.ReadFile(j.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return state{}, false, nil
	}
	if err != nil {
		return state{}, false, fmt.Errorf("read this node's copy of the state: %w", err)
	}
	s, err := decodeState(body, "on this node at "+j.StateFile)
	return s, err == nil, err
}

func (j *job) loadState(ctx context.Context) (state, error) {
	day := j.EnrolledSince.Format(dateLayout)
	inBucket, okBucket, err := j.bucketState(ctx)
	if err != nil {
		return state{}, err
	}
	onNode, okNode, err := j.nodeState()
	if err != nil {
		return state{}, err
	}
	for _, c := range []struct {
		where string
		s     state
		ok    bool
	}{{"in the bucket", inBucket, okBucket}, {"on this node", onNode, okNode}} {
		if c.ok && c.s.EnrolledSince != day {
			return state{}, fmt.Errorf("the state %s counts from %s but this node is set to count from %s, so the run stops without changing it",
				c.where, c.s.EnrolledSince, day)
		}
	}
	switch {
	case okBucket && okNode:
		return mergeStates(inBucket, onNode), nil
	case okBucket:
		j.Logger.Info("this node has no copy of the state yet, so it starts from the bucket's", "key", stateKey, "state_file", j.StateFile)
		return inBucket, nil
	case okNode:
		j.Logger.Warn("the state is missing from the bucket, so this run starts from this node's copy and a successful run puts it back",
			"key", stateKey, "state_file", j.StateFile, "names", len(onNode.Names))
		return onNode, nil
	default:
		j.Logger.Info("no state is stored yet, so this run starts a new one from the first counted day", "key", stateKey,
			"state_file", j.StateFile, "enrolled_since", day)
		return state{EnrolledSince: day, ReadFrom: j.EnrolledSince.Add(-clockSkew), Names: map[string]time.Time{}}, nil
	}
}

func mergeStates(a, b state) state {
	m := state{EnrolledSince: a.EnrolledSince, ReadFrom: a.ReadFrom, Names: make(map[string]time.Time, len(a.Names))}
	if b.ReadFrom.Before(m.ReadFrom) {
		m.ReadFrom = b.ReadFrom
	}
	for name, at := range a.Names {
		m.Names[name] = at
	}
	for name, at := range b.Names {
		m.Names[name] = at
	}
	return m
}

func (j *job) saveState(ctx context.Context, s state) error {
	body, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("encode the state: %w", err)
	}
	var errs []error
	if err := atomicfile.Write(j.StateFile, body, 0o600); err != nil {
		errs = append(errs, fmt.Errorf("save the state on this node: %w", err))
	}
	if err := j.Store.Put(ctx, stateKey, body); err != nil {
		errs = append(errs, fmt.Errorf("save the state in the bucket: %w", err))
	}
	return errors.Join(errs...)
}
