package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/bucket"
)

const stateKey = "busy-clients/alerted.json"

type alertedList struct {
	Addresses map[string]time.Time `json:"addresses"`
	LastDaily string               `json:"last_daily,omitempty"`
}

func (j *job) load(ctx context.Context) (alertedList, error) {
	body, err := j.Store.Get(ctx, stateKey)
	if errors.Is(err, bucket.ErrNotFound) {
		j.Logger.Info("no list of alerted addresses is stored yet, so this run starts a new one", "node", j.Node, "key", stateKey)
		return alertedList{Addresses: map[string]time.Time{}}, nil
	}
	if err != nil {
		return alertedList{}, fmt.Errorf("read the list of alerted addresses: %w", err)
	}
	var list alertedList
	if err := json.Unmarshal(body, &list); err != nil {
		return alertedList{}, fmt.Errorf("decode the list of alerted addresses %s: %w", stateKey, err)
	}
	if list.Addresses == nil {
		list.Addresses = map[string]time.Time{}
	}
	return list, nil
}

func (j *job) save(ctx context.Context, list alertedList) error {
	body, err := json.Marshal(list)
	if err != nil {
		return fmt.Errorf("encode the list of alerted addresses: %w", err)
	}
	return j.Store.Put(ctx, stateKey, body)
}

func (l alertedList) since(t time.Time) int {
	n := 0
	for _, at := range l.Addresses {
		if at.After(t) {
			n++
		}
	}
	return n
}
