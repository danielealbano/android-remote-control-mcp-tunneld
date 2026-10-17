package tunneltest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sync"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// Store is a thread-safe in-memory store.Store fake for assertions. The exported hook fields let the
// race tests inject interleavings: a claim PUT that "times out" client-side but lands
// later (zombie), etc.
type Store struct {
	mu       sync.Mutex
	names    map[string]store.NameRecord
	ConnLogs []store.Event
	Rejected []store.RejectedEnrollment

	// FailNextPut, when non-nil, is returned by the next PutName call WITHOUT writing (a clean PUT
	// failure). ZombieNextPut simulates a timed-out-but-landed PUT: the record IS written, the error
	// IS returned. RejectedErr, when non-nil, fails every
	// PutRejectedEnrollment (evidence-store outage).
	FailNextPut   error
	ZombieNextPut error
	RejectedErr   error
}

// NewStore builds an empty fake.
func NewStore() *Store { return &Store{names: map[string]store.NameRecord{}} }

var _ store.Store = (*Store)(nil)

// GetName returns the record or store.ErrNotFound.
func (s *Store) GetName(_ context.Context, name string) (store.NameRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.names[name]
	if !ok {
		return store.NameRecord{}, store.ErrNotFound
	}
	return rec, nil
}

// PutName stores the record (honoring the FailNextPut / ZombieNextPut hooks).
func (s *Store) PutName(_ context.Context, name string, rec store.NameRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.FailNextPut; err != nil {
		s.FailNextPut = nil
		return err
	}
	if err := s.ZombieNextPut; err != nil {
		s.ZombieNextPut = nil
		s.names[name] = rec // landed server-side despite the client-side error
		return err
	}
	s.names[name] = rec
	return nil
}

// DeleteName removes the record (idempotent).
func (s *Store) DeleteName(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.names, name)
	return nil
}

func (s *Store) PutConnLogFile(_ context.Context, _ string, body io.ReadSeeker, _ int64) error {
	raw, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	var evs []store.Event
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var ev store.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return err
		}
		evs = append(evs, ev)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ConnLogs = append(s.ConnLogs, evs...)
	return nil
}

// PutConnLog captures a connection-log event.
func (s *Store) PutConnLog(_ context.Context, ev store.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ConnLogs = append(s.ConnLogs, ev)
	return nil
}

// PutRejectedEnrollment captures rejected-enrollment evidence (honoring the RejectedErr hook).
func (s *Store) PutRejectedEnrollment(_ context.Context, ev store.RejectedEnrollment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.RejectedErr != nil {
		return s.RejectedErr
	}
	s.Rejected = append(s.Rejected, ev)
	return nil
}

// NameCount reports how many name records exist (rollback assertions).
func (s *Store) NameCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.names)
}
