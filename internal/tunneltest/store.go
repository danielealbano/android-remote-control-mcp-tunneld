package tunneltest

import (
	"context"
	"sync"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// Store is a thread-safe in-memory store.Store fake for assertions. The exported hook fields let the
// write-verify race tests inject interleavings: a claim PUT that "times out" client-side but lands
// later (zombie), a competing claimant writing between another's PUT and verify, etc.
type Store struct {
	mu       sync.Mutex
	names    map[string]store.NameRecord
	ConnLogs []store.Event
	Rejected []store.RejectedEnrollment

	// FailNextPut, when non-nil, is returned by the next PutName call WITHOUT writing (a clean PUT
	// failure). ZombieNextPut simulates a timed-out-but-landed PUT: the record IS written, the error
	// IS returned. BeforeVerifyGet runs before each GetName so a test can land a competing/zombie
	// write between a claimant's PUT and its verify. RejectedErr, when non-nil, fails every
	// PutRejectedEnrollment (evidence-store outage).
	FailNextPut     error
	ZombieNextPut   error
	BeforeVerifyGet func(name string)
	RejectedErr     error
}

// NewStore builds an empty fake.
func NewStore() *Store { return &Store{names: map[string]store.NameRecord{}} }

var _ store.Store = (*Store)(nil)

// GetName returns the record or store.ErrNotFound.
func (s *Store) GetName(_ context.Context, name string) (store.NameRecord, error) {
	if s.BeforeVerifyGet != nil {
		s.BeforeVerifyGet(name)
	}
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

// EnsureLifecycles is a no-op in the fake (real semantics are covered by the US14 MinIO tests).
func (s *Store) EnsureLifecycles(_ context.Context, _, _ int) error { return nil }
