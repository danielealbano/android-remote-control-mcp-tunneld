// Package store is tunneld's FIRST durable server-side state: the name registry and the connection
// logs, on any PLAIN S3 provider. It uses ONLY plain GetObject/PutObject/DeleteObject — no
// conditional-write / atomic-PUT feature — so it runs on any S3 (production targets a plain S3 such as
// OVH; MinIO is a local/e2e stand-in). Name uniqueness comes from the write-verify claim protocol in
// internal/enroll, not from storage semantics. See docs/PROTOCOL.md and docs/ARCHITECTURE.md §5.
package store

import (
	"context"
	"errors"
)

// ErrNotFound is returned by GetName when the name object is absent.
var ErrNotFound = errors.New("store: name not found")

// NameStore is the name-registry surface (consumers: enroll claim/rollback/LWW, phone renewal).
type NameStore interface {
	GetName(ctx context.Context, name string) (NameRecord, error) // ErrNotFound if absent
	// PutName is a plain PUT used both for the write-verify claim and for single-owner LWW updates.
	// Registry writes have SDK auto-retries DISABLED (a claim PUT retried after a timeout is a zombie
	// write); the caller's ctx carries the claim deadline.
	PutName(ctx context.Context, name string, rec NameRecord) error
	// DeleteName is a plain DELETE — rollback of a failed enrollment AFTER a verified claim only.
	DeleteName(ctx context.Context, name string) error
}

// ConnLogStore is the connection-event log surface (consumers: phoneconn, edge bridges).
type ConnLogStore interface {
	PutConnLog(ctx context.Context, ev Event) error // fire-once, immediate
}

// EvidenceStore is the rejected/suspicious-enrollment evidence surface (consumer: enroll).
type EvidenceStore interface {
	PutRejectedEnrollment(ctx context.Context, ev RejectedEnrollment) error
}

// LifecycleStore provisions the object-expiration rules (consumer: server.Run, once at startup).
type LifecycleStore interface {
	// EnsureLifecycles is idempotent: it expires objects under tunnel-logs/ after connLogDays and
	// under rejected-enroll/ after rejectedDays.
	EnsureLifecycles(ctx context.Context, connLogDays, rejectedDays int) error
}

// Store is the full composition implemented by the S3 backend and the tunneltest fake.
type Store interface {
	NameStore
	ConnLogStore
	EvidenceStore
	LifecycleStore
}
