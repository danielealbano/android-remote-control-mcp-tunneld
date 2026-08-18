// Package acme implements the public-cert issuance chain behind enroll.PublicIssuer: lego-backed
// per-CA clients with automatic LE→GTS→ZeroSSL spillover, DNS-01, the split renewal timing (LE NotAfter−margin floor /
// fixed cadence for GTS+ZeroSSL), and reactive per-CA cooldown+backoff (a rate-limited CA gets a Valkey
// retry-after; the spillover skips a cooling CA). Issue and renew share the same LE-first order, so every
// renewal opportunistically migrates the name to LE. See docs/PROTOCOL.md and the Plan-3 record.
package acme

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// Issuer error classes (the enroll package classifies via IssuerClass()/RetryAfter()).
const (
	ClassRateLimited = "rate-limited"
	ClassTransient   = "transient"
	ClassPermanent   = "permanent"
)

// IssuerError is a classified issuance error. It implements enroll.ClassifiedIssuerError so the enroll
// service can surface {reason, retryable, retry_after} without importing this package's sentinels.
type IssuerError struct {
	Class  string
	Reason string
	Retry  time.Duration
	Err    error
}

func (e *IssuerError) Error() string {
	if e.Err != nil {
		return "acme: " + e.Reason + ": " + e.Err.Error()
	}
	return "acme: " + e.Reason
}
func (e *IssuerError) IssuerClass() string       { return e.Class }
func (e *IssuerError) RetryAfter() time.Duration { return e.Retry }
func (e *IssuerError) Unwrap() error             { return e.Err }

func rateLimited(retry time.Duration, err error) *IssuerError {
	return &IssuerError{Class: ClassRateLimited, Reason: "rate limited", Retry: retry, Err: err}
}
func transient(err error) *IssuerError {
	return &IssuerError{Class: ClassTransient, Reason: "transient", Err: err}
}
func permanent(err error) *IssuerError {
	return &IssuerError{Class: ClassPermanent, Reason: "permanent", Err: err}
}

// caIssuer is one CA's issuance seam (implemented by legoClient; faked in unit tests).
type caIssuer interface {
	// obtain issues a public cert for the phone CSR (name inferred from the CSR CN/SAN the caller sets).
	obtain(ctx context.Context, csr *x509.CertificateRequest, name string) (pem []byte, info store.CertInfo, err error)
	// shouldRenew reports whether cur should renew now, and the suggested time. LE uses the NotAfter−margin floor; GTS/ZeroSSL
	// use the fixed cadence.
	shouldRenew(ctx context.Context, cur store.CertInfo, now time.Time) (bool, time.Time, error)
	id() string
}

// DNSProvider is our neutral wrapper over a lego DNS-01 provider (kept behind our own interface).
type DNSProvider interface {
	Present(ctx context.Context, fqdn, value string) error
	CleanUp(ctx context.Context, fqdn, value string) error
}
