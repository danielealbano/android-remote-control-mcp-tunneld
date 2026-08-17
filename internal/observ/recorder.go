// Package observ defines a dependency-free observability interface so the enroll, edge, phoneconn,
// acme and mesh sites can record metrics + cap-hit logs WITHOUT importing the Prometheus/caplog
// implementations. metrics.PromRecorder is the concrete implementation, injected in server.Run.
//
// Plan 3 (E2E) EXTENDS this interface with the E2E event set below while KEEPING the Plan-1 methods
// (their legacy consumers still compile) until the US13 teardown strips them together. New events use
// non-colliding names where a P1 name is still occupied (e.g. EnrollmentResult vs the P1 no-arg
// Enrollment()).
package observ

import "time"

// RejectReasons is the exact tunneld_rejections_total{reason} label set: every rejection writer
// (enroll, edge, phoneconn, acme) uses ONLY these values and US10 registers the family against them.
var RejectReasons = []string{
	"ban", "no-route", "handshake-timeout", "conn-rate", "max-clients", "quota-day", "quota-week",
	"stream-cap", "attest-untrusted", "attest-challenge", "attest-signer", "attest-security-level",
	"attest-boot", "attest-device-unlocked", "attest-revoked", "attest-stale", "csr-mismatch",
	"enroll-limit", "issuance-cap", "acme-failed",
}

// Recorder captures metric + cap-hit events. The concrete PromRecorder updates the
// (per-tunnel-label-free) Prometheus families AND writes the per-tunnel tcnt:{name} Valkey counters
// that back /admin/tunnels.
type Recorder interface {
	// --- Shared with Plan-1 (identical signatures) ---
	// Reject bumps tunneld_rejections_total{reason} (reason ∈ RejectReasons) and emits a deduped
	// cap-hit log. clientIP is a string ("" when no valid IP exists on the path).
	Reject(reason, tunnelName, clientIP string)
	// Bytes bumps tunneld_bytes_total{direction} and tcnt:{name} bytes_in/out. direction is
	// "in"/"out" from the peer's perspective.
	Bytes(tunnelName, direction string, n int64)

	// --- E2E event set (Plan 3) ---
	PublicConnOpen()
	PublicConnClose(reason string)
	PhoneConnOpen()
	PhoneConnClose(reason string)
	StreamOpen()
	StreamClose()
	EnrollmentResult(result string) // "ok" | reason
	AttestVerify(result string)     // "ok" | failure reason
	ACMEIssue(ca, result string)
	ACMERenew(ca, result string)
	QuotaExhausted(tunnelName, window string) // "day" | "week"
	ACMECooldown(ca string)                   // a per-CA cooldown/backoff was set
	MeshPool(peer string, size int)

	// --- Plan-1 methods KEPT until the US13 teardown (legacy consumers still compile). ---
	Request(tunnelName, class string, code int, dur time.Duration)
	WSConnect()
	WSDisconnect(reason string)
	Enrollment()
	InflightAdd(delta int)
	Timeout()
	PublishError()
}

// Nop is a no-op Recorder for unit tests / defaults.
type Nop struct{}

var _ Recorder = Nop{}

func (Nop) Reject(reason, tunnelName, clientIP string)  {}
func (Nop) Bytes(tunnelName, direction string, n int64) {}

func (Nop) PublicConnOpen()                          {}
func (Nop) PublicConnClose(reason string)            {}
func (Nop) PhoneConnOpen()                           {}
func (Nop) PhoneConnClose(reason string)             {}
func (Nop) StreamOpen()                              {}
func (Nop) StreamClose()                             {}
func (Nop) EnrollmentResult(result string)           {}
func (Nop) AttestVerify(result string)               {}
func (Nop) ACMEIssue(ca, result string)              {}
func (Nop) ACMERenew(ca, result string)              {}
func (Nop) QuotaExhausted(tunnelName, window string) {}
func (Nop) ACMECooldown(ca string)                   {}
func (Nop) MeshPool(peer string, size int)           {}

func (Nop) Request(tunnelName, class string, code int, d time.Duration) {}
func (Nop) WSConnect()                                                  {}
func (Nop) WSDisconnect(reason string)                                  {}
func (Nop) Enrollment()                                                 {}
func (Nop) InflightAdd(delta int)                                       {}
func (Nop) Timeout()                                                    {}
func (Nop) PublishError()                                               {}
