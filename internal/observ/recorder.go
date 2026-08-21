// Package observ defines a dependency-free observability interface so the enroll, edge, phoneconn,
// acme and mesh sites can record metrics + cap-hit logs WITHOUT importing the Prometheus/caplog
// implementations. metrics.PromRecorder is the concrete implementation, injected in server.Run.
package observ

// RejectReasons is the exact tunneld_rejections_total{reason} label set: every rejection writer
// (enroll, edge, phoneconn, acme) uses ONLY these values; the metrics registration pre-registers the
// family against this exact set (docs/ARCHITECTURE.md §8).
var RejectReasons = []string{
	"ban", "no-route", "handshake-timeout", "conn-rate", "max-clients", "quota-day", "quota-week",
	"stream-cap", "attest-untrusted", "attest-challenge", "attest-signer", "attest-security-level",
	"attest-boot", "attest-device-unlocked", "attest-revoked", "attest-stale", "csr-mismatch",
	"enroll-limit", "issuance-cap", "acme-failed",
}

// Recorder captures metric + cap-hit events. The concrete PromRecorder updates the
// (per-tunnel-label-free) Prometheus families AND writes the per-tunnel byte counters in tunnel:{name}
// that back /api/v1/admin/tunnels/stats.
type Recorder interface {
	// --- Core rejection/byte events ---
	// Reject bumps tunneld_rejections_total{reason} (reason ∈ RejectReasons) and emits a deduped
	// cap-hit log. clientIP is a string ("" when no valid IP exists on the path).
	Reject(reason, tunnelName, clientIP string)
	// Bytes bumps tunneld_bytes_total{direction} and tunnel:{name} bytes_in/out. direction is
	// "in"/"out" from the peer's perspective.
	Bytes(tunnelName, direction string, n int64)

	// --- E2E event set ---
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
