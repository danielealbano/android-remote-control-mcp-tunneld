// Package tunneltest provides shared test fakes: the capturing observ.Recorder (here) and the durable
// store fake, reused across the E2E package test suites.
package tunneltest

import (
	"sync"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/observ"
)

// RecCall is one captured Recorder invocation.
type RecCall struct {
	Kind, Reason, Tunnel, IP, Direction string
	N                                   int64
	CA, Result, Window, Peer            string
	Size                                int
}

// Recorder is a thread-safe capturing observ.Recorder for assertions.
type Recorder struct {
	mu    sync.Mutex
	Calls []RecCall
}

var _ observ.Recorder = (*Recorder)(nil)

func (r *Recorder) add(c RecCall) { r.mu.Lock(); r.Calls = append(r.Calls, c); r.mu.Unlock() }

func (r *Recorder) Reject(reason, tunnel, ip string) {
	r.add(RecCall{Kind: "reject", Reason: reason, Tunnel: tunnel, IP: ip})
}

func (r *Recorder) Bytes(tunnel, dir string, n int64) {
	r.add(RecCall{Kind: "bytes", Tunnel: tunnel, Direction: dir, N: n})
}

// --- E2E event set ---

func (r *Recorder) PublicConnOpen() { r.add(RecCall{Kind: "publicconnopen"}) }
func (r *Recorder) PublicConnClose(reason string) {
	r.add(RecCall{Kind: "publicconnclose", Reason: reason})
}
func (r *Recorder) PhoneConnOpen() { r.add(RecCall{Kind: "phoneconnopen"}) }
func (r *Recorder) PhoneConnClose(reason string) {
	r.add(RecCall{Kind: "phoneconnclose", Reason: reason})
}
func (r *Recorder) StreamOpen()  { r.add(RecCall{Kind: "streamopen"}) }
func (r *Recorder) StreamClose() { r.add(RecCall{Kind: "streamclose"}) }
func (r *Recorder) EnrollmentResult(result string) {
	r.add(RecCall{Kind: "enrollmentresult", Result: result})
}
func (r *Recorder) AttestVerify(result string) { r.add(RecCall{Kind: "attestverify", Result: result}) }
func (r *Recorder) ACMEIssue(ca, result string) {
	r.add(RecCall{Kind: "acmeissue", CA: ca, Result: result})
}
func (r *Recorder) ACMERenew(ca, result string) {
	r.add(RecCall{Kind: "acmerenew", CA: ca, Result: result})
}
func (r *Recorder) QuotaExhausted(tunnel, window string) {
	r.add(RecCall{Kind: "quotaexhausted", Tunnel: tunnel, Window: window})
}
func (r *Recorder) ACMECooldown(ca string) { r.add(RecCall{Kind: "acmecooldown", CA: ca}) }
func (r *Recorder) MeshPool(peer string, size int) {
	r.add(RecCall{Kind: "meshpool", Peer: peer, Size: size})
}

// BytesFor sums the bytes recorded for a tunnel in a direction ("in"/"out") across all Bytes calls.
func (r *Recorder) BytesFor(tunnel, dir string) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for _, c := range r.Calls {
		if c.Kind == "bytes" && c.Tunnel == tunnel && c.Direction == dir {
			n += c.N
		}
	}
	return n
}

// Count returns how many captured calls match kind and (optionally) reason ("" matches any reason).
func (r *Recorder) Count(kind, reason string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.Calls {
		if c.Kind == kind && (reason == "" || c.Reason == reason) {
			n++
		}
	}
	return n
}
