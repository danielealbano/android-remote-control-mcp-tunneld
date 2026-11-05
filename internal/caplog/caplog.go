// Package caplog is the deduplicated cap-hit event logger: the first hit per (tunnel, reason) in a
// window is logged immediately; further hits accumulate and are summarized at most once per window.
// No per-key tickers/goroutines — flushing is lazy (on a later hit past the window, on idle-key
// eviction, or via Flush) so there is no ticker lifecycle to leak.
package caplog

import (
	"log/slog"
	"strconv"
	"sync"
	"time"
)

type phrasing struct {
	first, repeated string
	level           slog.Level
}

var phrasings = map[string]phrasing{
	"handshake-timeout": {"refused a connection: the client did not send a valid TLS greeting in time",
		"refused connections repeatedly within one minute: the clients did not send a valid TLS greeting in time", slog.LevelInfo},
	"ban": {"refused a connection from a banned address",
		"refused connections from banned addresses repeatedly within one minute", slog.LevelInfo},
	"ban-tunnel": {"refused a phone connection: the tunnel name is banned",
		"refused phone connections repeatedly within one minute: the tunnel name is banned", slog.LevelInfo},
	"conn-rate": {"refused a connection: too many new connections from this address",
		"refused connections repeatedly within one minute: too many new connections from the same addresses", slog.LevelInfo},
	"acme-http-miss": {"answered a request on the plain HTTP port that matched no certificate validation",
		"answered requests on the plain HTTP port repeatedly within one minute that matched no certificate validation", slog.LevelInfo},
	"max-clients": {"refused a connection: this node is at its connection limit",
		"refused connections repeatedly within one minute: this node is at its connection limit", slog.LevelWarn},
	"quota-day": {"refused or ended a tunnel connection: the tunnel has used up its daily traffic",
		"refused or ended tunnel connections repeatedly within one minute: the tunnel has used up its daily traffic", slog.LevelWarn},
	"quota-week": {"refused or ended a tunnel connection: the tunnel has used up its weekly traffic",
		"refused or ended tunnel connections repeatedly within one minute: the tunnel has used up its weekly traffic", slog.LevelWarn},
	"stream-cap": {"refused a connection: the tunnel already has its maximum number of open connections",
		"refused connections repeatedly within one minute: the tunnel already has its maximum number of open connections", slog.LevelWarn},
	"attest-untrusted": {"refused a device attestation: it is missing or unreadable, or its certificate chain could not be verified against the loaded Google attestation roots",
		"refused device attestations repeatedly within one minute: they are missing or unreadable, or their certificate chains could not be verified against the loaded Google attestation roots", slog.LevelWarn},
	"attest-challenge": {"refused a device attestation: it does not contain the server's one-time code",
		"refused device attestations repeatedly within one minute: they do not contain the server's one-time code", slog.LevelWarn},
	"attest-signer": {"refused a device attestation: the app is not signed with an allowed key",
		"refused device attestations repeatedly within one minute: the app is not signed with an allowed key", slog.LevelWarn},
	"attest-security-level": {"refused a device attestation: the device key is not kept in secure hardware",
		"refused device attestations repeatedly within one minute: the device key is not kept in secure hardware", slog.LevelWarn},
	"attest-boot": {"refused a device attestation: the device did not prove that it started in verified boot mode",
		"refused device attestations repeatedly within one minute: the device did not prove that it started in verified boot mode", slog.LevelWarn},
	"attest-device-unlocked": {"refused a device attestation: the device's bootloader is unlocked",
		"refused device attestations repeatedly within one minute: the device's bootloader is unlocked", slog.LevelWarn},
	"attest-revoked": {"refused a device attestation: a certificate in the device's attestation chain is revoked or suspended",
		"refused device attestations repeatedly within one minute: a certificate in the device's attestation chain is revoked or suspended", slog.LevelWarn},
	"attest-stale": {"refused a device attestation: the attestation revocation list is too old or was never fetched, so the device cannot be checked",
		"refused device attestations repeatedly within one minute: the attestation revocation list is too old or was never fetched, so the devices cannot be checked", slog.LevelWarn},
	"csr-mismatch": {"refused a certificate request: it is badly signed, uses an unsupported key or not the attested key, or does not ask for exactly the tunnel's name",
		"refused certificate requests repeatedly within one minute: they are badly signed, use an unsupported key or not the attested key, or do not ask for exactly the tunnel's name", slog.LevelWarn},
	"csr-mismatch-enroll": {"refused an enrollment: its certificate signing request is badly signed or does not use the attested key",
		"refused enrollments repeatedly within one minute: their certificate signing requests are badly signed or do not use the attested key", slog.LevelWarn},
	"enroll-limit": {"refused an enrollment: too many enrollments from this address",
		"refused enrollments repeatedly within one minute: too many enrollments from the same addresses", slog.LevelWarn},
	"issuance-cap": {"refused a certificate request: the tunnel reached its weekly certificate limit or another request for it is still running",
		"refused certificate requests repeatedly within one minute: the tunnel reached its weekly certificate limit or another request for it is still running", slog.LevelWarn},
	"acme-failed": {"refused a certificate request: no certificate authority issued the certificate",
		"refused certificate requests repeatedly within one minute: no certificate authority issued the certificate", slog.LevelWarn},
}

func describe(tunnel, reason string) phrasing {
	switch {
	case reason == "ban" && tunnel != "":
		reason = "ban-tunnel"
	case reason == "csr-mismatch" && tunnel == "":
		reason = "csr-mismatch-enroll"
	}
	if p, ok := phrasings[reason]; ok {
		return p
	}
	return phrasing{"refused a request: " + reason, "refused requests repeatedly within one minute: " + reason, slog.LevelWarn}
}

func (l *Logger) logAt(level slog.Level, msg string, attrs ...any) {
	if level == slog.LevelInfo {
		l.log.Info(msg, attrs...)
		return
	}
	l.log.Warn(msg, attrs...)
}

// maxTrackedIPs bounds the distinct-IP set per (tunnel, reason) key within a window, so a distributed
// flood of many source IPs cannot grow this map without limit. Past the cap the count is reported with
// a "+" suffix.
const maxTrackedIPs = 1024

// Logger is the deduping cap-hit logger.
type Logger struct {
	mu     sync.Mutex
	states map[string]*state
	window time.Duration
	log    *slog.Logger
	now    func() time.Time
}

type state struct {
	count       int
	ips         map[string]struct{}
	ipsCapped   bool
	windowStart time.Time
}

// New builds a Logger with a 1-minute window.
func New(log *slog.Logger) *Logger {
	return newLogger(log, time.Minute, time.Now)
}

func newLogger(log *slog.Logger, window time.Duration, now func() time.Time) *Logger {
	return &Logger{states: map[string]*state{}, window: window, log: log, now: now}
}

// Hit records one cap hit. The first hit of each window logs immediately; subsequent hits
// accumulate; a summary is emitted at the window boundary (on the next hit past the window or when
// an idle key is swept).
func (l *Logger) Hit(tunnel, reason, clientIP string, fields ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	key := tunnel + "|" + reason

	st := l.states[key]
	switch {
	case st == nil:
		l.logImmediate(tunnel, reason, clientIP, fields)
		l.states[key] = newState(now, clientIP)
	case now.Sub(st.windowStart) >= l.window:
		l.emitSummary(tunnel, reason, st)
		l.logImmediate(tunnel, reason, clientIP, fields)
		*st = *newState(now, clientIP)
	default:
		st.count++
		if clientIP != "" {
			if len(st.ips) < maxTrackedIPs {
				st.ips[clientIP] = struct{}{}
			} else {
				st.ipsCapped = true
			}
		}
	}
	l.sweep(now, key)
}

// Flush emits any pending summaries (e.g. at shutdown) and clears the map.
func (l *Logger) Flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, st := range l.states {
		tunnel, reason := splitKey(key)
		l.emitSummary(tunnel, reason, st)
		delete(l.states, key)
	}
}

func (l *Logger) sweep(now time.Time, except string) {
	for key, st := range l.states {
		if key == except {
			continue
		}
		if now.Sub(st.windowStart) >= l.window {
			tunnel, reason := splitKey(key)
			l.emitSummary(tunnel, reason, st)
			delete(l.states, key)
		}
	}
}

func (l *Logger) logImmediate(tunnel, reason, clientIP string, fields []any) {
	attrs := append([]any{"tunnel", tunnel, "reason", reason, "client_ip", clientIP}, fields...)
	p := describe(tunnel, reason)
	l.logAt(p.level, p.first, attrs...)
}

func (l *Logger) emitSummary(tunnel, reason string, st *state) {
	if st.count <= 1 {
		return // only the immediately-logged first hit; nothing to summarize
	}
	ips := strconv.Itoa(len(st.ips))
	if st.ipsCapped {
		ips += "+"
	}
	p := describe(tunnel, reason)
	l.logAt(p.level, p.repeated,
		"tunnel", tunnel, "reason", reason,
		"count", st.count, "ips", ips,
		"window", l.window.String())
}

func newState(now time.Time, clientIP string) *state {
	s := &state{count: 1, ips: map[string]struct{}{}, windowStart: now}
	if clientIP != "" {
		s.ips[clientIP] = struct{}{}
	}
	return s
}

func splitKey(key string) (tunnel, reason string) {
	for i := 0; i < len(key); i++ {
		if key[i] == '|' {
			return key[:i], key[i+1:]
		}
	}
	return key, ""
}
