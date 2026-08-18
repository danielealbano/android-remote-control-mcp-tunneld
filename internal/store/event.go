package store

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

// Close-reason enum values (also the connection-log close_reason field). min-rate/evicted are CLOSE
// reasons, never rejection-counter labels.
const (
	CloseClientClose    = "client-close"
	ClosePhoneClose     = "phone-close"
	CloseBanEvict       = "ban-evict"
	CloseQuotaExhausted = "quota-exhausted"
	CloseIdleTimeout    = "idle-timeout"
	CloseMinRate        = "min-rate"
	CloseEvicted        = "evicted"
	CloseServerShutdown = "server-shutdown"
	CloseError          = "error"
)

// Event is one connection-log event (start OR end) for a public OR phone connection — one schema, one
// pipeline. node_start (a nanosecond process-start timestamp) is present on EVERY event to tie events
// to a process incarnation (crash detection). JA4 (tls_fp) is recorded on both sides; on phone
// connections it is an anomaly tripwire only, never a gate.
type Event struct {
	Schema       int    `json:"schema"`
	Event        string `json:"event"` // "start" | "end"
	Conn         string `json:"conn"`  // 10-hex conn id (see NewConnID)
	Type         string `json:"type"`  // "public" | "phone"
	Tunnel       string `json:"tunnel"`
	NodeHostname string `json:"node_hostname"`
	NodeStart    string `json:"node_start"` // RFC3339Nano process-start timestamp

	TSStart    time.Time `json:"ts_start"`
	TSEnd      time.Time `json:"ts_end,omitzero"`
	DurationMS int64     `json:"duration_ms,omitempty"`

	SrcIP      string `json:"src_ip"`
	SrcPort    int    `json:"src_port"`
	SNI        string `json:"sni,omitempty"` // public only
	ALPN       string `json:"alpn,omitempty"`
	TLSVersion string `json:"tls_version,omitempty"`
	TLSFP      string `json:"tls_fp,omitempty"` // JA4

	BytesIn  int64 `json:"bytes_in,omitempty"`  // end only, from the peer's perspective
	BytesOut int64 `json:"bytes_out,omitempty"` // end only

	CloseReason string `json:"close_reason,omitempty"`

	// Phone-only:
	IdentityCertSerial string `json:"identity_cert_serial,omitempty"`
	IdentityKeyFP      string `json:"identity_key_fpr,omitempty"`
}

// tsNanosLayout sorts chronologically as a string in an S3 listing.
const tsNanosLayout = "20060102T150405.000000000Z"

// LogKey is the S3 key for a connection-log event:
// tunnel-logs/<name>/<yyyy>/<mm>/<dd>/<tsNanos>-<conn8>-<event>.json (conn8 = first 8 conn chars).
func LogKey(ev Event) string {
	ts := ev.TSStart
	if ev.Event == "end" && !ev.TSEnd.IsZero() {
		ts = ev.TSEnd
	}
	ts = ts.UTC()
	conn8 := ev.Conn
	if len(conn8) > 8 {
		conn8 = conn8[:8]
	}
	return fmt.Sprintf("tunnel-logs/%s/%04d/%02d/%02d/%s-%s-%s.json",
		ev.Tunnel, ts.Year(), ts.Month(), ts.Day(), ts.Format(tsNanosLayout), conn8, ev.Event)
}

// NewConnID mints a 10-lowercase-hex connection id = 3 big-endian bytes of
// int(now.Sub(sessionStart).Seconds()) & 0xFFFFFF (seconds since the tunnel-session start) ‖ 2
// crypto/rand bytes. Both callers (phone control connections and public connections) seed sessionStart
// with the SAME per-tunnel epoch — the phone control connection's establishment time — so every conn id
// of one tunnel session counts from the same origin.
func NewConnID(sessionStart, now time.Time) (string, error) {
	secs := max(int64(now.Sub(sessionStart).Seconds()), 0)
	v := uint32(secs) & 0xFFFFFF
	var buf [5]byte
	binary.BigEndian.PutUint32(buf[:4], v<<8) // v occupies the top 24 bits of the first 4 bytes...
	// buf[0..2] now hold the 3 big-endian bytes of v; overwrite buf[3..4] with random.
	if _, err := rand.Read(buf[3:]); err != nil {
		return "", fmt.Errorf("store: conn id rand: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}
