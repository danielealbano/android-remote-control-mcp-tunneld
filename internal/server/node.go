package server

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"strings"
	"time"
)

// newNodeID returns a random 8-byte hex node identity.
func newNodeID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// hostname returns the OS hostname, falling back to a random node id when unavailable (connection-log
// restart detection only needs a stable-per-process value).
func hostname(lookup func() (string, error), logger *slog.Logger) string {
	h, err := lookup()
	if err != nil || h == "" {
		fallback := "node-" + newNodeID()[:6]
		logger.Warn("OS hostname unavailable (using a random node name)", "fallback", fallback, "err", err)
		return fallback
	}
	return h
}

// nodeStartStamp is this process's start timestamp (RFC3339Nano) used for connection-log restart
// detection.
func nodeStartStamp() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// firstLabel returns the first DNS label of a host (dropping any port), lower-cased.
func firstLabel(host string) string {
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	if i := strings.IndexByte(host, '.'); i >= 0 {
		host = host[:i]
	}
	return strings.ToLower(host)
}
