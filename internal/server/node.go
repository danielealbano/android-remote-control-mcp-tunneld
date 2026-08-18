package server

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"time"
)

// osHostname is a seam for tests.
var osHostname = os.Hostname

// newNodeID returns a random 8-byte hex node identity.
func newNodeID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// hostname returns the OS hostname, falling back to a random node id when unavailable (connection-log
// restart detection only needs a stable-per-process value).
func hostname() string {
	h, err := osHostname()
	if err != nil || h == "" {
		return "node-" + newNodeID()[:6]
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
