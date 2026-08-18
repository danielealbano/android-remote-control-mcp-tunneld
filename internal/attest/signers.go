package attest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// SignerAllowlist is a hot-reloadable set of accepted app signing-cert SHA-256 digests (one hex digest
// per line, '#' comments). It follows the ban-engine pattern: an atomic pointer to an immutable set,
// swapped by an mtime watcher, so Allowed is a lock-free read.
type SignerAllowlist struct {
	path  string
	set   atomic.Pointer[map[string]struct{}]
	mtime atomic.Int64
}

// LoadSignerAllowlist reads the file once and returns the allowlist (an unreadable/absent file is an
// error at startup).
func LoadSignerAllowlist(path string) (*SignerAllowlist, error) {
	a := &SignerAllowlist{path: path}
	if err := a.reload(); err != nil {
		return nil, err
	}
	return a, nil
}

func parseDigests(data []byte) (map[string]struct{}, error) {
	set := map[string]struct{}{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		line = strings.ToLower(line)
		if _, err := hex.DecodeString(line); err != nil {
			return nil, fmt.Errorf("attest: invalid signer digest %q: %w", line, err)
		}
		set[line] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return set, nil
}

func (a *SignerAllowlist) reload() error {
	fi, err := os.Stat(a.path)
	if err != nil {
		return fmt.Errorf("attest: stat signer allowlist: %w", err)
	}
	data, err := os.ReadFile(a.path)
	if err != nil {
		return fmt.Errorf("attest: read signer allowlist: %w", err)
	}
	set, err := parseDigests(data)
	if err != nil {
		return err
	}
	a.set.Store(&set)
	a.mtime.Store(fi.ModTime().UnixNano())
	return nil
}

// Allowed reports whether the given lowercase-hex digest is in the current snapshot (lock-free).
func (a *SignerAllowlist) Allowed(digestHex string) bool {
	set := a.set.Load()
	if set == nil {
		return false
	}
	_, ok := (*set)[strings.ToLower(digestHex)]
	return ok
}

// Watch reloads the allowlist when its mtime changes, at the given poll cadence, until ctx is done. A
// reload error keeps the last-known-good snapshot (logged by the caller via the returned error channel
// is intentionally avoided; a transient read error simply retries next tick).
func (a *SignerAllowlist) Watch(ctx context.Context, poll time.Duration) {
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fi, err := os.Stat(a.path)
			if err != nil {
				continue // keep last-known-good
			}
			if fi.ModTime().UnixNano() != a.mtime.Load() {
				_ = a.reload() // on error, the atomic set is left unchanged (last-known-good)
			}
		}
	}
}
