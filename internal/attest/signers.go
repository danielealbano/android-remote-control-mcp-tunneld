package attest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// SignerAllowlist is a hot-reloadable set of accepted app signing-cert SHA-256 digests (one hex digest
// per line, '#' comments). It follows the ban-engine pattern: an atomic pointer to an immutable set,
// swapped by an mtime watcher, so Allowed is a lock-free read.
type SignerAllowlist struct {
	path   string
	logger *slog.Logger
	set    atomic.Pointer[map[string]struct{}]
	mtime  atomic.Int64
}

// LoadSignerAllowlist reads the file once and returns the allowlist (an unreadable/absent file is an
// error at startup).
func LoadSignerAllowlist(path string, logger *slog.Logger) (*SignerAllowlist, error) {
	a := &SignerAllowlist{path: path, logger: orDiscard(logger)}
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
// reload failure keeps the last-known-good snapshot and is logged at Warn; because a failed reload does
// NOT advance the recorded mtime, it retries on EVERY subsequent tick until it succeeds. A vanished or
// unreadable file is refused the same way — the previous set is KEPT (never cleared) and the stat error
// is logged at Error once per state transition. The allowlist is a security-critical file, so a
// disappearing file must never silently allow everyone (mirrors internal/ban's vanished-file refusal).
func (a *SignerAllowlist) Watch(ctx context.Context, poll time.Duration) {
	if poll <= 0 {
		poll = 10 * time.Second
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	statErrLogged := false // rate-limit: log a vanished/unreadable allowlist ONCE per state transition
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fi, err := os.Stat(a.path)
			if err != nil {
				if !statErrLogged {
					a.logger.Error("signer allowlist stat failed; keeping the last-known-good set", "path", a.path, "err", err)
					statErrLogged = true
				}
				continue // keep last-known-good; never clear the set on a stat failure
			}
			statErrLogged = false
			if fi.ModTime().UnixNano() != a.mtime.Load() {
				if rerr := a.reload(); rerr != nil {
					a.logger.Warn("signer allowlist reload failed; keeping last-known-good set (retries every tick)", "path", a.path, "err", rerr)
				}
			}
		}
	}
}
