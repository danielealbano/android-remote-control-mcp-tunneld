package ca

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"io"
	"regexp"
	"strings"
)

// reserved host labels the name generator must never produce: the reserved /connect path source and
// the ops labels. NOTE: these BARE labels only collide with a generated name when --name-prefix is
// empty; with a non-empty prefix the prefixed name can never equal a bare label, so the enroll host's
// first label is passed in as an extra reserved label (a prefix-independent guard) by the caller.
var reserved = map[string]struct{}{
	"enroll":       {},
	"connect":      {},
	"tunnel":       {},
	"grafana":      {},
	"prometheus":   {},
	"alertmanager": {},
	"ntfy":         {},
	"www":          {},
	"api":          {},
	"admin":        {},
}

var labelRe = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)

var noPadBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateName returns prefix + base32(crypto/rand)[:length], lowercase [a-z2-7], skipping the
// reserved-hostname set (plus any extra reserved labels, e.g. the enroll host's first label) and any
// label failing the host-label regex.
func GenerateName(prefix string, length int, extra ...string) (string, error) {
	return generateName(prefix, length, rand.Reader, extra...)
}

// generateName is the injectable core (tests pass a deterministic rnd to force reserved collisions
// and the attempt-exhaustion path).
func generateName(prefix string, length int, rnd io.Reader, extra ...string) (string, error) {
	nbytes := (length*5 + 7) / 8
	for attempt := 0; attempt < 8; attempt++ {
		buf := make([]byte, nbytes)
		if _, err := io.ReadFull(rnd, buf); err != nil {
			return "", err
		}
		enc := strings.ToLower(noPadBase32.EncodeToString(buf))
		if len(enc) < length {
			continue
		}
		name := prefix + enc[:length]
		if _, bad := reserved[name]; bad {
			continue
		}
		if isExtraReserved(name, extra) {
			continue
		}
		if !labelRe.MatchString(name) {
			continue
		}
		return name, nil
	}
	return "", errors.New("ca: could not generate a valid non-reserved name")
}

func isExtraReserved(name string, extra []string) bool {
	for _, e := range extra {
		if strings.EqualFold(name, e) {
			return true
		}
	}
	return false
}
