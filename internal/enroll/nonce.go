// Package enroll implements attested enrollment: the challenge nonce, the write-verify name-claim
// protocol (no conditional S3 writes), the seven-point attestation gate with key binding + CSR
// proof-of-possession, the issuance cap, and the server-TLS enroll HTTP handler. It declares a
// consumer-side PublicIssuer interface so it does not depend on internal/acme.
package enroll

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// nonceTTL bounds how long an unused enrollment nonce lives in Valkey.
const nonceTTL = 5 * time.Minute

func nonceKey(nonce string) string { return "enroll-nonce:" + nonce }

// Nonce issues a fresh single-use challenge nonce, stored at enroll-nonce:{nonce} in Valkey with a
// short TTL. The app embeds it as the attestation challenge at key generation.
func (s *Service) Nonce(ctx context.Context) ([]byte, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("enroll: nonce rand: %w", err)
	}
	nonce := b[:]
	if err := s.rdb.Set(ctx, nonceKey(hex.EncodeToString(nonce)), "1", nonceTTL).Err(); err != nil {
		return nil, fmt.Errorf("enroll: store nonce: %w", err)
	}
	return nonce, nil
}

// consumeNonce atomically validates and deletes the nonce (single use). Returns false if absent.
var consumeNonceScript = redis.NewScript(`
if redis.call('DEL', KEYS[1]) == 1 then return 1 end
return 0
`)

func (s *Service) consumeNonce(ctx context.Context, nonce []byte) (bool, error) {
	ok, err := consumeNonceScript.Run(ctx, s.rdb, []string{nonceKey(hex.EncodeToString(nonce))}).Int()
	if err != nil {
		return false, err
	}
	return ok == 1, nil
}

// firstLabel returns the first DNS label of a host (stripping any port), lower-cased, so a generated
// tunnel name can never collide with a reserved operator hostname on the shared :443 namespace.
func firstLabel(host string) string {
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	if i := strings.IndexByte(host, '.'); i >= 0 {
		host = host[:i]
	}
	return strings.ToLower(host)
}
