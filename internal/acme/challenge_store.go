package acme

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	ChallengeTTL      = 10 * time.Minute
	selfLockTTL       = 10 * time.Minute
	selfUnlockTimeout = 5 * time.Second
)

var (
	ErrChallengeStore   = errors.New("acme: challenge store")
	ErrChallengePending = fmt.Errorf("%w: another tls-alpn-01 challenge is pending for this domain", ErrChallengeStore)
)

type ChallengeStore struct {
	rdb redis.UniversalClient
	ttl time.Duration
}

func NewChallengeStore(rdb redis.UniversalClient, ttl time.Duration) *ChallengeStore {
	return &ChallengeStore{rdb: rdb, ttl: ttl}
}

func alpnChallengeKey(domain string) string { return "acme:alpn:" + strings.ToLower(domain) }

func httpChallengeKey(domain, token string) string {
	return "acme:http:" + strings.ToLower(domain) + ":" + token
}

func selfLockKey(host string) string { return "lock:acme-self:" + strings.ToLower(host) }

func selfCertKey(host string) string { return "acme:self-cert:" + strings.ToLower(host) }

func (s *ChallengeStore) PutTLSALPN(ctx context.Context, domain, keyAuth string) error {
	key := alpnChallengeKey(domain)
	for range 2 {
		set, err := s.rdb.SetNX(ctx, key, keyAuth, s.ttl).Result()
		if err != nil {
			return fmt.Errorf("%w: store tls-alpn-01 challenge for %s: %w", ErrChallengeStore, domain, err)
		}
		if set {
			return nil
		}
		cur, err := s.rdb.Get(ctx, key).Result()
		switch {
		case err == nil && cur == keyAuth:
			return nil
		case err == nil:
			return ErrChallengePending
		case !errors.Is(err, redis.Nil):
			return fmt.Errorf("%w: read tls-alpn-01 challenge for %s: %w", ErrChallengeStore, domain, err)
		}
	}
	return ErrChallengePending
}

func (s *ChallengeStore) DeleteTLSALPN(ctx context.Context, domain, keyAuth string) error {
	return s.deleteIfValue(ctx, alpnChallengeKey(domain), keyAuth)
}

func (s *ChallengeStore) TLSALPNCertificate(ctx context.Context, domain string) (*tls.Certificate, bool, error) {
	keyAuth, ok, err := s.get(ctx, alpnChallengeKey(domain))
	if err != nil || !ok {
		return nil, false, err
	}
	cert, err := challengeCertificate(strings.ToLower(domain), keyAuth)
	if err != nil {
		return nil, false, fmt.Errorf("%w: tls-alpn-01 certificate for %s: %w", ErrChallengeStore, domain, err)
	}
	return cert, true, nil
}

func (s *ChallengeStore) PutHTTP(ctx context.Context, domain, token, keyAuth string) error {
	if err := s.rdb.Set(ctx, httpChallengeKey(domain, token), keyAuth, s.ttl).Err(); err != nil {
		return fmt.Errorf("%w: store http-01 challenge for %s: %w", ErrChallengeStore, domain, err)
	}
	return nil
}

func (s *ChallengeStore) DeleteHTTP(ctx context.Context, domain, token, keyAuth string) error {
	return s.deleteIfValue(ctx, httpChallengeKey(domain, token), keyAuth)
}

func (s *ChallengeStore) HTTPKeyAuth(ctx context.Context, domain, token string) (string, bool, error) {
	return s.get(ctx, httpChallengeKey(domain, token))
}

func (s *ChallengeStore) LockSelf(ctx context.Context, host string) (func() error, bool, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return noUnlock, false, fmt.Errorf("%w: self-issuance lock token: %w", ErrChallengeStore, err)
	}
	token := hex.EncodeToString(b[:])
	set, err := s.rdb.SetNX(ctx, selfLockKey(host), token, selfLockTTL).Result()
	if err != nil {
		return noUnlock, false, fmt.Errorf("%w: self-issuance lock for %s: %w", ErrChallengeStore, host, err)
	}
	if !set {
		return noUnlock, false, nil
	}
	return func() error {
		uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), selfUnlockTimeout)
		defer cancel()
		return s.deleteIfValue(uctx, selfLockKey(host), token)
	}, true, nil
}

func noUnlock() error { return nil }

func (s *ChallengeStore) SelfCert(ctx context.Context, host string) ([]byte, bool, error) {
	v, ok, err := s.get(ctx, selfCertKey(host))
	if err != nil || !ok {
		return nil, false, err
	}
	return []byte(v), true, nil
}

func (s *ChallengeStore) PutSelfCert(ctx context.Context, host string, bundle []byte, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("%w: self cert for %s is already expired", ErrChallengeStore, host)
	}
	if err := s.rdb.Set(ctx, selfCertKey(host), bundle, ttl).Err(); err != nil {
		return fmt.Errorf("%w: publish self cert for %s: %w", ErrChallengeStore, host, err)
	}
	return nil
}

func (s *ChallengeStore) get(ctx context.Context, key string) (string, bool, error) {
	v, err := s.rdb.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("%w: read %s: %w", ErrChallengeStore, key, err)
	}
	return v, true, nil
}

func (s *ChallengeStore) deleteIfValue(ctx context.Context, key, want string) error {
	cur, ok, err := s.get(ctx, key)
	if err != nil || !ok || cur != want {
		return err
	}
	if err := s.rdb.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("%w: delete %s: %w", ErrChallengeStore, key, err)
	}
	return nil
}
