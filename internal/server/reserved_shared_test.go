package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/acme"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

const sharedHost = "enroll.example.test"

type memShared struct {
	mu   sync.Mutex
	data map[string][]byte
	err  error
}

func (m *memShared) SelfCert(_ context.Context, host string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, false, m.err
	}
	b, ok := m.data[host]
	return b, ok, nil
}

func (m *memShared) PutSelfCert(_ context.Context, host string, bundle []byte, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	if m.data == nil {
		m.data = map[string][]byte{}
	}
	m.data[host] = bundle
	return nil
}

func newSharedStore(t *testing.T) (*acme.ChallengeStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	return acme.NewChallengeStore(rdb, acme.ChallengeTTL), mr
}

func seedShared(t *testing.T, s sharedCertStore, certPEM, keyPEM []byte, info store.CertInfo) {
	t.Helper()
	raw, err := json.Marshal(certBundle{CertPEM: string(certPEM), KeyPEM: string(keyPEM), Info: info})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutSelfCert(context.Background(), sharedHost, raw, time.Until(info.NotAfter)); err != nil {
		t.Fatal(err)
	}
}

type unlockProbe struct {
	fakeLocker
	onUnlock func()
}

func (u *unlockProbe) LockSelf(ctx context.Context, host string) (func() error, bool, error) {
	unlock, ok, err := u.fakeLocker.LockSelf(ctx, host)
	return func() error { u.onUnlock(); return unlock() }, ok, err
}

func TestReservedCerts_SharedHitUnderLockOrdersNothing(t *testing.T) {
	cs, _ := newSharedStore(t)
	certPEM, keyPEM, info := mintSelfCert(t, sharedHost, time.Now().Add(100*time.Hour))
	seedShared(t, cs, certPEM, keyPEM, info)
	iss := &countingIssuer{}
	lock := &fakeLocker{}
	dir := t.TempDir()
	rc := newTestReserved(dir, []string{sharedHost}, iss.obtain, neverRenew, lock, testLogger())
	rc.shared = cs

	rc.issue(context.Background(), rc.hosts[sharedHost])
	if iss.callCount() != 0 {
		t.Fatalf("a valid, not-due shared cert under the lock must not be ordered, got %d orders", iss.callCount())
	}
	if lock.unlockCount() != 1 {
		t.Fatalf("the lock must be released after taking the shared cert, unlocks = %d", lock.unlockCount())
	}
	if got := rc.hosts[sharedHost].currentInfo(); !got.NotAfter.Equal(info.NotAfter) {
		t.Fatalf("the shared cert must be served, got %+v", got)
	}
	if _, disk, ok := rc.loadCached(sharedHost); !ok || !disk.NotAfter.Equal(info.NotAfter) {
		t.Fatalf("the shared cert must be persisted to the disk bundle, got %+v (ok=%v)", disk, ok)
	}
}

func TestReservedCerts_MissOrdersAndPublishesBeforeUnlock(t *testing.T) {
	cs, mr := newSharedStore(t)
	certPEM, keyPEM, info := mintSelfCert(t, sharedHost, time.Now().Add(100*time.Hour))
	iss := &countingIssuer{certPEM: certPEM, keyPEM: keyPEM, info: info}
	var publishedAtUnlock bool
	lock := &unlockProbe{}
	lock.onUnlock = func() { publishedAtUnlock = mr.Exists("acme:self-cert:" + sharedHost) }
	rc := newTestReserved(t.TempDir(), []string{sharedHost}, iss.obtain, neverRenew, lock, testLogger())
	rc.shared = cs

	rc.issue(context.Background(), rc.hosts[sharedHost])
	if iss.callCount() != 1 {
		t.Fatalf("a shared-store miss must order exactly once, got %d", iss.callCount())
	}
	if !publishedAtUnlock {
		t.Fatal("the issued cert must be published to Valkey BEFORE the lock is released")
	}
	if ttl, want := mr.TTL("acme:self-cert:"+sharedHost), time.Until(info.NotAfter); ttl > want || ttl < want-time.Minute {
		t.Fatalf("the shared cert TTL must run until NotAfter, ttl = %v want ≈ %v", ttl, want)
	}
	raw, ok, err := cs.SelfCert(context.Background(), sharedHost)
	if err != nil || !ok {
		t.Fatalf("the published cert must be readable: ok=%v err=%v", ok, err)
	}
	var b certBundle
	if err := json.Unmarshal(raw, &b); err != nil || b.CertPEM != string(certPEM) || b.KeyPEM != string(keyPEM) {
		t.Fatalf("the published bundle must carry the issued cert + key (err=%v)", err)
	}
}

func TestReservedCerts_SharedPickUp(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name       string
		local      time.Duration
		shared     time.Duration
		atStartup  bool
		wantShared bool
	}{
		{name: "startup takes a newer shared cert", local: 50 * time.Hour, shared: 100 * time.Hour, atStartup: true, wantShared: true},
		{name: "startup keeps a newer local cert", local: 100 * time.Hour, shared: 50 * time.Hour, atStartup: true},
		{name: "renewal check takes a newer shared cert", local: 50 * time.Hour, shared: 100 * time.Hour, wantShared: true},
		{name: "renewal check keeps a newer local cert", local: 100 * time.Hour, shared: 50 * time.Hour},
		{name: "expired shared cert is ignored", local: 50 * time.Hour, shared: -time.Hour, atStartup: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			localCert, localKey, localInfo := mintSelfCert(t, sharedHost, now.Add(tc.local))
			seedCache(t, dir, sharedHost, localCert, localKey, localInfo)
			sharedCert, sharedKey, sharedInfo := mintSelfCert(t, sharedHost, now.Add(tc.shared))
			shared := &memShared{}
			iss := &countingIssuer{}
			rc := newTestReserved(dir, []string{sharedHost}, iss.obtain, neverRenew, &fakeLocker{}, testLogger())
			rc.shared = shared
			if tc.atStartup {
				seedShared(t, shared, sharedCert, sharedKey, sharedInfo)
				rc.loadCache(context.Background())
			} else {
				rc.loadCache(context.Background())
				seedShared(t, shared, sharedCert, sharedKey, sharedInfo)
				rc.maybeRenew(context.Background(), rc.hosts[sharedHost])
			}
			want := localInfo.NotAfter
			if tc.wantShared {
				want = sharedInfo.NotAfter
			}
			if got := rc.hosts[sharedHost].currentInfo().NotAfter; !got.Equal(want) {
				t.Fatalf("served NotAfter = %v, want %v", got, want)
			}
			if _, disk, ok := rc.loadCached(sharedHost); !ok || !disk.NotAfter.Equal(want) {
				t.Fatalf("the disk cache must hold the served cert, got %+v (ok=%v)", disk, ok)
			}
			if iss.callCount() != 0 {
				t.Fatalf("no order may be placed, got %d", iss.callCount())
			}
		})
	}
}

func TestReservedCerts_SharedErrorFallsBackToDisk(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM, info := mintSelfCert(t, sharedHost, time.Now().Add(100*time.Hour))
	seedCache(t, dir, sharedHost, certPEM, keyPEM, info)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	rc := newTestReserved(dir, []string{sharedHost}, (&countingIssuer{}).obtain, neverRenew, &fakeLocker{}, logger)
	rc.shared = &memShared{err: errors.New("valkey down")}

	rc.loadCache(context.Background())
	if got := rc.hosts[sharedHost].currentInfo().NotAfter; !got.Equal(info.NotAfter) {
		t.Fatalf("an unavailable shared store must fall back to the disk cache, served NotAfter = %v", got)
	}
	if !strings.Contains(buf.String(), `msg="reserved-host shared cert read failed (keeping the local cert)"`) {
		t.Fatalf("the shared-store failure must be logged; log = %q", buf.String())
	}
}
