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
	mu     sync.Mutex
	data   map[string][]byte
	err    error
	putErr error
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

func (m *memShared) PutSelfCert(ctx context.Context, host string, bundle []byte, _ time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	if m.putErr != nil {
		return m.putErr
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
	t.Parallel()
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
	t.Parallel()
	cs, mr := newSharedStore(t)
	certPEM, keyPEM, info := mintSelfCert(t, sharedHost, time.Now().Add(100*time.Hour))
	iss := &countingIssuer{certPEM: certPEM, keyPEM: keyPEM, info: info}
	var publishedAtUnlock bool
	lock := &unlockProbe{}
	lock.onUnlock = func() { publishedAtUnlock = mr.Exists("acme:self-cert:" + sharedHost) }
	rc := newTestReserved(t.TempDir(), []string{sharedHost}, iss.obtain, neverRenew, lock, testLogger())
	rc.shared = cs

	before := time.Until(info.NotAfter)
	rc.issue(context.Background(), rc.hosts[sharedHost])
	after := time.Until(info.NotAfter)
	if iss.callCount() != 1 {
		t.Fatalf("a shared-store miss must order exactly once, got %d", iss.callCount())
	}
	if !publishedAtUnlock {
		t.Fatal("the issued cert must be published to Valkey BEFORE the lock is released")
	}
	if ttl := mr.TTL("acme:self-cert:" + sharedHost); ttl > before || ttl < after-time.Second {
		t.Fatalf("the shared cert TTL must run until NotAfter, ttl = %v want between %v and %v", ttl, after-time.Second, before)
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
	t.Parallel()
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
			t.Parallel()
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
	t.Parallel()
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

func TestReservedCerts_SharedUnderLockStillOrders(t *testing.T) {
	t.Parallel()
	failCheck := func(context.Context, store.CertInfo) (bool, time.Time, error) {
		return false, time.Time{}, errors.New("ari unavailable")
	}
	tests := []struct {
		name        string
		shouldRenew shouldRenewFunc
		wantLog     string
	}{
		{name: "shared cert due for renewal", shouldRenew: alwaysRenew},
		{name: "shared cert renewal check fails", shouldRenew: failCheck,
			wantLog: `msg="reserved-host shared cert renewal check failed (ordering instead)"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			shared := &memShared{}
			sharedCert, sharedKey, sharedInfo := mintSelfCert(t, sharedHost, time.Now().Add(100*time.Hour))
			seedShared(t, shared, sharedCert, sharedKey, sharedInfo)
			newCert, newKey, newInfo := mintSelfCert(t, sharedHost, time.Now().Add(150*time.Hour))
			iss := &countingIssuer{certPEM: newCert, keyPEM: newKey, info: newInfo}
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
			rc := newTestReserved(t.TempDir(), []string{sharedHost}, iss.obtain, tc.shouldRenew, &fakeLocker{}, logger)
			rc.shared = shared

			rc.issue(context.Background(), rc.hosts[sharedHost])
			if iss.callCount() != 1 {
				t.Fatalf("the shared cert must not be taken under the lock, orders = %d", iss.callCount())
			}
			if got := rc.hosts[sharedHost].currentInfo().NotAfter; !got.Equal(newInfo.NotAfter) {
				t.Fatalf("the newly issued cert must be served, NotAfter = %v", got)
			}
			if tc.wantLog != "" && !strings.Contains(buf.String(), tc.wantLog) {
				t.Fatalf("the failed check must be logged; log = %q", buf.String())
			}
		})
	}
}

func TestReservedCerts_PublishFailureLoggedCertStillServed(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM, info := mintSelfCert(t, sharedHost, time.Now().Add(100*time.Hour))
	iss := &countingIssuer{certPEM: certPEM, keyPEM: keyPEM, info: info}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	rc := newTestReserved(t.TempDir(), []string{sharedHost}, iss.obtain, neverRenew, &fakeLocker{}, logger)
	rc.shared = &memShared{putErr: errors.New("valkey down")}

	rc.issue(context.Background(), rc.hosts[sharedHost])
	if got := rc.hosts[sharedHost].currentInfo().NotAfter; !got.Equal(info.NotAfter) {
		t.Fatalf("the issued cert must be served even when publishing fails, NotAfter = %v", got)
	}
	if _, disk, ok := rc.loadCached(sharedHost); !ok || !disk.NotAfter.Equal(info.NotAfter) {
		t.Fatalf("the issued cert must be persisted even when publishing fails, got %+v (ok=%v)", disk, ok)
	}
	if !strings.Contains(buf.String(), `msg="reserved-host shared cert publish failed (other nodes order their own)"`) {
		t.Fatalf("the publish failure must be logged; log = %q", buf.String())
	}
}

func TestReservedCerts_PublishSurvivesShutdownAfterOrder(t *testing.T) {
	t.Parallel()
	certPEM, keyPEM, info := mintSelfCert(t, sharedHost, time.Now().Add(100*time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	obtain := func(context.Context, string, store.CertInfo) ([]byte, []byte, store.CertInfo, error) {
		cancel()
		return certPEM, keyPEM, info, nil
	}
	shared := &memShared{}
	rc := newTestReserved(t.TempDir(), []string{sharedHost}, obtain, neverRenew, &fakeLocker{}, testLogger())
	rc.shared = shared

	rc.issue(ctx, rc.hosts[sharedHost])
	if _, ok, err := shared.SelfCert(context.Background(), sharedHost); err != nil || !ok {
		t.Fatalf("a cert ordered before shutdown must still be published for the next lock holder: ok=%v err=%v", ok, err)
	}
}

type hangingShared struct {
	mu        sync.Mutex
	deadlines []time.Time
	ended     []error
}

func (h *hangingShared) SelfCert(ctx context.Context, _ string) ([]byte, bool, error) {
	dl, _ := ctx.Deadline()
	<-ctx.Done()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.deadlines = append(h.deadlines, dl)
	h.ended = append(h.ended, ctx.Err())
	return nil, false, ctx.Err()
}

func (*hangingShared) PutSelfCert(ctx context.Context, _ string, _ []byte, _ time.Duration) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestReservedCerts_HangingSharedStoreDoesNotBlockStartup(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	certPEM, keyPEM, info := mintSelfCert(t, sharedHost, time.Now().Add(100*time.Hour))
	seedCache(t, dir, sharedHost, certPEM, keyPEM, info)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	rc := newTestReserved(dir, []string{sharedHost}, (&countingIssuer{}).obtain, neverRenew, &fakeLocker{}, logger)
	shared := &hangingShared{}
	rc.shared = shared
	rc.readTimeout = 50 * time.Millisecond

	start := time.Now()
	rc.loadCache(context.Background())
	end := time.Now()
	shared.mu.Lock()
	deadlines, ended := shared.deadlines, shared.ended
	shared.mu.Unlock()
	if len(ended) != 1 || !errors.Is(ended[0], context.DeadlineExceeded) ||
		deadlines[0].Sub(start) < rc.readTimeout || deadlines[0].Sub(end) > rc.readTimeout {
		t.Fatalf("the shared read must end at its own %v deadline, deadlines=%v ended=%v", rc.readTimeout, deadlines, ended)
	}
	if got := rc.hosts[sharedHost].currentInfo().NotAfter; !got.Equal(info.NotAfter) {
		t.Fatalf("the disk cert must be served when the shared store hangs, NotAfter = %v", got)
	}
	if !strings.Contains(buf.String(), `msg="reserved-host shared cert read failed (keeping the local cert)"`) {
		t.Fatalf("the timed-out read must be logged; log = %q", buf.String())
	}
}
