package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// TestReservedMaybeRenew_LogsShouldRenewError verifies a shouldRenew error is logged (not silently
// swallowed) so a stalled reserved-host renewal is diagnosable before the cert expires.
func TestReservedMaybeRenew_LogsShouldRenewError(t *testing.T) {
	dir := t.TempDir()
	host := "enroll.example.test"
	certPEM, keyPEM, info := mintSelfCert(t, host, time.Now().Add(400*time.Hour))
	seedCache(t, dir, host, certPEM, keyPEM, info)
	iss := &countingIssuer{certPEM: certPEM, keyPEM: keyPEM, info: info}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	failRenew := func(context.Context, store.CertInfo) (bool, time.Time, error) {
		return false, time.Time{}, errors.New("cooldown state unavailable")
	}
	rc := newTestReserved(dir, []string{host}, iss.obtain, failRenew, &fakeLocker{}, logger)
	rc.loadCache()
	rc.maybeRenew(context.Background(), rc.hosts[host])
	if !strings.Contains(buf.String(), "renewal check failed") {
		t.Fatalf("a shouldRenew error must be logged at Warn; log = %q", buf.String())
	}
	if iss.callCount() != 0 {
		t.Fatalf("a failed renewal check must not obtain, got %d calls", iss.callCount())
	}
}

func TestReservedCerts_LoadCacheUsesInjectedClock(t *testing.T) {
	dir := t.TempDir()
	host := "enroll.example.test"
	realNow := time.Now()
	cachedCert, cachedKey, cachedInfo := mintSelfCert(t, host, realNow.Add(10*time.Hour))
	seedCache(t, dir, host, cachedCert, cachedKey, cachedInfo)

	rc := newTestReserved(dir, []string{host}, (&countingIssuer{}).obtain, neverRenew, &fakeLocker{}, testLogger())
	rc.now = func() time.Time { return realNow.Add(20 * time.Hour) }
	rc.loadCache()
	if _, err := rc.getCertificateFor(host)(nil); err == nil {
		t.Fatal("a cache expired by the injected clock must not be served")
	}

	rc = newTestReserved(dir, []string{host}, (&countingIssuer{}).obtain, neverRenew, &fakeLocker{}, testLogger())
	rc.now = func() time.Time { return realNow }
	rc.loadCache()
	if _, err := rc.getCertificateFor(host)(nil); err != nil {
		t.Fatalf("a cache still valid by the injected clock must be served, got %v", err)
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// mintSelfCert produces a self-signed cert (PEM) + key (PEM) + CertInfo for host with the given NotAfter.
func mintSelfCert(t *testing.T, host string, notAfter time.Time) (certPEM, keyPEM []byte, info store.CertInfo) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: notAfter.Add(-160 * time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	info = store.CertInfo{CA: "letsencrypt", Serial: "1", NotBefore: tmpl.NotBefore, NotAfter: notAfter}
	return certPEM, keyPEM, info
}

// countingIssuer is a selfIssuer that records calls and returns a canned cert or error.
type countingIssuer struct {
	mu      sync.Mutex
	calls   int
	certPEM []byte
	keyPEM  []byte
	info    store.CertInfo
	err     error
}

func (c *countingIssuer) obtain(context.Context, string) ([]byte, []byte, store.CertInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return c.certPEM, c.keyPEM, c.info, c.err
}

func (c *countingIssuer) callCount() int { c.mu.Lock(); defer c.mu.Unlock(); return c.calls }

func neverRenew(context.Context, store.CertInfo) (bool, time.Time, error) {
	return false, time.Time{}, nil
}

func alwaysRenew(context.Context, store.CertInfo) (bool, time.Time, error) {
	return true, time.Time{}, nil
}

func newTestReserved(dir string, hosts []string, obtain selfIssuer, shouldRenew shouldRenewFunc, lock selfLocker, logger *slog.Logger) *reservedCerts {
	rc := newReservedCerts(dir, hosts, obtain, shouldRenew, lock, logger)
	rc.lockWait, rc.issueTimeout, rc.lockPoll = 200*time.Millisecond, 200*time.Millisecond, 10*time.Millisecond
	return rc
}

type fakeLocker struct {
	mu             sync.Mutex
	busyFor        int
	alwaysBusy     bool
	err            error
	blockUntilDone bool
	cancelOnLock   context.CancelFunc
	calls          int
	unlocks        int
}

func (f *fakeLocker) LockSelf(ctx context.Context, _ string) (func() error, bool, error) {
	f.mu.Lock()
	f.calls++
	call := f.calls
	f.mu.Unlock()
	unlock := func() error {
		f.mu.Lock()
		f.unlocks++
		f.mu.Unlock()
		return nil
	}
	switch {
	case f.blockUntilDone:
		<-ctx.Done()
		return unlock, false, ctx.Err()
	case f.err != nil:
		return unlock, false, f.err
	case f.alwaysBusy || call <= f.busyFor:
		return unlock, false, nil
	}
	if f.cancelOnLock != nil {
		f.cancelOnLock()
	}
	return unlock, true, nil
}

func (f *fakeLocker) unlockCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.unlocks }

type blockingIssuer struct {
	mu        sync.Mutex
	calls     int
	calledAt  time.Time
	deadline  time.Time
	hasDeadln bool
}

func (b *blockingIssuer) obtain(ctx context.Context, _ string) ([]byte, []byte, store.CertInfo, error) {
	b.mu.Lock()
	b.calls++
	b.calledAt = time.Now()
	b.deadline, b.hasDeadln = ctx.Deadline()
	b.mu.Unlock()
	<-ctx.Done()
	return nil, nil, store.CertInfo{}, ctx.Err()
}

func (b *blockingIssuer) callCount() int { b.mu.Lock(); defer b.mu.Unlock(); return b.calls }

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %s", d)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// seedCache writes a persisted cert/key/meta triple under dir/self/<host>/.
func seedCache(t *testing.T, dir, host string, certPEM, keyPEM []byte, info store.CertInfo) {
	t.Helper()
	hd := filepath.Join(dir, "self", host)
	if err := os.MkdirAll(hd, 0o700); err != nil {
		t.Fatal(err)
	}
	meta, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"cert.pem": certPEM, "key.pem": keyPEM, "meta.json": meta} {
		if err := os.WriteFile(filepath.Join(hd, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReservedCerts_CacheReused(t *testing.T) {
	dir := t.TempDir()
	host := "enroll.example.test"
	certPEM, keyPEM, info := mintSelfCert(t, host, time.Now().Add(400*time.Hour))
	seedCache(t, dir, host, certPEM, keyPEM, info)

	iss := &countingIssuer{}
	lock := &fakeLocker{}
	var checks atomic.Int32
	notDue := func(context.Context, store.CertInfo) (bool, time.Time, error) {
		checks.Add(1)
		return false, time.Time{}, nil
	}
	rc := newTestReserved(dir, []string{host}, iss.obtain, notDue, lock, testLogger())
	rc.loadCache()
	if _, err := rc.getCertificateFor(host)(nil); err != nil {
		t.Fatalf("cached cert must be served, got %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rc.run(ctx, time.Hour, time.Hour) }()
	waitFor(t, 5*time.Second, func() bool { return checks.Load() >= 1 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	lock.mu.Lock()
	lockCalls := lock.calls
	lock.mu.Unlock()
	if iss.callCount() != 0 || lockCalls != 0 {
		t.Fatalf("a valid, not-due cached pair must NOT trigger issuance: obtains=%d lock calls=%d", iss.callCount(), lockCalls)
	}
}

func TestReservedCerts_ObtainsWhenNoCache(t *testing.T) {
	dir := t.TempDir()
	host := "connect.example.test"
	certPEM, keyPEM, info := mintSelfCert(t, host, time.Now().Add(400*time.Hour))
	iss := &countingIssuer{certPEM: certPEM, keyPEM: keyPEM, info: info}
	lock := &fakeLocker{}
	rc := newTestReserved(dir, []string{host}, iss.obtain, neverRenew, lock, testLogger())
	rc.loadCache()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rc.run(ctx, time.Hour, time.Hour) }()
	// It must have been persisted for reuse across restarts (atomic single-file bundle).
	var statErr error
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, statErr = os.Stat(filepath.Join(dir, "self", host, "bundle.json")); statErr == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("bundle.json was never persisted: %v", statErr)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if iss.callCount() != 1 {
		t.Fatalf("no cache must trigger exactly one ObtainSelf, got %d", iss.callCount())
	}
	if _, err := rc.getCertificateFor(host)(nil); err != nil {
		t.Fatalf("obtained cert must be served, got %v", err)
	}
	if lock.unlockCount() != 1 {
		t.Fatalf("the cluster lock must be released after issuance, got %d unlocks", lock.unlockCount())
	}
}

func TestReservedCerts_DegradedWhenNoCAAndNoCache(t *testing.T) {
	dir := t.TempDir()
	host := "enroll.example.test"
	iss := &countingIssuer{err: context.DeadlineExceeded} // no CA can issue
	rc := newTestReserved(dir, []string{host}, iss.obtain, neverRenew, &fakeLocker{}, testLogger())
	rc.loadCache()
	rc.maybeRenew(context.Background(), rc.hosts[host])

	if iss.callCount() != 1 {
		t.Fatalf("a host without a cert must try to obtain once per pass, got %d", iss.callCount())
	}
	if _, err := rc.getCertificateFor(host)(nil); err == nil {
		t.Fatal("with no CA and no cache the reserved host must be degraded (TLS refused)")
	}
}

func TestReservedCerts_RenewsExpiringCache(t *testing.T) {
	tests := []struct {
		name      string
		renewErr  error
		wantNewer bool
	}{
		{name: "renewal succeeds", wantNewer: true},
		{name: "renewal fails keeps current", renewErr: errors.New("all CAs cooling")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			host := "enroll.example.test"
			// Cached pair is still valid → must be renewed at startup.
			oldCert, oldKey, oldInfo := mintSelfCert(t, host, time.Now().Add(10*time.Hour))
			seedCache(t, dir, host, oldCert, oldKey, oldInfo)
			newCert, newKey, newInfo := mintSelfCert(t, host, time.Now().Add(400*time.Hour))
			iss := &countingIssuer{certPEM: newCert, keyPEM: newKey, info: newInfo, err: tc.renewErr}
			rc := newTestReserved(dir, []string{host}, iss.obtain, alwaysRenew, &fakeLocker{}, testLogger())
			rc.loadCache()
			rc.maybeRenew(context.Background(), rc.hosts[host])

			if iss.callCount() != 1 {
				t.Fatalf("a due cached pair must be renewed once in the first pass, got %d", iss.callCount())
			}
			if _, err := rc.getCertificateFor(host)(nil); err != nil {
				t.Fatalf("a cert must still be served, got %v", err)
			}
			if got := rc.hosts[host].currentInfo().NotAfter.After(oldInfo.NotAfter); got != tc.wantNewer {
				t.Fatalf("served NotAfter newer = %v, want %v", got, tc.wantNewer)
			}
			if !tc.wantNewer {
				return
			}
			raw, err := os.ReadFile(filepath.Join(dir, "self", host, "bundle.json"))
			if err != nil {
				t.Fatal(err)
			}
			var got certBundle
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			if !got.Info.NotAfter.After(oldInfo.NotAfter) {
				t.Fatalf("renewed cert must be re-persisted with a later NotAfter (old=%v new=%v)", oldInfo.NotAfter, got.Info.NotAfter)
			}
		})
	}
}

func TestReservedCerts_RunRetriesDegradedSooner(t *testing.T) {
	t.Run("degraded retries at degradedEvery", func(t *testing.T) {
		iss := &countingIssuer{err: errors.New("no CA")}
		rc := newTestReserved(t.TempDir(), []string{"enroll.example.test"}, iss.obtain, neverRenew, &fakeLocker{}, testLogger())
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- rc.run(ctx, time.Hour, 20*time.Millisecond) }()
		waitFor(t, 5*time.Second, func() bool { return iss.callCount() >= 3 })
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
	t.Run("healthy waits renewEvery", func(t *testing.T) {
		host := "enroll.example.test"
		certPEM, keyPEM, info := mintSelfCert(t, host, time.Now().Add(400*time.Hour))
		iss := &countingIssuer{certPEM: certPEM, keyPEM: keyPEM, info: info}
		var checks atomic.Int32
		notDue := func(context.Context, store.CertInfo) (bool, time.Time, error) {
			checks.Add(1)
			return false, time.Time{}, nil
		}
		rc := newTestReserved(t.TempDir(), []string{host}, iss.obtain, notDue, &fakeLocker{}, testLogger())
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- rc.run(ctx, time.Hour, 20*time.Millisecond) }()
		waitFor(t, 5*time.Second, func() bool { return iss.callCount() >= 1 })
		time.Sleep(200 * time.Millisecond)
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if iss.callCount() != 1 || checks.Load() != 0 {
			t.Fatalf("a healthy host must wait renewEvery before the next pass: obtains=%d renewal checks=%d", iss.callCount(), checks.Load())
		}
	})
}

func TestReservedCerts_WaitsForClusterLock(t *testing.T) {
	host := "enroll.example.test"
	certPEM, keyPEM, info := mintSelfCert(t, host, time.Now().Add(400*time.Hour))
	iss := &countingIssuer{certPEM: certPEM, keyPEM: keyPEM, info: info}
	lock := &fakeLocker{busyFor: 3}
	rc := newTestReserved(t.TempDir(), []string{host}, iss.obtain, neverRenew, lock, testLogger())
	rc.maybeRenew(context.Background(), rc.hosts[host])
	if iss.callCount() != 1 || lock.unlockCount() != 1 {
		t.Fatalf("obtains=%d unlocks=%d, want 1/1 once the lock frees", iss.callCount(), lock.unlockCount())
	}
}

func TestReservedCerts_LockErrorFailsOpen(t *testing.T) {
	host := "enroll.example.test"
	certPEM, keyPEM, info := mintSelfCert(t, host, time.Now().Add(400*time.Hour))
	iss := &countingIssuer{certPEM: certPEM, keyPEM: keyPEM, info: info}
	lock := &fakeLocker{err: errors.New("valkey down")}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	rc := newTestReserved(t.TempDir(), []string{host}, iss.obtain, neverRenew, lock, logger)
	rc.maybeRenew(context.Background(), rc.hosts[host])
	if iss.callCount() != 1 {
		t.Fatalf("a lock error must still issue, got %d obtains", iss.callCount())
	}
	if !strings.Contains(buf.String(), "lock unavailable") {
		t.Fatalf("a lock error must be logged at Warn; log = %q", buf.String())
	}
	if lock.unlockCount() != 0 {
		t.Fatal("no unlock may run for a lock that was never held")
	}
}

func TestReservedCerts_LockBusyUntilWaitBudget(t *testing.T) {
	host := "enroll.example.test"
	iss := &countingIssuer{}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	rc := newTestReserved(t.TempDir(), []string{host}, iss.obtain, neverRenew, &fakeLocker{alwaysBusy: true}, logger)
	start := time.Now()
	rc.maybeRenew(context.Background(), rc.hosts[host])
	if elapsed := time.Since(start); elapsed < rc.lockWait {
		t.Fatalf("returned after %s, before the %s wait budget", elapsed, rc.lockWait)
	}
	if iss.callCount() != 0 {
		t.Fatalf("a busy lock must not issue, got %d obtains", iss.callCount())
	}
	if !strings.Contains(buf.String(), "busy on another node") {
		t.Fatalf("a busy lock must be logged at Info; log = %q", buf.String())
	}
}

func TestReservedCerts_LockErrorAfterWaitBudget(t *testing.T) {
	host := "enroll.example.test"
	iss := &countingIssuer{}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	rc := newTestReserved(t.TempDir(), []string{host}, iss.obtain, neverRenew, &fakeLocker{blockUntilDone: true}, logger)
	rc.maybeRenew(context.Background(), rc.hosts[host])
	if iss.callCount() != 0 {
		t.Fatalf("an expired lock wait must not issue, got %d obtains", iss.callCount())
	}
	if !strings.Contains(buf.String(), "busy on another node") || strings.Contains(buf.String(), "level=WARN") {
		t.Fatalf("an expired lock wait must read as busy (Info, no Warn); log = %q", buf.String())
	}
}

func TestReservedCerts_AbandonedIssuanceKeepsLock(t *testing.T) {
	host := "enroll.example.test"
	iss := &blockingIssuer{}
	lock := &fakeLocker{}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	rc := newTestReserved(t.TempDir(), []string{host}, iss.obtain, neverRenew, lock, logger)
	rc.maybeRenew(context.Background(), rc.hosts[host])
	if lock.unlockCount() != 0 {
		t.Fatal("an issuance abandoned at its deadline must keep the lock until its TTL")
	}
	if !strings.Contains(buf.String(), "abandoned at its deadline") {
		t.Fatalf("an abandoned issuance must be logged at Warn; log = %q", buf.String())
	}
}

func TestReservedCerts_SeparateBudgets(t *testing.T) {
	host := "enroll.example.test"
	iss := &blockingIssuer{}
	lock := &fakeLocker{busyFor: 20}
	rc := newTestReserved(t.TempDir(), []string{host}, iss.obtain, neverRenew, lock, testLogger())
	rc.lockWait, rc.issueTimeout = 400*time.Millisecond, 500*time.Millisecond
	rc.maybeRenew(context.Background(), rc.hosts[host])
	iss.mu.Lock()
	defer iss.mu.Unlock()
	if iss.calls != 1 || !iss.hasDeadln {
		t.Fatalf("obtain calls=%d deadline=%v, want one call with a deadline", iss.calls, iss.hasDeadln)
	}
	if budget := iss.deadline.Sub(iss.calledAt); budget < rc.issueTimeout-20*time.Millisecond {
		t.Fatalf("obtain got %s after a late lock, want the full %s issuance budget", budget, rc.issueTimeout)
	}
}

func TestReservedCerts_ShutdownWhileWaitingForLock(t *testing.T) {
	t.Run("lock busy", func(t *testing.T) {
		iss := &countingIssuer{}
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
		rc := newTestReserved(t.TempDir(), []string{"enroll.example.test"}, iss.obtain, neverRenew, &fakeLocker{alwaysBusy: true}, logger)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		rc.maybeRenew(ctx, rc.hosts["enroll.example.test"])
		if iss.callCount() != 0 || buf.Len() != 0 {
			t.Fatalf("a shutdown while waiting must neither issue nor log: obtains=%d log=%q", iss.callCount(), buf.String())
		}
	})
	t.Run("lock obtained as ctx is cancelled", func(t *testing.T) {
		iss := &countingIssuer{}
		ctx, cancel := context.WithCancel(context.Background())
		lock := &fakeLocker{cancelOnLock: cancel}
		rc := newTestReserved(t.TempDir(), []string{"enroll.example.test"}, iss.obtain, neverRenew, lock, testLogger())
		rc.maybeRenew(ctx, rc.hosts["enroll.example.test"])
		if iss.callCount() != 0 || lock.unlockCount() != 1 {
			t.Fatalf("obtains=%d unlocks=%d, want 0/1", iss.callCount(), lock.unlockCount())
		}
	})
}

func TestReservedCerts_ShutdownDuringIssuanceReleasesLock(t *testing.T) {
	iss := &blockingIssuer{}
	lock := &fakeLocker{}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	rc := newTestReserved(t.TempDir(), []string{"enroll.example.test"}, iss.obtain, neverRenew, lock, logger)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rc.maybeRenew(ctx, rc.hosts["enroll.example.test"])
		close(done)
	}()
	waitFor(t, 5*time.Second, func() bool { return iss.callCount() == 1 })
	cancel()
	<-done
	if lock.unlockCount() != 1 {
		t.Fatalf("a shutdown during issuance must release the lock, got %d unlocks", lock.unlockCount())
	}
	if buf.Len() != 0 {
		t.Fatalf("a shutdown during issuance must not log a Warn; log = %q", buf.String())
	}
}

func TestReservedCerts_PersistAtomicBundle(t *testing.T) {
	dir := t.TempDir()
	host := "enroll.example.test"
	certPEM, keyPEM, info := mintSelfCert(t, host, time.Now().Add(400*time.Hour))
	rc := &reservedCerts{dir: filepath.Join(dir, "self"), logger: testLogger(), now: time.Now}

	rc.persist(host, certPEM, keyPEM, info)

	hd := filepath.Join(dir, "self", host)
	if _, err := os.Stat(filepath.Join(hd, "bundle.json")); err != nil {
		t.Fatalf("persist must write bundle.json via rename: %v", err)
	}
	if _, err := os.Stat(filepath.Join(hd, "bundle.json.tmp")); !os.IsNotExist(err) {
		t.Fatalf("the temp file must not survive a successful persist (err=%v)", err)
	}
	cert, gotInfo, ok := rc.loadCached(host)
	if !ok || cert == nil {
		t.Fatal("the persisted bundle must load back")
	}
	if !gotInfo.NotAfter.Equal(info.NotAfter) {
		t.Fatalf("loaded NotAfter mismatch: got %v want %v", gotInfo.NotAfter, info.NotAfter)
	}
}

func TestReservedCerts_LoadLegacyTriple(t *testing.T) {
	dir := t.TempDir()
	host := "connect.example.test"
	certPEM, keyPEM, info := mintSelfCert(t, host, time.Now().Add(400*time.Hour))
	seedCache(t, dir, host, certPEM, keyPEM, info) // pre-bundle cert.pem/key.pem/meta.json triple
	rc := &reservedCerts{dir: filepath.Join(dir, "self"), logger: testLogger(), now: time.Now}

	cert, gotInfo, ok := rc.loadCached(host)
	if !ok || cert == nil {
		t.Fatal("a legacy cert.pem/key.pem/meta.json triple must still load")
	}
	if gotInfo.NotAfter.IsZero() {
		t.Fatal("legacy load must recover NotAfter")
	}
}

func TestReservedCerts_CacheLoadLogging(t *testing.T) {
	host := "enroll.example.test"
	tests := []struct {
		name     string
		seed     func(t *testing.T, dir string)
		wantOK   bool
		wantWarn string
	}{
		{name: "missing cache", seed: func(*testing.T, string) {}, wantOK: false},
		{name: "corrupt bundle", seed: func(t *testing.T, dir string) {
			hd := filepath.Join(dir, "self", host)
			if err := os.MkdirAll(hd, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(hd, "bundle.json"), []byte(`{"cert_pem":`), 0o600); err != nil {
				t.Fatal(err)
			}
		}, wantOK: false, wantWarn: "reserved-host cert bundle unparseable"},
		{name: "corrupt legacy meta", seed: func(t *testing.T, dir string) {
			certPEM, keyPEM, info := mintSelfCert(t, host, time.Now().Add(400*time.Hour))
			seedCache(t, dir, host, certPEM, keyPEM, info)
			if err := os.WriteFile(filepath.Join(dir, "self", host, "meta.json"), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, wantOK: true, wantWarn: "reserved-host legacy meta unparseable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.seed(t, dir)
			var buf syncBuffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			rc := &reservedCerts{dir: filepath.Join(dir, "self"), logger: logger, now: time.Now}
			cert, info, ok := rc.loadCached(host)
			if ok != tc.wantOK || (ok && (cert == nil || info.NotAfter.IsZero())) {
				t.Fatalf("loadCached ok=%v cert=%v NotAfter=%v, want ok=%v", ok, cert != nil, info.NotAfter, tc.wantOK)
			}
			warned := strings.Contains(buf.String(), "level=WARN")
			if tc.wantWarn == "" && warned {
				t.Fatalf("a missing cache must not warn; log = %q", buf.String())
			}
			if tc.wantWarn != "" && (!warned || !strings.Contains(buf.String(), tc.wantWarn)) {
				t.Fatalf("want a Warn %q; log = %q", tc.wantWarn, buf.String())
			}
		})
	}
}

func TestReservedCerts_CorruptBundleTreatedAbsent(t *testing.T) {
	dir := t.TempDir()
	host := "enroll.example.test"
	hd := filepath.Join(dir, "self", host)
	if err := os.MkdirAll(hd, 0o700); err != nil {
		t.Fatal(err)
	}
	// A truncated bundle.json with no legacy fallback must report absent, never crash.
	if err := os.WriteFile(filepath.Join(hd, "bundle.json"), []byte(`{"cert_pem":"---BEGIN`), 0o600); err != nil {
		t.Fatal(err)
	}
	rc := &reservedCerts{dir: filepath.Join(dir, "self"), logger: testLogger(), now: time.Now}

	if _, _, ok := rc.loadCached(host); ok {
		t.Fatal("a corrupt bundle.json with no legacy fallback must report absent")
	}
}
