package enroll

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ca"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

var errInjected = errors.New("injected failure")

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureLogger() (*slog.Logger, *syncBuffer) {
	buf := &syncBuffer{}
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

type faultyNames struct {
	*tunneltest.Store
	gets   atomic.Int64
	getErr func(call int64) error
}

func (f *faultyNames) GetName(ctx context.Context, name string) (store.NameRecord, error) {
	if err := f.getErr(f.gets.Add(1)); err != nil {
		return store.NameRecord{}, err
	}
	return f.Store.GetName(ctx, name)
}

func newLoggedService(t *testing.T, names NameStore, ev EvidenceStore) (*Service, *syncBuffer, *x509.CertificateRequest) {
	t.Helper()
	logger, buf := captureLogger()
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: names, Evidence: ev, TunnelDomain: "example.test", Logger: logger,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{ca: "letsencrypt"},
	})
	return svc, buf, idCSR
}

func TestClaimName_ReadFailuresAreLoggedAndJoined(t *testing.T) {
	names := &faultyNames{Store: tunneltest.NewStore(), getErr: func(int64) error { return errInjected }}
	svc, buf, _ := newLoggedService(t, names, names.Store)
	_, err := svc.claimName(context.Background(), store.NameRecord{})
	if !errors.Is(err, errClaimLost) || !errors.Is(err, errInjected) {
		t.Fatalf("claimName = %v, want errClaimLost joined with the last read error", err)
	}
	if !strings.Contains(buf.String(), `msg="name claim read failed (trying another name)"`) {
		t.Fatalf("each failed candidate read must be logged; log = %q", buf.String())
	}
}

func TestEnroll_ClaimFailureLoggedAsUnavailable(t *testing.T) {
	names := &faultyNames{Store: tunneltest.NewStore(), getErr: func(int64) error { return errInjected }}
	svc, buf, idCSR := newLoggedService(t, names, names.Store)
	_, ee := svc.Enroll(context.Background(), "1.2.3.4", Request{Nonce: mintNonce(t, svc), IdentityCSR: idCSR})
	if ee == nil || ee.Reason != "name_unavailable" || !ee.Retryable {
		t.Fatalf("Enroll = %+v, want a retryable name_unavailable", ee)
	}
	if !strings.Contains(buf.String(), `msg="enrollment name claim failed" ip=1.2.3.4`) {
		t.Fatalf("the failed claim must be logged; log = %q", buf.String())
	}
}

func TestClaimName_WriteFailureLoggedAndRedrawn(t *testing.T) {
	st := tunneltest.NewStore()
	st.FailNextPut = errInjected
	svc, buf, _ := newLoggedService(t, st, st)
	name, err := svc.claimName(context.Background(), store.NameRecord{})
	if err != nil || name == "" {
		t.Fatalf("claimName = (%q, %v), want a claim on the next candidate", name, err)
	}
	if !strings.Contains(buf.String(), `msg="name claim write failed (name abandoned)"`) {
		t.Fatalf("the abandoned candidate must be logged; log = %q", buf.String())
	}
}

type failingPutNames struct{ *tunneltest.Store }

func (failingPutNames) PutName(context.Context, string, store.NameRecord) error { return errInjected }

func TestClaimName_WriteFailuresAreJoined(t *testing.T) {
	t.Parallel()
	names := failingPutNames{Store: tunneltest.NewStore()}
	svc, buf, _ := newLoggedService(t, names, names.Store)
	_, err := svc.claimName(context.Background(), store.NameRecord{})
	if !errors.Is(err, errClaimLost) || !errors.Is(err, errInjected) || !strings.Contains(err.Error(), "enroll: claim write") {
		t.Fatalf("claimName = %v, want errClaimLost joined with the wrapped write error", err)
	}
	if strings.Count(buf.String(), `msg="name claim write failed (name abandoned)"`) != 8 {
		t.Fatalf("every abandoned candidate must be logged; log = %q", buf.String())
	}
}

func TestService_LogSignError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantLog bool
	}{
		{name: "signing failure", err: errInjected, wantLog: true},
		{name: "unsupported key is the phone's error", err: ca.ErrUnsupportedKeyType},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger, buf := captureLogger()
			svc := &Service{logger: logger}
			svc.logSignError("n", "1.2.3.4", tc.err)
			logged := strings.Contains(buf.String(), `level=ERROR msg="identity certificate signing failed" tunnel=n ip=1.2.3.4`)
			if logged != tc.wantLog {
				t.Fatalf("logged = %v, want %v; log = %q", logged, tc.wantLog, buf.String())
			}
		})
	}
}

func TestIssue_FailuresAreLogged(t *testing.T) {
	tests := []struct {
		name       string
		failCmd    string
		failGetAt  int64
		wantReason string
		want       string
	}{
		{name: "nonce consume fails", failCmd: "del", wantReason: "internal", want: `msg="issuance nonce consume failed"`},
		{name: "name record read fails", failGetAt: 1, wantReason: "internal", want: `msg="issuance name record read failed"`},
		{name: "issuance lock acquire fails", failCmd: "set", wantReason: "internal", want: `msg="issuance lock or cap check failed"`},
		{name: "record re-read fails", failGetAt: 2, want: `msg="name record re-read failed (using the record read earlier)"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var armed atomic.Bool
			var base atomic.Int64
			names := &faultyNames{Store: tunneltest.NewStore()}
			names.getErr = func(call int64) error {
				if armed.Load() && tc.failGetAt > 0 && call-base.Load() == tc.failGetAt {
					return errInjected
				}
				return nil
			}
			svc, buf, idCSR := newLoggedService(t, names, names.Store)
			name := doEnroll(t, svc, idCSR)
			nonce := mintNonce(t, svc)
			if tc.failCmd != "" {
				svc.rdb.AddHook(tunneltest.FailCommands(errInjected, tc.failCmd))
			}
			base.Store(names.gets.Load())
			armed.Store(true)
			_, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{
				Nonce: nonce, IdentityCSR: idCSR, TLSCSR: newTLSCSR(t, name+".example.test"),
			})
			switch {
			case tc.wantReason == "" && ee != nil:
				t.Fatalf("Issue must still succeed, got %+v", ee)
			case tc.wantReason != "" && (ee == nil || ee.Reason != tc.wantReason || !ee.Retryable):
				t.Fatalf("Issue = %+v, want a retryable %q", ee, tc.wantReason)
			}
			if !strings.Contains(buf.String(), tc.want) || !strings.Contains(buf.String(), errInjected.Error()) {
				t.Fatalf("the failure must be logged with its cause; log = %q", buf.String())
			}
		})
	}
}

func TestClaimName_CancelledCallerIsSilent(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(*faultyNames)
		preCancel bool
	}{
		{name: "lock fails", preCancel: true, setup: func(n *faultyNames) {
			n.getErr = func(int64) error { return nil }
		}},
		{name: "read fails", setup: func(n *faultyNames) {
			n.getErr = func(int64) error { return context.Canceled }
		}},
		{name: "write fails", setup: func(n *faultyNames) {
			n.getErr = func(int64) error { return nil }
			n.FailNextPut = context.Canceled
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			names := &faultyNames{Store: tunneltest.NewStore()}
			tc.setup(names)
			svc, buf, _ := newLoggedService(t, names, names.Store)
			ctx, cancel := context.WithCancel(context.Background())
			if tc.preCancel {
				cancel()
			} else {
				svc.rdb.AddHook(tunneltest.CancelAfter("set", cancel))
			}
			if _, err := svc.claimName(ctx, store.NameRecord{}); err == nil {
				t.Fatal("a cancelled caller must not claim a name")
			}
			if strings.Contains(buf.String(), "name claim") {
				t.Fatalf("a claim failure caused by the caller's cancellation must not be logged; log = %q", buf.String())
			}
			if names.NameCount() != 0 {
				t.Fatal("no name may be written for a cancelled caller")
			}
		})
	}
}

func TestEnrollIssue_CancelledCallerIsSilent(t *testing.T) {
	tests := []struct {
		name    string
		enroll  bool
		prepare func(svc *Service, names *faultyNames, cancel context.CancelFunc)
	}{
		{name: "enroll name claim", enroll: true, prepare: func(svc *Service, names *faultyNames, cancel context.CancelFunc) {
			names.getErr = func(int64) error { return context.Canceled }
			svc.rdb.AddHook(tunneltest.CancelAfter("del", cancel))
		}},
		{name: "issuance nonce consume", prepare: func(svc *Service, _ *faultyNames, cancel context.CancelFunc) {
			cancel()
			svc.rdb.AddHook(tunneltest.FailCommands(context.Canceled, "del"))
		}},
		{name: "issuance name record read", prepare: func(svc *Service, names *faultyNames, cancel context.CancelFunc) {
			names.getErr = func(int64) error { return context.Canceled }
			svc.rdb.AddHook(tunneltest.CancelAfter("del", cancel))
		}},
		{name: "issuance lock acquire", prepare: func(svc *Service, _ *faultyNames, cancel context.CancelFunc) {
			svc.rdb.AddHook(tunneltest.CancelAfter("del", cancel))
			svc.rdb.AddHook(tunneltest.FailCommands(context.Canceled, "set"))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			names := &faultyNames{Store: tunneltest.NewStore(), getErr: func(int64) error { return nil }}
			svc, buf, idCSR := newLoggedService(t, names, names.Store)
			name := ""
			if !tc.enroll {
				name = doEnroll(t, svc, idCSR)
			}
			nonce := mintNonce(t, svc)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tc.prepare(svc, names, cancel)
			var ee *Error
			if tc.enroll {
				_, ee = svc.Enroll(ctx, "1.2.3.4", Request{Nonce: nonce, IdentityCSR: idCSR})
			} else {
				_, ee = svc.Issue(ctx, name, "1.2.3.4", Request{
					Nonce: nonce, IdentityCSR: idCSR, TLSCSR: newTLSCSR(t, name+".example.test"),
				})
			}
			want := "internal"
			if tc.enroll {
				want = "name_unavailable"
			}
			if ee == nil || ee.Reason != want || !ee.Retryable {
				t.Fatalf("the cancelled request must fail as a retryable %q, got %+v", want, ee)
			}
			if strings.Contains(buf.String(), "level=WARN") {
				t.Fatalf("a failure caused by the caller's cancellation must not be logged at Warn; log = %q", buf.String())
			}
		})
	}
}

func TestRecordCert_CancelledReReadIsSilent(t *testing.T) {
	names := &faultyNames{Store: tunneltest.NewStore(), getErr: func(int64) error { return context.Canceled }}
	svc, buf, idCSR := newLoggedService(t, names, names.Store)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	enrolled := time.Unix(1000, 0).UTC()
	svc.recordCert(ctx, "n", store.NameRecord{Schema: 1, EnrolledAt: enrolled}, Request{IdentityCSR: idCSR},
		store.CertInfo{CA: "letsencrypt"}, store.DeviceInfo{})
	if strings.Contains(buf.String(), "name record re-read failed") {
		t.Fatalf("a re-read failure caused by the caller's cancellation must not be logged; log = %q", buf.String())
	}
	rec, err := names.Store.GetName(context.Background(), "n")
	if err != nil || !rec.EnrolledAt.Equal(enrolled) || rec.CA != "letsencrypt" {
		t.Fatalf("the record must still be written from the earlier read: %+v %v", rec, err)
	}
}

func TestRecordRejection_LogsUnparseableClaimedIdentity(t *testing.T) {
	st := tunneltest.NewStore()
	svc, buf, _ := newLoggedService(t, st, st)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: bigOne(), Subject: pkix.Name{CommonName: "no-attestation"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	svc.recordRejection(context.Background(), "1.2.3.4", "", "attest-untrusted", Request{AttestChain: []*x509.Certificate{leaf}})
	if !strings.Contains(buf.String(), `msg="rejected-enrollment claimed identity unparseable (recorded empty)" reason=attest-untrusted src_ip=1.2.3.4`) {
		t.Fatalf("the unparseable KeyDescription must be logged; log = %q", buf.String())
	}
	if len(st.Rejected) != 1 || st.Rejected[0].ClaimedPackage != "" || st.Rejected[0].SignerDigestHex != "" {
		t.Fatalf("the evidence must still be recorded with empty claimed fields: %+v", st.Rejected)
	}
}

func TestService_StepTimingsLoggedAtDebug(t *testing.T) {
	t.Parallel()
	st := tunneltest.NewStore()
	svc, buf, idCSR := newLoggedService(t, st, st)
	h := newTestHandler(t, svc, nil)
	b, err := json.Marshal(enrollRequestBody{Nonce: hexEncode(mintNonce(t, svc)), IdentityCSR: csrPEM(t, idCSR)})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/v1/enroll", bytes.NewReader(b))
	req.RemoteAddr = "203.0.113.18:5000"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("enroll failed: %d %s", rr.Code, rr.Body.String())
	}
	var resp enrollResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if _, ee := svc.Issue(context.Background(), resp.Name, "203.0.113.18", Request{
		Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: newTLSCSR(t, resp.Name+".example.test"),
	}); ee != nil {
		t.Fatalf("issue failed: %v", ee)
	}

	var want []string
	for _, s := range []string{"limit-check", "issue-nonce", "limit", "nonce", "attest", "claim-lock", "claim-get",
		"claim-put", "claim", "sign"} {
		want = append(want, `level=DEBUG msg="enroll step" step=`+s+" took=")
	}
	for _, s := range []string{"nonce", "attest", "registry-read", "issuance-lock", "sign", "acme", "issuance-record",
		"registry-write", "issuance-unlock"} {
		want = append(want, `level=DEBUG msg="issue step" step=`+s+" took=")
	}
	log := buf.String()
	at := 0
	for _, w := range want {
		i := strings.Index(log[at:], w)
		if i < 0 {
			t.Fatalf("missing (or out of order) %q after offset %d; log = %q", w, at, log)
		}
		at += i + len(w)
	}
	if !strings.Contains(log, `step=acme took=0s tunnel=`+resp.Name+` ip=203.0.113.18 ca=letsencrypt`) {
		t.Errorf("the acme step must carry the tunnel, ip and issuing CA; log = %q", log)
	}
}

func TestClaimName_LockFailuresAreLoggedAndJoined(t *testing.T) {
	t.Parallel()
	st := tunneltest.NewStore()
	logger, buf := captureLogger()
	svc, mr := newService(t, Config{Names: st, Logger: logger})
	mr.SetError("ERR injected")
	_, err := svc.claimName(context.Background(), store.NameRecord{})
	if !errors.Is(err, errClaimLost) || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("claimName = %v, want errClaimLost joined with the lock error", err)
	}
	if !strings.Contains(buf.String(), `msg="name claim lock failed (trying another name)"`) {
		t.Fatalf("each failed lock must be logged; log = %q", buf.String())
	}
	if st.NameCount() != 0 {
		t.Fatal("no name may be written without its lock")
	}
}

type clockedNames struct {
	*tunneltest.Store
	mu       *sync.Mutex
	now      *time.Time
	get, put time.Duration
}

func (c *clockedNames) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	*c.now = c.now.Add(d)
}

func (c *clockedNames) GetName(ctx context.Context, name string) (store.NameRecord, error) {
	c.advance(c.get)
	return c.Store.GetName(ctx, name)
}

func (c *clockedNames) PutName(ctx context.Context, name string, rec store.NameRecord) error {
	c.advance(c.put)
	return c.Store.PutName(ctx, name, rec)
}

func TestClaimName_StepTimingsArePerStep(t *testing.T) {
	t.Parallel()
	logger, buf := captureLogger()
	var mu sync.Mutex
	clk := time.Unix(1_700_000_000, 0)
	names := &clockedNames{Store: tunneltest.NewStore(), mu: &mu, now: &clk, get: 2 * time.Second, put: 3 * time.Second}
	svc, _ := newService(t, Config{Names: names, Logger: logger})
	svc.SetClock(func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return clk
	})
	if _, err := svc.claimName(context.Background(), store.NameRecord{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"step=claim-lock took=0s", "step=claim-get took=2s", "step=claim-put took=3s"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("missing %q (each step's own duration); log = %q", want, buf.String())
		}
	}
}

func TestClaimName_OneDeadlineCoversReadAndWrite(t *testing.T) {
	t.Parallel()
	const timeout = 2 * time.Second
	names := &deadlineNames{Store: tunneltest.NewStore(), getDelay: 50 * time.Millisecond}
	svc, _ := newService(t, Config{Names: names, ClaimTimeout: timeout, ClaimSettle: 5 * time.Second})
	svc.rdb.AddHook(names)
	before := time.Now()
	if _, err := svc.claimName(context.Background(), store.NameRecord{}); err != nil {
		t.Fatal(err)
	}
	names.mu.Lock()
	defer names.mu.Unlock()
	if names.getDL.IsZero() || !names.setDL.Equal(names.getDL) || !names.getDL.Equal(names.putDL) {
		t.Fatalf("the lock, the read and the PUT must share one claim deadline: set %v get %v put %v", names.setDL, names.getDL, names.putDL)
	}
	if names.putDL.Before(before.Add(timeout)) || names.putDL.After(names.getAt.Add(timeout)) {
		t.Fatalf("the claim deadline %v must start before the lock and the read: want within [%v, %v]",
			names.putDL, before.Add(timeout), names.getAt.Add(timeout))
	}
}

type deadlineNames struct {
	*tunneltest.Store
	getDelay            time.Duration
	mu                  sync.Mutex
	getAt               time.Time
	setDL, getDL, putDL time.Time
}

func (d *deadlineNames) DialHook(next redis.DialHook) redis.DialHook { return next }

func (d *deadlineNames) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "set" {
			dl, _ := ctx.Deadline()
			d.mu.Lock()
			d.setDL = dl
			d.mu.Unlock()
		}
		return next(ctx, cmd)
	}
}

func (d *deadlineNames) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func (d *deadlineNames) GetName(ctx context.Context, name string) (store.NameRecord, error) {
	dl, _ := ctx.Deadline()
	d.mu.Lock()
	d.getAt, d.getDL = time.Now(), dl
	d.mu.Unlock()
	time.Sleep(d.getDelay)
	return d.Store.GetName(ctx, name)
}

func (d *deadlineNames) PutName(ctx context.Context, name string, rec store.NameRecord) error {
	dl, _ := ctx.Deadline()
	d.mu.Lock()
	d.putDL = dl
	d.mu.Unlock()
	return d.Store.PutName(ctx, name, rec)
}
