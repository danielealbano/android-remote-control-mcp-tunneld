package enroll

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	_, _, err := svc.claimName(context.Background())
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
	name, _, err := svc.claimName(context.Background())
	if err != nil || name == "" {
		t.Fatalf("claimName = (%q, %v), want a claim on the next candidate", name, err)
	}
	if !strings.Contains(buf.String(), `msg="name claim write failed (name abandoned)"`) {
		t.Fatalf("the abandoned candidate must be logged; log = %q", buf.String())
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
		{name: "issuance lock acquire fails", failCmd: "set", wantReason: "internal", want: `msg="issuance lock acquire failed"`},
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
		name    string
		setup   func(*faultyNames)
		wantErr bool
	}{
		{name: "read fails", wantErr: true, setup: func(n *faultyNames) {
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
			cancel()
			if _, _, err := svc.claimName(ctx); (err != nil) != tc.wantErr {
				t.Fatalf("claimName error = %v, wantErr %v", err, tc.wantErr)
			}
			if strings.Contains(buf.String(), "name claim") {
				t.Fatalf("a claim failure caused by the caller's cancellation must not be logged; log = %q", buf.String())
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
	svc.recordCert(ctx, "n", store.NameRecord{Schema: 1, ClaimNonce: "c"}, Request{IdentityCSR: idCSR},
		store.CertInfo{CA: "letsencrypt"}, store.DeviceInfo{})
	if strings.Contains(buf.String(), "name record re-read failed") {
		t.Fatalf("a re-read failure caused by the caller's cancellation must not be logged; log = %q", buf.String())
	}
	rec, err := names.Store.GetName(context.Background(), "n")
	if err != nil || rec.ClaimNonce != "c" || rec.CA != "letsencrypt" {
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
