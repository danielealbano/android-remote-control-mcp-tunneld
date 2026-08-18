package enroll

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/attest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ca"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/observ"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// ClassifiedIssuerError lets an issuer error carry its class + retry hint WITHOUT the enroll package
// importing internal/acme (the acme error type implements this interface).
type ClassifiedIssuerError interface {
	error
	IssuerClass() string // "rate-limited" | "transient" | "permanent"
	RetryAfter() time.Duration
}

// PublicIssuer is the consumer-side view of the ACME chain (implemented by internal/acme). Obtain
// runs the initial LE→GTS→ZeroSSL spillover; Renew renews an existing name using the same LE-first order,
// so every renewal opportunistically migrates the name to LE.
type PublicIssuer interface {
	Obtain(ctx context.Context, csr *x509.CertificateRequest, name string) (pemChain []byte, info store.CertInfo, err error)
	Renew(ctx context.Context, csr *x509.CertificateRequest, name string, cur store.CertInfo) (pemChain []byte, info store.CertInfo, err error)
}

// Verifier is the consumer-side view of the attestation verifier (implemented by internal/attest).
type Verifier interface {
	Verify(chain []*x509.Certificate, nonce []byte, now time.Time) (attest.Result, error)
}

// NameStore is the registry surface the enroll service needs.
type NameStore = store.NameStore

// EvidenceStore persists rejected-enrollment evidence.
type EvidenceStore = store.EvidenceStore

// Request carries the submitted material for enrollment (Phase 1) or issuance (Phase 2 / renewal). Phase
// 1 (Enroll) uses everything except TLSCSR; issuance (Issue) uses all of it.
type Request struct {
	Nonce          []byte
	AttestChainPEM []byte // raw submitted chain (retained on rejection)
	AttestChain    []*x509.Certificate
	IdentityCSR    *x509.CertificateRequest
	TLSCSR         *x509.CertificateRequest // Phase 2 (Issue) only — the public-cert CSR (SAN=<name>.<tunnel-domain>)
}

// Result is a successful enrollment/renewal.
type Result struct {
	Name         string
	IdentityCert []byte
	PublicCert   []byte
	CA           string
}

// Error is a structured, user-facing enrollment error (implements error).
type Error struct {
	Reason     string
	Retryable  bool
	RetryAfter time.Duration
}

func (e *Error) Error() string { return "enroll: " + e.Reason }

// Config wires the Service (constructor DI).
type Config struct {
	RDB            redis.UniversalClient
	CA             *ca.CA
	Names          NameStore
	Evidence       EvidenceStore
	Verifier       Verifier
	Limiter        *limit.Limiter
	Issuer         PublicIssuer
	TunnelDomain   string // base domain: the public cert is issued for <name>.<TunnelDomain>
	NamePrefix     string
	NameLength     int
	ExtraReserved  []string // firstLabel(--enroll-host), firstLabel(--control-host)
	IssuePerWeek   int
	EnrollHour     int
	EnrollMinute   int
	ClaimTimeout   time.Duration
	ClaimSettle    time.Duration
	AttestOptional bool
	Recorder       observ.Recorder // rejection/attestation metrics (defaults to observ.Nop)
	Logger         *slog.Logger    // best-effort store-write failures are LOGGED, never swallowed
}

// Service runs the enrollment flow.
type Service struct {
	cfg     Config
	rdb     redis.UniversalClient
	rec     observ.Recorder
	logger  *slog.Logger
	now     func() time.Time
	sleep   func(time.Duration)
	nameGen func() (string, error)
}

// NewService builds the enrollment service (injectable clock/sleep for tests).
func NewService(cfg Config) *Service {
	s := &Service{cfg: cfg, rdb: cfg.RDB, rec: cfg.Recorder, logger: cfg.Logger, now: time.Now, sleep: time.Sleep}
	if s.rec == nil {
		s.rec = observ.Nop{}
	}
	if s.logger == nil {
		s.logger = slog.New(slog.DiscardHandler)
	}
	s.nameGen = func() (string, error) {
		return ca.GenerateName(s.cfg.NamePrefix, s.cfg.NameLength, s.cfg.ExtraReserved...)
	}
	return s
}

// SetClock overrides the clock+sleep (tests only): the settle wait becomes instant.
func (s *Service) SetClock(now func() time.Time) {
	s.now = now
	s.sleep = func(time.Duration) {}
}

// SetNameGen overrides the candidate-name generator (tests only): used to force a name collision in the
// write-verify claim race. Default is ca.GenerateName with the configured prefix/length/reserved set.
func (s *Service) SetNameGen(f func() (string, error)) { s.nameGen = f }

var errClaimLost = errors.New("enroll: claim lost")

// Enroll runs PHASE 1: attestation + key binding → generate + write-verify-claim a fresh name → sign the
// bootstrap identity (mTLS) cert. It issues NO public cert and takes NO TLS CSR; the phone then reaches
// the mTLS POST /issue endpoint (see Issue) to regenerate its identity and obtain the public WebPKI cert
// for <name>.<tunnel-domain>. Any post-claim failure rolls the freshly claimed name back (plain
// DeleteName, safe only because the claim was verified).
func (s *Service) Enroll(ctx context.Context, ip string, req Request) (Result, *Error) {
	if e := s.enrollLimit(ctx, ip); e != nil {
		return Result{}, e
	}

	// Consume + validate the single-use nonce.
	if ok, err := s.consumeNonce(ctx, req.Nonce); err != nil || !ok {
		return Result{}, &Error{Reason: "invalid_nonce", Retryable: true}
	}

	// Attestation gate (skipped only in the fail-closed test-only optional mode) + key binding.
	att, e := s.attestAndBind(ctx, ip, req)
	if e != nil {
		return Result{}, e
	}

	// Generate + write-verify-claim a fresh name.
	name, claimNonce, err := s.claimName(ctx)
	if err != nil {
		return Result{}, &Error{Reason: "name_unavailable", Retryable: true}
	}

	// Bootstrap identity cert (CN = the server-assigned name; the CSR subject is ignored).
	identityPEM, err := s.cfg.CA.SignIdentity(req.IdentityCSR, name)
	if err != nil {
		s.rollback(ctx, true, name)
		return Result{}, signError(err)
	}

	s.recordIdentity(ctx, name, claimNonce, req, att.Device)
	return Result{Name: name, IdentityCert: identityPEM}, nil
}

// Issue runs PHASE 2 (and every renewal): for an already-enrolled, mTLS-authenticated tunnel (name from
// the client-cert CN), it re-verifies the seven-point attestation on a FRESH chain over the nonce,
// rebinds + rotates the identity cert, and obtains (first public cert) or renews (subsequent) the public
// WebPKI cert for <name>.<tunnel-domain>. It regenerates the identity + public certs TOGETHER.
func (s *Service) Issue(ctx context.Context, name, ip string, req Request) (Result, *Error) {
	if ok, err := s.consumeNonce(ctx, req.Nonce); err != nil || !ok {
		return Result{}, &Error{Reason: "invalid_nonce", Retryable: true}
	}
	att, e := s.attestAndBind(ctx, ip, req)
	if e != nil {
		return Result{}, e
	}
	// Proof-of-possession of the TLS key + the server-dictated public identity: the TLS CSR MUST verify
	// and MUST request exactly <name>.<tunnel-domain>.
	if err := req.TLSCSR.CheckSignature(); err != nil {
		s.recordRejection(ctx, ip, "csr-mismatch", req)
		return Result{}, &Error{Reason: "unauthorized"}
	}
	if !csrMatchesTunnel(req.TLSCSR, name, s.cfg.TunnelDomain) {
		s.rec.Reject("csr-mismatch", name, ip)
		return Result{}, &Error{Reason: "csr_domain_mismatch"}
	}

	// The tunnel MUST already be enrolled (Phase 1 wrote the claim record). Only a definitive
	// not-found is name_unknown; a transient store error is retryable, never a permanent-looking 400.
	cur, err := s.cfg.Names.GetName(ctx, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Result{}, &Error{Reason: "name_unknown"}
		}
		return Result{}, &Error{Reason: "internal", Retryable: true}
	}

	// Issuance read-only cap (keyed on the name).
	allowed, err := s.cfg.Limiter.IssuanceAllowed(ctx, name, s.cfg.IssuePerWeek)
	if err != nil {
		return Result{}, &Error{Reason: "internal", Retryable: true}
	}
	if !allowed {
		s.rec.Reject("issuance-cap", name, ip)
		return Result{}, &Error{Reason: "issuance_cap", Retryable: true, RetryAfter: 7 * 24 * time.Hour}
	}

	// Rotate the identity cert (CN = the server-assigned name; CSR subject ignored).
	identityPEM, err := s.cfg.CA.SignIdentity(req.IdentityCSR, name)
	if err != nil {
		return Result{}, signError(err)
	}

	// Public cert: Obtain on the FIRST issuance for this name (full spillover), Renew afterwards
	// (LE-first opportunistic migration).
	var (
		pubChain []byte
		info     store.CertInfo
	)
	renewal := cur.CA != ""
	if renewal {
		pubChain, info, err = s.cfg.Issuer.Renew(ctx, req.TLSCSR, name, cur.CertInfo())
	} else {
		pubChain, info, err = s.cfg.Issuer.Obtain(ctx, req.TLSCSR, name)
	}
	if err != nil {
		s.rec.Reject("acme-failed", name, ip)
		if renewal {
			s.rec.ACMERenew("all", "fail")
		}
		return Result{}, classifyIssuerError(err)
	}
	if renewal {
		s.rec.ACMERenew(info.CA, "ok")
	}

	// Count this SUCCESSFUL issuance, then LWW-record the cert metadata (preserving the claim nonce).
	if err := s.cfg.Limiter.IssuanceRecord(ctx, name); err != nil {
		// Non-fatal: the cert is issued; the counter is best-effort here — but never silent.
		s.logger.Warn("issuance counter record failed", "tunnel", name, "err", err)
	}
	s.recordCert(ctx, name, req, info, att.Device)

	return Result{Name: name, IdentityCert: identityPEM, PublicCert: pubChain, CA: info.CA}, nil
}

// attestAndBind runs the seven-point attestation gate (skipped only in the fail-closed test-only optional
// mode) and the identity-key binding + CSR proof-of-possession: the identity CSR signature MUST verify
// and — when attestation ran — the identity key MUST equal the attested TEE key (closes the software-key
// bypass). On any failure it records rejection evidence + the rejection metric and returns an
// unauthorized error; on success it returns the attestation result (device scalars + attested key).
func (s *Service) attestAndBind(ctx context.Context, ip string, req Request) (attest.Result, *Error) {
	var att attest.Result
	if !s.cfg.AttestOptional {
		res, err := s.cfg.Verifier.Verify(req.AttestChain, req.Nonce, s.now())
		if err != nil {
			s.rec.AttestVerify(attestReason(err))
			s.recordRejection(ctx, ip, attestReason(err), req)
			return attest.Result{}, &Error{Reason: "unauthorized"}
		}
		s.rec.AttestVerify("ok")
		att = res
	}
	if err := req.IdentityCSR.CheckSignature(); err != nil {
		s.recordRejection(ctx, ip, "csr-mismatch", req)
		return attest.Result{}, &Error{Reason: "unauthorized"}
	}
	if att.LeafPublicKey != nil && !publicKeyEqual(req.IdentityCSR.PublicKey, att.LeafPublicKey) {
		s.recordRejection(ctx, ip, "csr-mismatch", req)
		return attest.Result{}, &Error{Reason: "unauthorized"}
	}
	return att, nil
}

// signError maps a SignIdentity failure to its structured reason (a non-P256 key is the phone's error,
// distinct from an internal signing failure).
func signError(err error) *Error {
	if errors.Is(err, ca.ErrUnsupportedKeyType) {
		return &Error{Reason: "unsupported_key_type"}
	}
	return &Error{Reason: "identity_sign_failed"}
}

// csrMatchesTunnel reports whether csr requests exactly <name>.<tunnelDomain> (CN or a SAN).
func csrMatchesTunnel(csr *x509.CertificateRequest, name, tunnelDomain string) bool {
	want := name + "." + tunnelDomain
	if csr.Subject.CommonName == want {
		return true
	}
	for _, d := range csr.DNSNames {
		if d == want {
			return true
		}
	}
	return false
}

// claimName runs the write-verify claim protocol over PLAIN S3 (no conditional writes): per candidate,
// GET (exists → new name) → PUT with a fresh claim_nonce under the claim-timeout deadline (SDK retries
// disabled; timeout = abandon this name permanently) → wait settle (strictly > timeout) → GET-verify
// the nonce. Bounded loop.
func (s *Service) claimName(ctx context.Context) (name, claimNonce string, err error) {
	for attempt := 0; attempt < 8; attempt++ {
		cand, err := s.nameGen()
		if err != nil {
			return "", "", err
		}
		// GET: if it already exists, draw a new name.
		if _, err := s.cfg.Names.GetName(ctx, cand); err == nil {
			continue
		} else if !errors.Is(err, store.ErrNotFound) {
			continue // transient — try a different name
		}

		nonce := newClaimNonce()
		rec := store.NameRecord{Schema: 1, EnrolledAt: s.now().UTC(), LastRenewedAt: s.now().UTC(), ClaimNonce: nonce}

		putCtx, cancel := context.WithTimeout(ctx, s.cfg.ClaimTimeout)
		putErr := s.cfg.Names.PutName(putCtx, cand, rec)
		cancel()
		if putErr != nil {
			// Timeout/error: abandon this name PERMANENTLY (a retried PUT would be a zombie write).
			continue
		}

		// Settle wait (strictly > the PUT timeout) so any zombie PUT has landed or died.
		s.sleep(s.cfg.ClaimSettle)

		got, err := s.cfg.Names.GetName(ctx, cand)
		if err != nil {
			continue // our PUT was lost — new name
		}
		if got.ClaimNonce == nonce {
			return cand, nonce, nil // we won
		}
		// Lost the race — new name.
	}
	return "", "", errClaimLost
}

func (s *Service) rollback(ctx context.Context, initial bool, name string) {
	if initial {
		_ = s.cfg.Names.DeleteName(ctx, name) // plain delete; safe only after a verified claim
	}
}

// recordIdentity writes the Phase-1 registry record (name claimed, bootstrap identity signed, attested
// device scalars) preserving the claim nonce, with NO cert info yet (the public cert lands at Issue).
// Best-effort: the claimName PUT already created the record; a failure is logged, never silent.
func (s *Service) recordIdentity(ctx context.Context, name, claimNonce string, req Request, dev store.DeviceInfo) {
	rec := store.NameRecord{
		Schema: 1, EnrolledAt: s.now().UTC(), LastRenewedAt: s.now().UTC(), ClaimNonce: claimNonce,
		Device: dev,
	}
	if req.IdentityCSR != nil {
		rec.IdentityKeyFP = keyFingerprint(req.IdentityCSR.PublicKey)
	}
	if err := s.cfg.Names.PutName(ctx, name, rec); err != nil {
		s.logger.Warn("registry identity record write failed", "tunnel", name, "err", err)
	}
}

// recordCert LWW-updates the registry record with the issued cert + rotated identity-key fingerprint +
// the freshly-attested device scalars, preserving the claim nonce. A failure here is non-fatal (the
// certs are issued and the next Issue's LWW refreshes it) but logged, never silent.
func (s *Service) recordCert(ctx context.Context, name string, req Request, info store.CertInfo, dev store.DeviceInfo) {
	rec, err := s.cfg.Names.GetName(ctx, name)
	if err != nil {
		rec = store.NameRecord{Schema: 1, EnrolledAt: s.now().UTC()}
	}
	rec.Schema = 1
	rec.LastRenewedAt = s.now().UTC()
	if rec.EnrolledAt.IsZero() {
		rec.EnrolledAt = s.now().UTC()
	}
	if req.IdentityCSR != nil {
		rec.IdentityKeyFP = keyFingerprint(req.IdentityCSR.PublicKey)
	}
	if dev != (store.DeviceInfo{}) {
		rec.Device = dev // refresh from the renewal's fresh attestation; keep prior when attestation was optional
	}
	rec.SetCert(info)
	if err := s.cfg.Names.PutName(ctx, name, rec); err != nil {
		s.logger.Warn("registry cert record write failed", "tunnel", name, "err", err)
	}
}

// recordRejection bumps the rejection metric (reason is an observ.RejectReasons label) and persists the
// rejected-enrollment evidence (best-effort — a store failure is logged and never masks the rejection).
func (s *Service) recordRejection(ctx context.Context, ip, reason string, req Request) {
	s.rec.Reject(reason, "", ip)
	pkg, digest := claimedIdentity(req.AttestChain)
	ev := store.RejectedEnrollment{
		TS:              s.now().UTC(),
		SrcIP:           ip,
		Reason:          reason,
		AttestChainPEM:  string(req.AttestChainPEM),
		ClaimedPackage:  pkg,
		SignerDigestHex: digest,
		NonceHex:        hex.EncodeToString(req.Nonce),
	}
	if s.cfg.Evidence != nil {
		if err := s.cfg.Evidence.PutRejectedEnrollment(ctx, ev); err != nil {
			s.logger.Warn("rejected-enrollment evidence write failed", "reason", reason, "src_ip", ip, "err", err)
		}
	}
}

func (s *Service) enrollLimit(ctx context.Context, ip string) *Error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return &Error{Reason: "bad_source_ip"}
	}
	okMin, ra, err := limit.Allow(ctx, s.rdb, "enroll-min", addr, s.cfg.EnrollMinute, time.Minute)
	if err == nil && !okMin {
		s.rec.Reject("enroll-limit", "", ip)
		return &Error{Reason: "enroll_rate", Retryable: true, RetryAfter: ra}
	}
	okHour, ra, err := limit.Allow(ctx, s.rdb, "enroll-hour", addr, s.cfg.EnrollHour, time.Hour)
	if err == nil && !okHour {
		s.rec.Reject("enroll-limit", "", ip)
		return &Error{Reason: "enroll_rate", Retryable: true, RetryAfter: ra}
	}
	return nil
}

// enrollLimitCheck is the READ-ONLY pre-gate: it reports whether ip is already at either enroll
// window's limit WITHOUT consuming a slot (the handler runs it BEFORE minting the issue nonce, so an
// over-limit caller cannot mint Valkey keys; Enroll's enrollLimit remains the authoritative consume).
// A control-plane error fails open — the authoritative check still runs.
func (s *Service) enrollLimitCheck(ctx context.Context, ip string) *Error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return &Error{Reason: "bad_source_ip"}
	}
	overMin, ra, err := limit.Over(ctx, s.rdb, "enroll-min", addr, s.cfg.EnrollMinute, time.Minute)
	if err == nil && overMin {
		s.rec.Reject("enroll-limit", "", ip)
		return &Error{Reason: "enroll_rate", Retryable: true, RetryAfter: ra}
	}
	overHour, ra, err := limit.Over(ctx, s.rdb, "enroll-hour", addr, s.cfg.EnrollHour, time.Hour)
	if err == nil && overHour {
		s.rec.Reject("enroll-limit", "", ip)
		return &Error{Reason: "enroll_rate", Retryable: true, RetryAfter: ra}
	}
	return nil
}

func newClaimNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (it panics internally on a broken source)
	return hex.EncodeToString(b[:])
}

// publicKeyEqual compares two crypto.PublicKey values.
func publicKeyEqual(a, b crypto.PublicKey) bool {
	type equalable interface{ Equal(crypto.PublicKey) bool }
	ea, ok := a.(equalable)
	if !ok {
		return false
	}
	return ea.Equal(b)
}

func keyFingerprint(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// classifyIssuerError maps an ACME/issuer error to a structured user-facing Error, using the
// ClassifiedIssuerError interface so no acme import is needed.
func classifyIssuerError(err error) *Error {
	var ce ClassifiedIssuerError
	if errors.As(err, &ce) {
		switch ce.IssuerClass() {
		case "rate-limited":
			return &Error{Reason: "acme_rate_limited", Retryable: true, RetryAfter: ce.RetryAfter()}
		case "transient":
			return &Error{Reason: "acme_transient", Retryable: true, RetryAfter: time.Minute}
		}
	}
	return &Error{Reason: "acme_failed"}
}

// attestReason maps an attestation sentinel to a rejection label.
func attestReason(err error) string {
	switch {
	case errors.Is(err, attest.ErrChainUntrusted):
		return "attest-untrusted"
	case errors.Is(err, attest.ErrChallengeMismatch):
		return "attest-challenge"
	case errors.Is(err, attest.ErrSignerNotAllowed):
		return "attest-signer"
	case errors.Is(err, attest.ErrSecurityLevel):
		return "attest-security-level"
	case errors.Is(err, attest.ErrBootState):
		return "attest-boot"
	case errors.Is(err, attest.ErrDeviceUnlocked):
		return "attest-device-unlocked"
	case errors.Is(err, attest.ErrRevoked):
		return "attest-revoked"
	case errors.Is(err, attest.ErrStatusStale):
		return "attest-stale"
	default:
		return "attest-untrusted"
	}
}

// claimedIdentity best-effort extracts the claimed package + first signer digest from a submitted
// chain (for rejection evidence), tolerating an unparseable KeyDescription.
func claimedIdentity(chain []*x509.Certificate) (pkg, digestHex string) {
	if len(chain) == 0 {
		return "", ""
	}
	kd, err := attest.ParseKeyDescription(chain[0])
	if err != nil {
		return "", ""
	}
	if len(kd.SignatureDigests) > 0 {
		digestHex = hex.EncodeToString(kd.SignatureDigests[0])
	}
	return kd.Package, digestHex
}
