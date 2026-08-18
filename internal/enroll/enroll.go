package enroll

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/netip"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/attest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ca"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// ClassifiedIssuerError lets an issuer error carry its class + retry hint WITHOUT the enroll package
// importing internal/acme (the acme error type implements this interface).
type ClassifiedIssuerError interface {
	error
	IssuerClass() string // "rate-limited" | "transient" | "permanent"
	RetryAfter() time.Duration
}

// PublicIssuer is the consumer-side view of the ACME chain (implemented by internal/acme, US6). Obtain
// runs the initial LE→GTS→ZeroSSL spillover; Renew renews an existing name (opportunistic LE-first
// migration for non-LE names, budget-exempt LE renewal for LE names).
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

// Request is one enrollment/renewal request.
type Request struct {
	Renewal        bool   // false = initial; true = renewal (existing name, over the phone's mTLS control connection)
	Name           string // required iff Renewal
	Nonce          []byte
	AttestChainPEM []byte // raw submitted chain (retained on rejection)
	AttestChain    []*x509.Certificate
	IdentityCSR    *x509.CertificateRequest
	TLSCSR         *x509.CertificateRequest
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
	NamePrefix     string
	NameLength     int
	ExtraReserved  []string // firstLabel(--enroll-host), firstLabel(--control-host)
	IssuePerWeek   int
	EnrollHour     int
	EnrollMinute   int
	ClaimTimeout   time.Duration
	ClaimSettle    time.Duration
	AttestOptional bool
}

// Service runs the enrollment flow.
type Service struct {
	cfg   Config
	rdb   redis.UniversalClient
	now   func() time.Time
	sleep func(time.Duration)
}

// NewService builds the enrollment service (injectable clock/sleep for tests).
func NewService(cfg Config) *Service {
	return &Service{cfg: cfg, rdb: cfg.RDB, now: time.Now, sleep: time.Sleep}
}

// SetClock overrides the clock+sleep (tests only): the settle wait becomes instant.
func (s *Service) SetClock(now func() time.Time) {
	s.now = now
	s.sleep = func(time.Duration) {}
}

var errClaimLost = errors.New("enroll: claim lost")

// Enroll runs the full flow. ORDER matters: attestation + key binding (pre-claim) → name (generate +
// write-verify claim on INITIAL / existing on RENEWAL) → issuance read-only check → identity cert →
// public cert → record issuance on success. Any post-claim failure of an INITIAL enrollment rolls the
// name back (plain DeleteName, safe only because the claim was verified).
func (s *Service) Enroll(ctx context.Context, ip string, req Request) (Result, *Error) {
	// Per-IP enroll limit — INITIAL only (renewal is already authenticated over the phone's mTLS
	// control connection).
	if !req.Renewal {
		if e := s.enrollLimit(ctx, ip); e != nil {
			return Result{}, e
		}
	}

	// Consume + validate the single-use nonce.
	if ok, err := s.consumeNonce(ctx, req.Nonce); err != nil || !ok {
		return Result{}, &Error{Reason: "invalid_nonce", Retryable: true}
	}

	// Attestation gate (skipped only in the fail-closed test-only optional mode).
	var attestedKey crypto.PublicKey
	if !s.cfg.AttestOptional {
		res, err := s.cfg.Verifier.Verify(req.AttestChain, req.Nonce, s.now())
		if err != nil {
			s.recordRejection(ctx, ip, attestReason(err), req)
			return Result{}, &Error{Reason: "unauthorized"}
		}
		attestedKey = res.LeafPublicKey
	}

	// Key binding + CSR proof-of-possession (PRE-CLAIM). Both CSR signatures must verify, and — when
	// attestation ran — the identity key MUST equal the attested TEE key (closes the software-key
	// bypass). Returns csr-mismatch with no name to roll back.
	if err := req.IdentityCSR.CheckSignature(); err != nil {
		s.recordRejection(ctx, ip, "csr-mismatch", req)
		return Result{}, &Error{Reason: "unauthorized"}
	}
	if err := req.TLSCSR.CheckSignature(); err != nil {
		s.recordRejection(ctx, ip, "csr-mismatch", req)
		return Result{}, &Error{Reason: "unauthorized"}
	}
	if attestedKey != nil && !publicKeyEqual(req.IdentityCSR.PublicKey, attestedKey) {
		s.recordRejection(ctx, ip, "csr-mismatch", req)
		return Result{}, &Error{Reason: "unauthorized"}
	}

	// Determine the name.
	name, claimNonce, initial, e := s.resolveName(ctx, req)
	if e != nil {
		return Result{}, e
	}

	// Issuance read-only gate (keyed on the known name).
	allowed, err := s.cfg.Limiter.IssuanceAllowed(ctx, name, s.cfg.IssuePerWeek)
	if err != nil {
		s.rollback(ctx, initial, name)
		return Result{}, &Error{Reason: "internal", Retryable: true}
	}
	if !allowed {
		s.rollback(ctx, initial, name)
		return Result{}, &Error{Reason: "issuance_cap", Retryable: true, RetryAfter: 7 * 24 * time.Hour}
	}

	// Identity cert.
	identityPEM, err := s.cfg.CA.SignIdentity(req.IdentityCSR, name)
	if err != nil {
		s.rollback(ctx, initial, name)
		return Result{}, &Error{Reason: "identity_sign_failed"}
	}

	// Public cert (initial: full spillover; renewal: CA-pinning/LE-migrating Renew).
	var (
		pubChain []byte
		info     store.CertInfo
	)
	if initial {
		pubChain, info, err = s.cfg.Issuer.Obtain(ctx, req.TLSCSR, name)
	} else {
		var cur store.NameRecord
		cur, err = s.cfg.Names.GetName(ctx, name)
		if err == nil {
			pubChain, info, err = s.cfg.Issuer.Renew(ctx, req.TLSCSR, name, cur.Cert)
		}
	}
	if err != nil {
		s.rollback(ctx, initial, name)
		return Result{}, classifyIssuerError(err)
	}

	// Success: count this SUCCESSFUL issuance, then LWW-record the metadata preserving the claim nonce.
	if err := s.cfg.Limiter.IssuanceRecord(ctx, name); err != nil {
		// Non-fatal: the cert is issued; the counter is best-effort here.
		_ = err
	}
	s.recordSuccess(ctx, name, claimNonce, initial, req, info)

	return Result{Name: name, IdentityCert: identityPEM, PublicCert: pubChain, CA: info.CA}, nil
}

// resolveName generates + write-verify-claims a new name (INITIAL) or returns the existing name
// (RENEWAL). Returns the claim nonce used (for the record) and whether this is an initial enrollment.
func (s *Service) resolveName(ctx context.Context, req Request) (name, claimNonce string, initial bool, e *Error) {
	if req.Renewal {
		if req.Name == "" {
			return "", "", false, &Error{Reason: "missing_name"}
		}
		return req.Name, "", false, nil
	}
	name, claimNonce, err := s.claimName(ctx)
	if err != nil {
		return "", "", true, &Error{Reason: "name_unavailable", Retryable: true}
	}
	return name, claimNonce, true, nil
}

// claimName runs the write-verify claim protocol over PLAIN S3 (no conditional writes): per candidate,
// GET (exists → new name) → PUT with a fresh claim_nonce under the claim-timeout deadline (SDK retries
// disabled; timeout = abandon this name permanently) → wait settle (strictly > timeout) → GET-verify
// the nonce. Bounded loop.
func (s *Service) claimName(ctx context.Context) (name, claimNonce string, err error) {
	for attempt := 0; attempt < 8; attempt++ {
		cand, err := ca.GenerateName(s.cfg.NamePrefix, s.cfg.NameLength, s.cfg.ExtraReserved...)
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

// recordSuccess writes the registry record (LWW, preserving the claim nonce) with the cert + device
// info. A failure here is non-fatal: the verified claim record already exists and the certs are issued.
func (s *Service) recordSuccess(ctx context.Context, name, claimNonce string, initial bool, req Request, info store.CertInfo) {
	var rec store.NameRecord
	if !initial {
		if cur, err := s.cfg.Names.GetName(ctx, name); err == nil {
			rec = cur
		}
	} else {
		rec.Schema = 1
		rec.EnrolledAt = s.now().UTC()
		rec.ClaimNonce = claimNonce
	}
	rec.Schema = 1
	rec.LastRenewedAt = s.now().UTC()
	if rec.EnrolledAt.IsZero() {
		rec.EnrolledAt = s.now().UTC()
	}
	if req.IdentityCSR != nil {
		rec.IdentityKeyFP = keyFingerprint(req.IdentityCSR.PublicKey)
	}
	rec.SetCert(info)
	if err := s.cfg.Names.PutName(ctx, name, rec); err != nil {
		_ = err // best-effort; next renewal's LWW refreshes it
	}
}

func (s *Service) recordRejection(ctx context.Context, ip, reason string, req Request) {
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
		_ = s.cfg.Evidence.PutRejectedEnrollment(ctx, ev) // best-effort; never masks the rejection
	}
}

func (s *Service) enrollLimit(ctx context.Context, ip string) *Error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return &Error{Reason: "bad_source_ip"}
	}
	okMin, ra, err := limit.Allow(ctx, s.rdb, "enroll-min", addr, s.cfg.EnrollMinute, time.Minute)
	if err == nil && !okMin {
		return &Error{Reason: "enroll_rate", Retryable: true, RetryAfter: ra}
	}
	okHour, ra, err := limit.Allow(ctx, s.rdb, "enroll-hour", addr, s.cfg.EnrollHour, time.Hour)
	if err == nil && !okHour {
		return &Error{Reason: "enroll_rate", Retryable: true, RetryAfter: ra}
	}
	return nil
}

func newClaimNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
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
