package server

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/edge"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/enroll"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/phoneconn"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// serveTLS runs srv on ln until ctx is cancelled, then closes the listener. The listener is already a
// tls.Listener (and, for HTTP/2 servers, http2.ConfigureServer was applied at the call site).
func serveTLS(ctx context.Context, srv *http.Server, ln net.Listener, logger *slog.Logger, which string) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	err := srv.Serve(ln)
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		logger.Warn("listener exited", "which", which, "err", err)
	}
	return nil
}

// serveInternal runs the internal (metrics/healthz/admin) listener until ctx is cancelled.
func serveInternal(ctx context.Context, srv *http.Server, logger *slog.Logger) error {
	go func() { <-ctx.Done(); _ = srv.Close() }()
	err := srv.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Warn("internal listener exited", "err", err)
	}
	return nil
}

// validNameFunc validates a derived CN as EXACTLY a server-generated tunnel name: the configured
// prefix + --name-length lowercase-base32 ([a-z2-7]) characters, and not a reserved label. Only names
// this server's generator can have produced pass — anything looser would accept CNs the CA never signs.
func validNameFunc(cfg config.ServeCmd) func(string) bool {
	el := firstLabel(cfg.EnrollHost)
	cl := firstLabel(cfg.ControlHost)
	return func(name string) bool {
		if len(name) != len(cfg.NamePrefix)+cfg.NameLength {
			return false
		}
		if name[:len(cfg.NamePrefix)] != cfg.NamePrefix {
			return false
		}
		if name == el || name == cl {
			return false
		}
		for _, c := range name[len(cfg.NamePrefix):] {
			if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
				return false
			}
		}
		return true
	}
}

// edgeLogSink converts an edge.PublicEvent into a store.Event and writes it to the connection log (a
// failure is logged, never silent).
type edgeLogSink struct {
	st                  store.ConnLogStore
	logger              *slog.Logger
	nodeHost, nodeStart string
}

func (s *edgeLogSink) PutConnLogPublic(ctx context.Context, ev edge.PublicEvent) {
	e := store.Event{
		Schema: 1, Event: ev.Event, Conn: ev.Conn, Type: "public", Tunnel: ev.Tunnel,
		NodeHostname: s.nodeHost, NodeStart: s.nodeStart, TSStart: ev.StartedAt,
		SrcIP: ev.SrcIP, SrcPort: ev.SrcPort, SNI: ev.SNI, ALPN: ev.ALPN,
		TLSVersion: ev.TLSVersion, TLSFP: ev.JA4,
	}
	if ev.Event == "end" {
		e.TSEnd = ev.EndedAt
		e.DurationMS = ev.EndedAt.Sub(ev.StartedAt).Milliseconds()
		e.BytesIn = ev.BytesIn
		e.BytesOut = ev.BytesOut
		e.CloseReason = ev.CloseReason
	}
	if err := s.st.PutConnLog(ctx, e); err != nil {
		s.logger.Warn("public conn-log write failed", "tunnel", ev.Tunnel, "event", ev.Event, "err", err)
	}
}

// bridgeAdapter implements mesh.Bridge on the OWNER node: it opens the local phone dial-back stream and
// splices the incoming mesh stream to it. The entry node already accounted bytes + enforced caps, so the
// owner only relays.
type bridgeAdapter struct {
	mgr             *phoneconn.Manager
	dialBackTimeout time.Duration
}

func (b *bridgeAdapter) BridgeMesh(ctx context.Context, tunnel, streamID string, client io.ReadWriteCloser) error {
	// Bound the owner-side dial-back wait (mirrors the local fast path in edge.openFar): a phone that never
	// opens the /data stream fails fast so the entry node's held stream slot is released, rather than
	// pinning it until the idle timeout.
	timeout := b.dialBackTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	octx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel() // bounds ONLY the dial-back wait; the returned ds does not depend on octx
	ds, err := b.mgr.OpenStream(octx, tunnel, streamID)
	if err != nil {
		return err
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(ds, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, ds); done <- struct{}{} }()
	// Wait for BOTH copy directions to exit before returning: `client` is the mesh HTTP/2 response writer,
	// which MUST NOT be written after the handler returns. The first direction to finish triggers ds.Close
	// (cascading the phone side); the frontend teardown EOFs the request body, so the other copy exits too.
	<-done
	_ = ds.Close()
	<-done
	_ = client.Close()
	return nil
}

// issueFunc adapts the enroll service's Issue path to the phone control handler's mTLS POST /issue
// endpoint: it parses the phone's fresh attestation chain + rotated CSRs and runs the attested issuance
// (name from the mTLS client-cert CN, validated by the handler), returning the regenerated identity +
// public certs. It serves BOTH the initial public cert and every renewal.
func issueFunc(svc *enroll.Service) phoneconn.IssueFunc {
	return func(ctx context.Context, name, _, ip string, req phoneconn.IssueRequest) (phoneconn.IssueResponse, *phoneconn.IssueError) {
		nonce, err := hex.DecodeString(req.Nonce)
		if err != nil {
			return phoneconn.IssueResponse{}, &phoneconn.IssueError{Reason: "bad_nonce"}
		}
		chainPEM := []byte(req.AttestationChainPEM)
		attestChain, err := parseCertChainPEM(chainPEM)
		if err != nil {
			return phoneconn.IssueResponse{}, &phoneconn.IssueError{Reason: "bad_attestation"}
		}
		idCSR, err := parseCSRPEM(req.IdentityCSR)
		if err != nil {
			return phoneconn.IssueResponse{}, &phoneconn.IssueError{Reason: "bad_identity_csr"}
		}
		tlsCSR, err := parseCSRPEM(req.TLSCSR)
		if err != nil {
			return phoneconn.IssueResponse{}, &phoneconn.IssueError{Reason: "bad_tls_csr"}
		}
		res, eerr := svc.Issue(ctx, name, ip, enroll.Request{
			Nonce: nonce, AttestChainPEM: chainPEM, AttestChain: attestChain,
			IdentityCSR: idCSR, TLSCSR: tlsCSR,
		})
		if eerr != nil {
			return phoneconn.IssueResponse{}, &phoneconn.IssueError{
				Reason: eerr.Reason, Retryable: eerr.Retryable, Unauthorized: eerr.Reason == "unauthorized",
				RetryAfter: eerr.RetryAfter,
			}
		}
		return phoneconn.IssueResponse{
			IdentityCert: string(res.IdentityCert), PublicCert: string(res.PublicCert), CA: res.CA,
		}, nil
	}
}

// challengeFunc mints a fresh single-use challenge nonce (a real enroll nonce, Valkey-stored) for the
// renewal nudge, so the phone's follow-up POST /issue validates through the same attestation path as an
// initial issuance.
func challengeFunc(svc *enroll.Service) func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		nonce, err := svc.Nonce(ctx)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(nonce), nil
	}
}

// parseCertChainPEM parses every CERTIFICATE block in pemData into an ordered chain.
func parseCertChainPEM(pemData []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		return nil, errors.New("server: no certificate in attestation chain")
	}
	return chain, nil
}

// parseCSRPEM parses a single PEM-encoded PKCS#10 CSR.
func parseCSRPEM(pemStr string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("server: malformed CSR PEM")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}
