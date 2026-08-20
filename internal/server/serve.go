package server

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/edge"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/enroll"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/mesh"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/phoneconn"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// serveTLS runs srv on ln until ctx is cancelled, then closes the listener. ln is a tls.Listener for the
// TLS servers (enroll/control/mesh — http2.ConfigureServer was applied at the call site), or the plain
// internal (metrics/healthz/admin) listener. A non-shutdown Serve error is returned so the errgroup
// cancels and the process exits for the orchestrator to restart; ErrServerClosed / net.ErrClosed are the
// normal drain signals and stay non-fatal (the drain's srv.Shutdown bounds in-flight requests).
func serveTLS(ctx context.Context, srv *http.Server, ln net.Listener, logger *slog.Logger, which string) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	err := srv.Serve(ln)
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		logger.Warn("listener exited", "which", which, "err", err)
		return err
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

// dialBackOpener opens the local phone dial-back stream for a tunnel (satisfied by *phoneconn.Manager).
// bridgeAdapter depends on this narrow surface so the OpenMesh sentinel translation is unit-testable.
type dialBackOpener interface {
	OpenStream(ctx context.Context, name, streamID string) (phoneconn.DataStream, error)
}

// bridgeAdapter implements mesh.Bridge on the OWNER node: OpenMesh opens the local phone dial-back
// stream (open phase) and SpliceMesh relays the incoming mesh stream to it. The entry node already
// accounted bytes + enforced caps, so the owner only relays.
type bridgeAdapter struct {
	mgr             dialBackOpener
	dialBackTimeout time.Duration
}

func (b *bridgeAdapter) OpenMesh(ctx context.Context, tunnel, streamID string) (io.ReadWriteCloser, error) {
	// Bound the owner-side dial-back wait (mirrors the local fast path in edge.openFar): a phone that never
	// opens the /api/v1/data stream fails fast so the entry node's held stream slot is released, rather than
	// pinning it until the idle timeout.
	timeout := b.dialBackTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	octx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel() // bounds ONLY the dial-back wait; the returned ds does not depend on octx
	ds, err := b.mgr.OpenStream(octx, tunnel, streamID)
	if err != nil {
		// Translate the phone-side sentinel to the mesh-owned one (mesh MUST NOT import phoneconn), so the
		// listener answers 422 and the entry node re-mints the stream id.
		if errors.Is(err, phoneconn.ErrDuplicateStreamID) {
			return nil, fmt.Errorf("mesh dial-back: %w", mesh.ErrDuplicateStream)
		}
		return nil, err
	}
	return ds, nil
}

func (b *bridgeAdapter) SpliceMesh(ds, client io.ReadWriteCloser) {
	bridgeCopy(ds, client)
}

// bridgeCopy splices the phone stream `ds` ↔ the mesh stream `client`, returning once the phone→client
// direction (the ONLY one that writes to `client`, the mesh HTTP/2 response body) has fully stopped —
// guaranteeing no write to the response writer after the caller returns. Teardown fires as soon as
// EITHER direction ends, so an abrupt phone-side close (or an entry-side close) propagates PROMPTLY
// instead of stalling until the entry's idle timeout: closing `ds` EOFs the phone→client copy, and
// closing `client` marks the response writer done + unblocks the entry. The client→phone copy writes
// solely to `ds` and never touches the response writer, so it may safely outlive the return by the
// microseconds until the server closes the request body and unblocks its read.
func bridgeCopy(ds, client io.ReadWriteCloser) {
	inDone := make(chan struct{}, 1) // client→phone finished
	respDone := make(chan struct{})  // phone→client finished (the one that writes the response body)
	go func() { _, _ = io.Copy(ds, client); inDone <- struct{}{} }()
	go func() { _, _ = io.Copy(client, ds); close(respDone) }()
	select {
	case <-respDone: // the phone (or a client write error) ended the response direction
	case <-inDone: // the entry (or a phone write error) ended the request direction
	}
	_ = ds.Close()
	_ = client.Close()
	<-respDone // the response-writer copy has fully stopped — safe to return
}

// issueFunc adapts the enroll service's Issue path to the phone control handler's mTLS POST /api/v1/issue
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

// renewController is this node's mesh.Controller: it mints a fresh renewal nonce (the same challenge the
// renewal watcher uses) and enqueues a RENEW_NUDGE to the tunnel's LOCAL phone connection. Used both
// directly by the /api/v1/admin/renew local path and by the mesh /api/v1/mesh/control handler on the owner node.
type renewController struct {
	mgr   *phoneconn.Manager
	nonce func(ctx context.Context) (string, error)
}

func (rc *renewController) Renew(ctx context.Context, tunnel string) (bool, error) {
	nonceHex, err := rc.nonce(ctx)
	if err != nil {
		return false, err
	}
	return rc.mgr.SendRenewNudge(tunnel, nonceHex, ""), nil
}

// challengeFunc mints a fresh single-use challenge nonce (a real enroll nonce, Valkey-stored) for the
// renewal nudge, so the phone's follow-up POST /api/v1/issue validates through the same attestation path as an
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
