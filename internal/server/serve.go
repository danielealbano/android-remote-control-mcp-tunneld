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

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/edge"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/enroll"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/phoneconn"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
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

// validNameFunc validates a derived CN as a well-formed, non-reserved base32 tunnel name.
func validNameFunc(cfg config.ServeCmd) func(string) bool {
	el := firstLabel(cfg.EnrollHost)
	cl := firstLabel(cfg.ControlHost)
	return func(name string) bool {
		if len(name) < 6 || len(name) > 63 {
			return false
		}
		if name == el || name == cl {
			return false
		}
		for _, c := range name {
			lower := c >= 'a' && c <= 'z'
			b32 := c >= '2' && c <= '7'
			digit := c >= '0' && c <= '9'
			if !lower && !b32 && !digit && c != '-' {
				return false
			}
		}
		return true
	}
}

// edgeLogSink converts an edge.PublicEvent into a store.Event and writes it to the connection log.
type edgeLogSink struct {
	st                  store.ConnLogStore
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
	_ = s.st.PutConnLog(ctx, e)
}

// bridgeAdapter implements mesh.Bridge on the OWNER node: it opens the local phone dial-back stream and
// splices the incoming mesh stream to it. The entry node already accounted bytes + enforced caps, so the
// owner only relays.
type bridgeAdapter struct {
	mgr *phoneconn.Manager
}

func (b *bridgeAdapter) BridgeMesh(ctx context.Context, tunnel, streamID string, client io.ReadWriteCloser) error {
	ds, err := b.mgr.OpenStream(ctx, tunnel, streamID)
	if err != nil {
		return err
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(ds, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, ds); done <- struct{}{} }()
	<-done
	_ = ds.Close()
	_ = client.Close()
	return nil
}

// renewFunc adapts the enroll service's renewal path to the phone control handler's OnRenew callback:
// it parses the phone's submitted attestation chain + rotated CSRs and runs the same attested-enrollment
// flow in renewal mode (existing name, no per-IP enroll limit), returning the rotated certs to push.
func renewFunc(svc *enroll.Service) phoneconn.RenewFunc {
	return func(ctx context.Context, name, nonceHex, ip string, sub wire.RenewSubmitPayload) (wire.CertPushPayload, error) {
		nonce, err := hex.DecodeString(nonceHex)
		if err != nil {
			return wire.CertPushPayload{}, err
		}
		chainPEM := []byte(sub.AttestationChainPEM)
		attestChain, err := parseCertChainPEM(chainPEM)
		if err != nil {
			return wire.CertPushPayload{}, err
		}
		idCSR, err := parseCSRPEM(sub.IdentityCSR)
		if err != nil {
			return wire.CertPushPayload{}, err
		}
		tlsCSR, err := parseCSRPEM(sub.TLSCSR)
		if err != nil {
			return wire.CertPushPayload{}, err
		}
		res, eerr := svc.Enroll(ctx, ip, enroll.Request{
			Renewal: true, Name: name, Nonce: nonce,
			AttestChainPEM: chainPEM, AttestChain: attestChain,
			IdentityCSR: idCSR, TLSCSR: tlsCSR,
		})
		if eerr != nil {
			return wire.CertPushPayload{}, eerr
		}
		return wire.CertPushPayload{
			IdentityCertPEM: string(res.IdentityCert),
			PublicCertPEM:   string(res.PublicCert),
		}, nil
	}
}

// challengeFunc adapts the enroll service's single-use nonce minting to the control handler's renewal
// challenge: the renewal nonce is a real enroll nonce (Valkey-stored), so the submission validates
// through the exact same attestation path as an initial enrollment.
func challengeFunc(svc *enroll.Service) phoneconn.ChallengeFunc {
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
