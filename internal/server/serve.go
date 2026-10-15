package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/edge"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/enroll"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/mesh"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/phoneconn"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

func h2Protocols() *http.Protocols {
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetHTTP2(true)
	return &p
}

func h2NextProtos() []string { return []string{"h2", "http/1.1"} }

// serveTLS runs srv on ln until ctx is cancelled, then closes the listener. ln is a tls.Listener for the
// TLS servers (enroll/control/mesh), or the plain
// listener. A non-shutdown Serve error is returned so the errgroup
// cancels and the process exits for the orchestrator to restart; ErrServerClosed / net.ErrClosed are the
// normal drain signals and stay non-fatal (the drain's srv.Shutdown bounds in-flight requests).
func serveTLS(ctx context.Context, srv *http.Server, ln net.Listener, logger *slog.Logger, which string) error {
	go func() { <-ctx.Done(); closeLogged(logger, which+" listener", ln) }()
	err := srv.Serve(ln)
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		logger.Warn("listener exited", "which", which, "err", err)
		return err
	}
	return nil
}

func closeLogged(logger *slog.Logger, what string, c io.Closer) {
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		logger.Warn("close failed", "what", what, "err", err)
	}
}

func shutdownLogged(ctx context.Context, logger *slog.Logger, which string, srv *http.Server) {
	if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, net.ErrClosed) {
		logger.Warn("server shutdown did not complete cleanly", "which", which, "err", err)
	}
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

// phoneControl is the consumer-side surface the admin controller needs from the phone manager (satisfied by
// *phoneconn.Manager) — an interface so adminController's Renew/Terminate logic is unit-testable in isolation.
type phoneControl interface {
	SendRenewNudge(name, nonceHex, ariWindow string) bool
	Close(name, reason string) bool
	SendOpen(ctx context.Context, name, connID string, open wire.OpenPayload) error
}

// adminController is this node's mesh.Controller: Renew enqueues a RENEW_NUDGE to the tunnel's LOCAL phone
// connection; Terminate evicts this node's in-flight public splices then closes that phone connection. Used
// both by the local admin path and by the mesh /api/v1/mesh/control handler.
type adminController struct {
	mgr          phoneControl
	nonce        func(ctx context.Context) (string, error) // mints the single-use renewal challenge nonce
	evictStreams func(name string)                         // edge.EvictTunnelStreams on this node
	evictConn    func(name, connID, reason string) bool
}

func (c *adminController) Renew(ctx context.Context, tunnel string) (bool, error) {
	nonceHex, err := c.nonce(ctx)
	if err != nil {
		return false, err
	}
	return c.mgr.SendRenewNudge(tunnel, nonceHex, ""), nil
}

// Terminate kicks the tunnel on this node: it first evicts this node's in-flight public splices
// (attributed admin-terminate), then closes the live phone control connection. The phone reconnects
// afterwards — terminate is a force-reconnect, not a keep-down. Returns whether a live phone conn existed.
func (c *adminController) Terminate(_ context.Context, tunnel string) (bool, error) {
	c.evictStreams(tunnel)
	return c.mgr.Close(tunnel, store.CloseAdminTerminate), nil
}

var errOpenNotApplied = errors.New("server: the owner node does not hold that phone connection")

var publicKeepAlive = net.KeepAliveConfig{Enable: true, Idle: 10 * time.Second, Interval: 5 * time.Second, Count: 3}

func listenPublic(ctx context.Context, addr string) (net.Listener, error) {
	lc := net.ListenConfig{KeepAliveConfig: publicKeepAlive}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	return ln, nil
}

type reservedCertLookup interface {
	has(host string) bool
}

type dialBackReadiness struct {
	https bool
	host  string
	certs reservedCertLookup
}

func (r dialBackReadiness) DialBackReady() bool {
	return !r.https || r.certs.has(r.host)
}

func controlClientAuth(mtls bool) tls.ClientAuthType {
	if mtls {
		return tls.RequireAndVerifyClientCert
	}
	return tls.VerifyClientCertIfGiven
}

type meshControl interface {
	Control(ctx context.Context, peer string, req mesh.ControlRequest) (mesh.ControlResponse, error)
}

type nodeResolver interface {
	LookupNode(ctx context.Context, nodeID string) (advertise string, ok bool, err error)
}

type liveNodeLister interface {
	LiveNodes(ctx context.Context) (map[string]router.NodeInfo, error)
}

func broadcastControl(ctx context.Context, self string, nodes map[string]router.NodeInfo, mc meshControl,
	req mesh.ControlRequest, logger *slog.Logger) (applied bool, failed map[string]bool) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	failed = map[string]bool{}
	for id, info := range nodes {
		if id == self {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := mc.Control(ctx, info.Advertise, req)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				logger.Warn("mesh control broadcast failed on a node", "op", req.Op, "tunnel", req.Tunnel, "node", id, "err", err)
				failed[id] = true
				return
			}
			applied = applied || res.Applied
		}()
	}
	wg.Wait()
	return applied, failed
}

type openAdapter struct {
	nodeID string
	phones phoneControl
	nodes  nodeResolver
	mesh   meshControl
	open   wire.OpenPayload
}

func (a *openAdapter) Open(ctx context.Context, nodeID, name, connID, token string) error {
	open := a.open
	open.Token = token
	if nodeID == a.nodeID {
		if err := a.phones.SendOpen(ctx, name, connID, open); err != nil {
			return fmt.Errorf("send OPEN to the local phone %s: %w", name, err)
		}
		return nil
	}
	peer, ok, err := a.nodes.LookupNode(ctx, nodeID)
	if err != nil {
		return fmt.Errorf("resolve owner node %s: %w", nodeID, err)
	}
	if !ok {
		return fmt.Errorf("owner node %s is not registered: %w", nodeID, errOpenNotApplied)
	}
	res, err := a.mesh.Control(ctx, peer, mesh.ControlRequest{Op: "open", Tunnel: name, ConnID: connID, Open: &open})
	if err != nil {
		return fmt.Errorf("mesh open on node %s: %w", nodeID, err)
	}
	if !res.Applied {
		return fmt.Errorf("mesh open on node %s: %w", nodeID, errOpenNotApplied)
	}
	return nil
}

const (
	evictBroadcastTimeout     = 10 * time.Second
	evictBroadcastConcurrency = 32
)

type spliceEvictor struct {
	nodeID string
	nodes  liveNodeLister
	mesh   meshControl
	local  func(name, connID, reason string) bool
	logger *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc
	slots  chan struct{}
	wg     sync.WaitGroup

	mu       sync.Mutex
	draining bool
}

func newSpliceEvictor(nodeID string, nodes liveNodeLister, mc meshControl, logger *slog.Logger) *spliceEvictor {
	ctx, cancel := context.WithCancel(context.Background())
	return &spliceEvictor{nodeID: nodeID, nodes: nodes, mesh: mc, logger: logger, ctx: ctx, cancel: cancel,
		slots: make(chan struct{}, evictBroadcastConcurrency)}
}

func (s *spliceEvictor) PhoneConnClosed(_ context.Context, name, connID, reason string) {
	s.local(name, connID, reason)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draining {
		s.logger.Warn("splice eviction broadcast skipped: the node is draining", "tunnel", name, "conn", connID)
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ctx, cancel := context.WithTimeout(s.ctx, evictBroadcastTimeout)
		defer cancel()
		select {
		case s.slots <- struct{}{}:
		case <-ctx.Done():
			s.logger.Warn("splice eviction broadcast dropped while waiting for a slot", "tunnel", name, "conn", connID, "err", ctx.Err())
			return
		}
		defer func() { <-s.slots }()
		nodes, err := s.nodes.LiveNodes(ctx)
		if err != nil {
			s.logger.Warn("splice eviction after a phone disconnect: node listing failed", "tunnel", name, "conn", connID, "err", err)
			return
		}
		broadcastControl(ctx, s.nodeID, nodes, s.mesh, mesh.ControlRequest{Op: "evict", Tunnel: name, ConnID: connID, Reason: reason}, s.logger)
	}()
}

func (s *spliceEvictor) Drain(ctx context.Context) {
	s.mu.Lock()
	s.draining = true
	s.mu.Unlock()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		select {
		case <-done:
		default:
			s.logger.Warn("drain deadline reached before every splice-eviction broadcast finished (cancelling them)", "err", ctx.Err())
		}
	}
	s.cancel()
	<-done
}

func (c *adminController) Open(ctx context.Context, tunnel, connID string, open wire.OpenPayload) (bool, error) {
	if err := c.mgr.SendOpen(ctx, tunnel, connID, open); err != nil {
		if errors.Is(err, phoneconn.ErrNoConn) {
			return false, nil
		}
		return false, fmt.Errorf("send OPEN to %s: %w", tunnel, err)
	}
	return true, nil
}

func (c *adminController) Evict(_ context.Context, tunnel, connID, reason string) (bool, error) {
	return c.evictConn(tunnel, connID, reason), nil
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

func connLogDropped(c prometheus.Counter) func(int) {
	return func(n int) { c.Add(float64(n)) }
}
