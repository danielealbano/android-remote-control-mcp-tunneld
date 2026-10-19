// Package server assembles and runs the E2E tunneld process: Valkey, internal CA, ban engine, routing
// registry + node registry, the limiter, the durable store, the attestation verifier, the ACME chain,
// the enrollment service + handler, the phone control plane, the replica mesh, the public SNI edge, the
// internal metrics/admin server, and the background schedulers — with graceful shutdown. See
// docs/ARCHITECTURE.md for the system map.
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/acme"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/admin"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ban"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ca"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/caplog"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/edge"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/enroll"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/mesh"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/metrics"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/phoneconn"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

const (
	readHeaderTimeout   = 10 * time.Second
	renewalScanInterval = time.Hour
)

// Run constructs every component and runs the process until ctx is cancelled, then drains gracefully.
func Run(ctx context.Context, cfg config.ServeCmd, logger *slog.Logger, version string) error {
	// SNI dispatch is case-insensitive: normalize the routing hosts once so every downstream comparison
	// (edge dispatch, reserved-cert issuance, enroll reserved labels) uses the canonical lowercase form.
	cfg.TunnelDomain = strings.ToLower(cfg.TunnelDomain)
	cfg.EnrollHost = strings.ToLower(cfg.EnrollHost)
	cfg.ControlHost = strings.ToLower(cfg.ControlHost)
	// The name prefix feeds BOTH name generation and validNameFunc; lowercase it once so a generated CN
	// matches the lowercased SNI at the edge (an uppercase prefix would otherwise no-route every tunnel).
	cfg.NamePrefix = strings.ToLower(cfg.NamePrefix)

	redisConn, err := config.ParseRedisURL(cfg.RedisURL)
	if err != nil {
		return fmt.Errorf("valkey client: %w", err)
	}
	rdb := redisConn.NewClient()
	defer closeLogged(logger, "valkey client", rdb)

	nodeID := newNodeID()
	nodeHost := hostname(os.Hostname, logger)
	nodeStart := nodeStartStamp()
	logger = logger.With("node", nodeID, "version", version)

	caObj, err := ca.Load(cfg.CACert, cfg.CAKey, cfg.CertValidity)
	if err != nil {
		return err
	}

	// Ban engine + watcher: ONE startup load (Initial), synchronous, before any listener binds — so a
	// file present at that load which later VANISHES is refused on the next poll instead of silently
	// unbanning (docs/ARCHITECTURE.md §7).
	banEng := ban.NewEngine()
	banWatcher := ban.NewWatcher(banEng, cfg.BanFile, cfg.DBIPCountryLiteCSV, cfg.BanPoll, logger)
	banWatcher.Initial()
	banIP := func(ip netip.Addr) bool { _, b := banEng.Match(ip); return b }
	banTunnel := func(name string) bool { _, b := banEng.MatchTunnel(name); return b }

	// Control-plane primitives.
	reg, err := router.NewRegistry(rdb, cfg.RouteTTL, router.WithLogger(logger))
	if err != nil {
		return fmt.Errorf("route registry: %w", err)
	}
	// These flags were already parsed + range-checked by cfg.Validate() at startup; a parse error
	// here is impossible.
	bwRate, err := config.ParseBitrate(cfg.LimitBandwidth)
	if err != nil {
		return fmt.Errorf("--limit-bandwidth: %w", err)
	}
	dayCap, err := config.ParseByteSize(cfg.LimitTrafficDay)
	if err != nil {
		return fmt.Errorf("--limit-traffic-day: %w", err)
	}
	weekCap, err := config.ParseByteSize(cfg.LimitTrafficWeek)
	if err != nil {
		return fmt.Errorf("--limit-traffic-week: %w", err)
	}
	minRate, err := config.ParseByteSize(cfg.LimitConnMinRate)
	if err != nil {
		return fmt.Errorf("--limit-conn-min-rate: %w", err)
	}
	protectRate, err := config.ParseByteSize(cfg.LimitConnProtectRate)
	if err != nil {
		return fmt.Errorf("--limit-conn-protect-rate: %w", err)
	}
	enrollBody, err := config.ParseByteSize(cfg.LimitEnrollBody)
	if err != nil {
		return fmt.Errorf("--limit-enroll-body: %w", err)
	}
	lim := limit.NewLimiter(rdb, bwRate, dayCap, weekCap, 3*cfg.LimitConnIdle,
		limit.WithLogger(logger), limit.WithPacketCap(int64(cfg.LimitPackets)))
	chal := acme.NewChallengeStore(rdb, acme.ChallengeTTL)

	// Durable store.
	st, err := store.NewS3Store(ctx, store.S3Config{
		Endpoint: cfg.S3Endpoint, Region: cfg.S3Region, Bucket: cfg.S3Bucket,
		AccessKey: cfg.S3AccessKey, SecretKey: cfg.S3SecretKey, ForcePathStyle: cfg.S3ForcePathStyle,
	})
	if err != nil {
		return err
	}

	// Metrics + admin + recorder.
	m := metrics.NewMetrics()
	if err := registerLogSinkErrors(m, logger); err != nil {
		return err
	}
	if err := registerValkeyPool(m, rdb); err != nil {
		return err
	}
	adminTunnels := admin.NewTunnels(reg, lim) // composes routing meta (router) + live windows (limiter)
	capLogger := caplog.New(logger)
	rec := metrics.NewPromRecorder(m, capLogger, reg, logger) // reg (router.Registry) is the TrafficSink

	// Async connection-log writer: enqueue is O(1) so no admission/splice/teardown path blocks on an
	// S3 write; a full queue drops-newest and bumps the dropped-events counter. Both the phone control
	// plane and the public edge log through it.
	connLogs, err := store.NewConnLogSpool(cfg.ConnLogDir, nodeID, st, connLogDropped(m.ConnLogDropped()), logger)
	if err != nil {
		return fmt.Errorf("connection-log spool: %w", err)
	}
	defer func() {
		dctx, dcancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
		defer dcancel()
		connLogs.Drain(dctx)
	}()

	// Attestation verifier (fail-closed until the roots/status refreshers succeed; refreshers started
	// on the errgroup below). A signer-allowlist load failure is a fatal configuration error.
	verifier, attRoots, attStatus, attSigners, err := buildVerifier(ctx, cfg, logger)
	if err != nil {
		return err
	}

	// ACME chain (lazy self-healing lego clients). An
	// existing-but-unreadable account key aborts startup (never overwrites it).
	chain, err := buildACMEChain(cfg, lim, chal, rec, logger, nodeID, liveNodeIDs{reg})
	if err != nil {
		return err
	}
	if err := m.RegisterACMEBudgets(func(ctx context.Context) ([]metrics.ACMEBudgetLevel, error) {
		levels, err := chain.ACMEBudgetLevels(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]metrics.ACMEBudgetLevel, len(levels))
		for i, l := range levels {
			out[i] = metrics.ACMEBudgetLevel{CA: l.CA, Account: l.Account, Budget: l.Budget, Ratio: l.Ratio}
		}
		return out, nil
	}, logger); err != nil {
		return fmt.Errorf("acme budget metrics: %w", err)
	}

	// Enrollment service + handler.
	enrollSvc := enroll.NewService(enroll.Config{
		RDB: rdb, CA: caObj, Names: st, Evidence: st, Verifier: verifier, Limiter: lim, Issuer: chain,
		TunnelDomain: cfg.TunnelDomain,
		NamePrefix:   cfg.NamePrefix, NameLength: cfg.NameLength,
		ExtraReserved: []string{firstLabel(cfg.EnrollHost), firstLabel(cfg.ControlHost)},
		IssuePerWeek:  cfg.IssuePerWeek, EnrollHour: cfg.LimitEnrollHour, EnrollMinute: cfg.LimitEnrollMinute,
		ClaimTimeout: cfg.RegistryClaimTimeout, ClaimSettle: cfg.RegistryClaimSettle,
		AttestOptional: cfg.AttestationOptional,
		Recorder:       rec, Logger: logger,
	})
	enrollHandler := enroll.NewHandler(enrollSvc, banIP, rec, enrollBody)

	// Mesh cert (hot-swappable) + client + listener. A failed initial mint is fatal — :9443 must never
	// bind without a servable cert.
	meshCert, err := newMeshCertHolder(caObj, nodeID, cfg.MeshCertTTL, logger)
	if err != nil {
		return err
	}
	meshClient := mesh.NewClient(meshCert.clientTLS(caObj), cfg.MeshPoolSize, mesh.WithRecorder(rec))

	// Phone control plane.
	dialBacks := phoneconn.NewDialBacks(logger)
	evictor := newSpliceEvictor(nodeID, reg, meshClient, logger)
	phoneMgr := phoneconn.NewManager(phoneconn.Config{
		Router: reg, Logs: connLogs, Recorder: rec, Logger: logger, Closed: evictor,
		NodeID: nodeID, NodeHost: nodeHost, NodeStart: nodeStart,
		RouteTTL: cfg.RouteTTL,
	})
	phoneHandler := phoneconn.NewHandler(phoneconn.HandlerConfig{
		Manager: phoneMgr, ValidName: validNameFunc(cfg), BanIP: banIP, BanTunnel: banTunnel,
		Reject:       rec.Reject,
		PingInterval: cfg.ControlPingInterval, StreamPending: cfg.LimitStreamPending,
		OnIssue:   issueFunc(enrollSvc),
		DialBacks: dialBacks, DialBackMTLS: cfg.DialBackMTLS,
	})

	// Public edge (constructed from the resolved static address — the raw listener is bound LAST, below,
	// so the edge never depends on a live socket at construction time). Built BEFORE the admin controller
	// and mesh handler so the controller can take ed.EvictTunnelStreams (for the terminate action).
	edgeAddr, err := net.ResolveTCPAddr("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", cfg.Listen, err)
	}
	// Reserved-host certs (ObtainSelf via the ACME chain, disk-persisted per node, degraded start).
	reserved := newReservedCerts(cfg.ACMEAccountDir, []string{cfg.EnrollHost, cfg.ControlHost},
		chain.ObtainSelf, chain.ShouldRenew, chal, chal, logger)
	reserved.loadCache(ctx)

	opener := &openAdapter{nodeID: nodeID, phones: phoneMgr, nodes: reg, mesh: meshClient,
		open: wire.OpenPayload{Addr: cfg.DialBackAdvertise, UseHTTPS: cfg.DialBackHTTPS, UseMTLS: cfg.DialBackMTLS}}
	ed := edge.New(edge.Config{
		EnrollHost: cfg.EnrollHost, ControlHost: cfg.ControlHost, TunnelDomain: cfg.TunnelDomain,
		MaxClients: cfg.MaxClients, ConnRate: cfg.LimitConnRate,
		Concurrent: cfg.LimitConcurrent, HandshakeTimeout: cfg.HandshakeTimeout, DialBackTimeout: cfg.LimitDialBackTimeout,
		IdleTimeout: cfg.LimitConnIdle, MinGrace: cfg.LimitConnMinGrace, EvictIdle: cfg.LimitConnEvictIdle,
		MinRate: minRate, ProtectRate: protectRate,
		Logger: logger,
	}, banIP, rec,
		reg, dialBacks, opener, dialBackReadiness{https: cfg.DialBackHTTPS, host: cfg.ControlHost, certs: reserved}, lim,
		&edgeLogSink{st: connLogs, logger: logger, nodeHost: nodeHost, nodeStart: nodeStart}, chal, edgeAddr)
	evictor.local = ed.EvictConnStreams

	adminCtl := &adminController{mgr: phoneMgr, nonce: challengeFunc(enrollSvc), evictStreams: ed.EvictTunnelStreams, evictConn: ed.EvictConnStreams}
	meshHandler, err := mesh.NewHandler(adminCtl, mesh.WithHandlerLogger(logger))
	if err != nil {
		return fmt.Errorf("mesh handler: %w", err)
	}

	// Reserved-host TLS terminators (enroll: server-TLS HTTP/1.1; control: TLS with ConnMeta).
	// The enroll server is an UNAUTHENTICATED surface: its requests are small and short, so both the
	// full-request read and keep-alive idling are tightly bounded (idle TLS conns must not accumulate).
	publicErrLog := slog.NewLogLogger(logger.Handler(), slog.LevelDebug)
	internalErrLog := slog.NewLogLogger(logger.Handler(), slog.LevelWarn)
	enrollSrv := &http.Server{Handler: enrollHandler, ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout: 30 * time.Second, IdleTimeout: time.Minute, ErrorLog: publicErrLog,
		TLSConfig: &tls.Config{GetCertificate: reserved.getCertificateFor(cfg.EnrollHost), MinVersion: tls.VersionTLS12}}
	// The control server's idle timeout closes mTLS-authenticated HTTP/2 conns holding NO active stream
	// (a bound phone always keeps its /api/v1/control stream open, so real connections are never idle).
	controlSrv := &http.Server{Handler: phoneHandler, ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout: 4 * cfg.ControlPingInterval, ErrorLog: publicErrLog,
		ConnContext: phoneconn.ConnContext,
		Protocols:   h2Protocols(),
		TLSConfig: &tls.Config{GetCertificate: reserved.getCertificateFor(cfg.ControlHost),
			ClientAuth: controlClientAuth(cfg.DialBackMTLS), ClientCAs: caObj.Pool(), MinVersion: tls.VersionTLS12,
			NextProtos: h2NextProtos()}}

	// Mesh server (mTLS mesh-role, HTTP/2); its listener is bound LAST, below.
	meshSrv := &http.Server{Handler: meshHandler, ReadHeaderTimeout: readHeaderTimeout,
		Protocols: h2Protocols(), ErrorLog: internalErrLog,
		TLSConfig: &tls.Config{GetCertificate: meshCert.getCert, ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs: caObj.Pool(), MinVersion: tls.VersionTLS12, NextProtos: h2NextProtos()}}

	// Internal server (metrics + healthz + admin actions; never proxied). The mux mounts the per-tunnel
	// admin actions /api/v1/admin/tunnels/{name}/reissue and .../terminate and delegates everything else to
	// the existing metrics handler (unchanged).
	internalMux := http.NewServeMux()
	internalMux.Handle("/api/v1/admin/tunnels/{name}/reissue",
		adminActionHandler(nodeID, reg, meshClient, logger, "renew", "reissued", adminCtl.Renew))
	internalMux.Handle("/api/v1/admin/tunnels/{name}/terminate",
		adminTerminateHandler(nodeID, reg, meshClient, logger, adminCtl.Terminate))
	internalMux.Handle("/", metrics.Handler(m.Registry(), rdb, adminTunnels, reg, logger))
	internalSrv := &http.Server{Addr: cfg.InternalListen, ReadHeaderTimeout: readHeaderTimeout,
		Handler: internalMux, ErrorLog: internalErrLog}

	var acmeHTTPSrv *http.Server
	if cfg.ServesPlainHTTP() {
		challenges := acme.HTTPChallengeHandler(chal, func(ip string) { rec.Reject("acme-http-miss", "", ip) }, logger)
		plain := http.Handler(challenges)
		if !cfg.DialBackHTTPS {
			plain = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == wire.DialBackPath {
					phoneHandler.ServeHTTP(w, r)
					return
				}
				challenges.ServeHTTP(w, r)
			})
		}
		acmeHTTPSrv = &http.Server{
			Handler:           plain,
			ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: readHeaderTimeout, WriteTimeout: readHeaderTimeout,
			IdleTimeout: acmeHTTPIdleTimeout, MaxHeaderBytes: acmeHTTPMaxHeaderBytes,
			DisableGeneralOptionsHandler: true, ErrorLog: publicErrLog,
		}
		acmeHTTPSrv.SetKeepAlivesEnabled(false)
	}

	// Bind the public + mesh listeners LAST: every fallible construction step above
	// has now succeeded, so no socket is ever left bound
	// but unserved. A mesh-bind failure closes the already-bound raw listener before returning.
	rawLn, err := listenPublic(ctx, cfg.Listen)
	if err != nil {
		return err
	}
	meshLn, err := net.Listen("tcp", cfg.MeshListen)
	if err != nil {
		closeLogged(logger, "raw listener", rawLn) // never leak a bound listener on a construction error
		return fmt.Errorf("mesh listen %s: %w", cfg.MeshListen, err)
	}
	// The internal (metrics/healthz/admin) listener binds HERE too — a bind failure must be fatal, not a
	// silent Warn that leaves health checking and metrics dead forever.
	internalLn, err := net.Listen("tcp", cfg.InternalListen)
	if err != nil {
		closeLogged(logger, "raw listener", rawLn)
		closeLogged(logger, "mesh listener", meshLn)
		return fmt.Errorf("internal listen %s: %w", cfg.InternalListen, err)
	}
	var acmeHTTPLn net.Listener
	if acmeHTTPSrv != nil {
		acmeHTTPLn, err = listenPublic(ctx, cfg.ACMEHTTPListen)
		if err != nil {
			closeLogged(logger, "raw listener", rawLn)
			closeLogged(logger, "mesh listener", meshLn)
			closeLogged(logger, "internal listener", internalLn)
			return fmt.Errorf("acme http %w", err)
		}
	}

	g, gctx := errgroup.WithContext(ctx)

	// Reserved-host + mesh + internal servers.
	g.Go(func() error {
		return serveTLS(gctx, enrollSrv, tls.NewListener(ed.EnrollListener(), enrollSrv.TLSConfig), logger, "enroll")
	})
	g.Go(func() error {
		return serveTLS(gctx, controlSrv, tls.NewListener(ed.ControlListener(), controlSrv.TLSConfig), logger, "control")
	})
	g.Go(func() error {
		return serveTLS(gctx, meshSrv, tls.NewListener(meshLn, meshSrv.TLSConfig), logger, "mesh")
	})
	g.Go(func() error { return serveTLS(gctx, internalSrv, internalLn, logger, "internal") })

	// Edge accept loop.
	g.Go(func() error { ed.Serve(gctx, rawLn); return nil })
	var guarded *guardedListener
	if acmeHTTPSrv != nil {
		guarded = newGuardedListener(gctx, acmeHTTPLn, banIP, connRateAllow(lim, cfg.LimitConnRate, logger),
			ed.Admit, ed.Release, rec.Reject, logger)
		g.Go(func() error { return serveTLS(gctx, acmeHTTPSrv, guarded, logger, "acme-http") })
	}

	// Recorder flusher.
	g.Go(func() error { return rec.RunFlusher(gctx, 5*time.Second) })

	// Mesh pool janitor (reaps per-peer pools idle for 10m).
	g.Go(func() error { return meshClient.Run(gctx, 10*time.Minute) })

	// Attestation refreshers: root set + status list at --attest-refresh (last-known-good), and the
	// signer-digest allowlist mtime watcher at the ban poll cadence.
	g.Go(func() error { attRoots.Refresh(gctx, cfg.AttestRefresh); return nil })
	g.Go(func() error { attStatus.Refresh(gctx, cfg.AttestRefresh); return nil })
	g.Go(func() error { attSigners.Watch(gctx, cfg.BanPoll); return nil })

	// Schedulers: node heartbeat, mesh-cert rotation, reserved-cert renewal, phone renewal watcher.
	g.Go(func() error {
		return heartbeatNode(gctx, reg, nodeID, cfg.MeshAdvertise, nodeHost, version, nodeStart, cfg.RouteTTL, logger)
	})
	g.Go(func() error { meshCert.rotateLoop(gctx); return nil })
	g.Go(func() error { return reserved.run(gctx, renewalScanInterval, reservedDegradedRetry) })
	g.Go(func() error {
		rw := &renewalWatcher{mgr: phoneMgr, names: st, chain: chain, nonce: challengeFunc(enrollSvc), logger: logger}
		return rw.run(gctx, renewalScanInterval)
	})

	// Ban watcher with the live eviction hook.
	g.Go(func() error {
		banWatcher.Run(gctx, func(e *ban.Engine) {
			phoneMgr.EvictBanned(func(name string) bool { _, b := e.MatchTunnel(name); return b })
		})
		return nil
	})

	<-gctx.Done()
	// Ordered drain: stop accepting new public connections (close the raw listener) → actively close the
	// live phone control connections (each /api/v1/control handler returns, running its teardown: owner-conditional
	// route unbind + the durable end event — a never-idle control stream would otherwise pin Shutdown for
	// the full grace and skip both) → drain the HTTP servers → join every in-flight public splice handler
	// (so their end events are enqueued) → join the errgroup goroutines → flush the async conn-log queue
	// (the server-shutdown end events land) → final admin-counter flush + pending cap-hit summaries. The
	// route/node TTLs remain the crash backstop.
	sctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()
	closeLogged(logger, "raw listener", rawLn)
	if guarded != nil {
		closeLogged(logger, "acme-http listener", guarded)
	}
	phoneMgr.CloseAll(store.CloseServerShutdown)
	shutdownLogged(sctx, logger, "enroll", enrollSrv)
	shutdownLogged(sctx, logger, "control", controlSrv)
	shutdownLogged(sctx, logger, "mesh", meshSrv)
	shutdownLogged(sctx, logger, "internal", internalSrv)
	if acmeHTTPSrv != nil {
		shutdownLogged(sctx, logger, "acme-http", acmeHTTPSrv)
	}
	ed.Wait(sctx) // every public handler (splice + end-event enqueue + slot release) has returned
	if guarded != nil {
		guarded.Wait(sctx)
	}
	werr := g.Wait()
	connLogs.Drain(sctx) // queued conn-log events (incl. server-shutdown end events) land
	rec.FinalFlush()     // after ALL producers stopped — no late deltas lost (self-bounded)
	rec.FlushCapLog()    // pending cap-hit summaries
	if err := reg.DeregisterNode(sctx, nodeID); err != nil {
		logger.Warn("node deregister failed (expires by TTL)", "err", err)
	}
	evictor.Drain(sctx)
	if werr != nil && !errors.Is(werr, context.Canceled) {
		return werr
	}
	return nil
}

// adminActionHandler routes a per-tunnel admin action ({name} from the path) to the tunnel's owner node:
// the local controller method when this node owns the route, else the mesh control RPC. op is the mesh op
// ("renew"); respField is the operator-facing JSON boolean key ("reissued").
// Internal listener only (never published). 404 when no route is bound. local is the mesh.Controller method
// (adminController.Renew) so the owner-local path is unit-testable with a stub.
func adminActionHandler(nodeID string, reg *router.Registry, mc *mesh.Client, log *slog.Logger,
	op, respField string, local func(ctx context.Context, name string) (bool, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := r.PathValue("name")
		if name == "" {
			http.Error(w, "missing tunnel", http.StatusBadRequest)
			return
		}
		owner, _, ok, err := reg.LookupRoute(r.Context(), name)
		if err != nil {
			log.Warn("admin "+op+": route lookup failed", "tunnel", name, "err", err)
			http.Error(w, "route lookup failed", http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "no route bound for tunnel", http.StatusNotFound)
			return
		}
		var applied bool
		if owner == nodeID {
			applied, err = local(r.Context(), name)
		} else {
			addr, addrOK, lerr := reg.LookupNode(r.Context(), owner)
			if lerr != nil || !addrOK {
				log.Warn("admin "+op+": owner node unresolved", "tunnel", name, "owner", owner, "err", lerr)
				http.Error(w, "owner node unavailable", http.StatusBadGateway)
				return
			}
			var res mesh.ControlResponse
			res, err = mc.Control(r.Context(), addr, mesh.ControlRequest{Op: op, Tunnel: name})
			applied = res.Applied
		}
		if err != nil {
			log.Warn("admin "+op+": failed", "tunnel", name, "owner", owner, "err", err)
			http.Error(w, op+" failed", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"tunnel": name, "owner": owner, respField: applied}); err != nil {
			log.Warn("admin "+op+": response write failed", "tunnel", name, "err", err)
		}
	}
}

func adminTerminateHandler(nodeID string, reg *router.Registry, mc meshControl, log *slog.Logger,
	local func(ctx context.Context, name string) (bool, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := r.PathValue("name")
		if name == "" {
			http.Error(w, "missing tunnel", http.StatusBadRequest)
			return
		}
		owner, _, ok, err := reg.LookupRoute(r.Context(), name)
		if err != nil {
			log.Warn("admin terminate: route lookup failed", "tunnel", name, "err", err)
			http.Error(w, "route lookup failed", http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "no route bound for tunnel", http.StatusNotFound)
			return
		}
		nodes, err := reg.LiveNodes(r.Context())
		if err != nil {
			log.Warn("admin terminate: node listing failed", "tunnel", name, "err", err)
			http.Error(w, "node listing failed", http.StatusInternalServerError)
			return
		}
		applied, lerr := local(r.Context(), name)
		if lerr != nil {
			log.Warn("admin terminate: local terminate failed", "tunnel", name, "err", lerr)
		}
		remote, failed := broadcastControl(r.Context(), nodeID, nodes, mc, mesh.ControlRequest{Op: "terminate", Tunnel: name}, log)
		applied = applied || remote
		_, ownerLive := nodes[owner]
		switch {
		case owner == nodeID && lerr != nil, failed[owner]:
			http.Error(w, "terminate failed", http.StatusBadGateway)
			return
		case owner != nodeID && !ownerLive:
			log.Warn("admin terminate: owner node unresolved", "tunnel", name, "owner", owner)
			http.Error(w, "owner node unavailable", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"tunnel": name, "owner": owner, "terminated": applied}); err != nil {
			log.Warn("admin terminate: response write failed", "tunnel", name, "err", err)
		}
	}
}

type sinkErrorCounter interface {
	SinkErrors() uint64
}

func registerLogSinkErrors(m *metrics.Metrics, logger *slog.Logger) error {
	c, ok := logger.Handler().(sinkErrorCounter)
	if !ok {
		return nil
	}
	if err := m.RegisterLogSinkErrors(func() float64 { return float64(c.SinkErrors()) }); err != nil {
		return fmt.Errorf("register the log sink error metric: %w", err)
	}
	return nil
}

func registerValkeyPool(m *metrics.Metrics, rdb *redis.Client) error {
	poolSize := float64(rdb.Options().PoolSize)
	if err := m.RegisterValkeyPool(func() metrics.ValkeyPoolStats {
		s := rdb.PoolStats()
		return metrics.ValkeyPoolStats{
			Conns: float64(s.TotalConns), IdleConns: float64(s.IdleConns), MaxConns: poolSize,
			Waits: float64(s.WaitCount), Timeouts: float64(s.Timeouts),
		}
	}); err != nil {
		return fmt.Errorf("register the valkey pool metrics: %w", err)
	}
	return nil
}

type liveNodeIDs struct{ reg *router.Registry }

func (n liveNodeIDs) LiveNodeIDs(ctx context.Context) ([]string, error) {
	nodes, err := n.reg.LiveNodes(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}
	return ids, nil
}
