// Package server assembles and runs the E2E tunneld process: Valkey, internal CA, ban engine, routing
// registry + node registry, the limiter, the durable store, the attestation verifier, the ACME chain,
// the enrollment service + handler, the phone control plane, the replica mesh, the public SNI edge, the
// internal metrics/admin server, and the background schedulers — with graceful shutdown. See
// docs/ARCHITECTURE.md for the system map.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/net/http2"
	"golang.org/x/sync/errgroup"

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
)

const (
	readHeaderTimeout   = 10 * time.Second
	renewalScanInterval = time.Hour
)

// Run constructs every component and runs the process until ctx is cancelled, then drains gracefully.
func Run(ctx context.Context, cfg config.ServeCmd, logger *slog.Logger, version string) error {
	redisOpts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return err
	}
	rdb := redis.NewClient(redisOpts)
	defer func() { _ = rdb.Close() }()

	nodeID := newNodeID()
	nodeHost := hostname()
	nodeStart := nodeStartStamp()
	logger = logger.With("node", nodeID, "version", version)

	caObj, err := ca.Load(cfg.CACert, cfg.CAKey, cfg.CertValidity)
	if err != nil {
		return err
	}

	// Ban engine + watcher.
	banEng := ban.NewEngine()
	if err := banEng.Load(cfg.BanFile, cfg.DBIPCountryLiteCSV, logger); err != nil {
		logger.Warn("initial ban load failed", "err", err)
	}
	banIP := func(ip netip.Addr) bool { _, b := banEng.Match(ip); return b }
	banTunnel := func(name, fp string) bool { _, b := banEng.MatchTunnel(name, fp); return b }

	// Control-plane primitives.
	reg := router.NewRegistry(rdb, cfg.RouteTTL)
	// These flags were already parsed + range-checked by cfg.Validate() at startup; a parse error
	// here is impossible, so the errors are intentionally ignored (same for every mustBytes call).
	bwRate, _ := config.ParseBitrate(cfg.LimitBandwidth)
	dayCap, _ := config.ParseByteSize(cfg.LimitTrafficDay)
	weekCap, _ := config.ParseByteSize(cfg.LimitTrafficWeek)
	lim := limit.NewLimiter(rdb, bwRate, dayCap, weekCap)

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
	adminStore := admin.NewStore(rdb, time.Hour)
	capLogger := caplog.New(logger)
	rec := metrics.NewPromRecorder(m, capLogger, adminStore, logger)

	// Attestation verifier (fail-closed until the roots/status refreshers succeed; refreshers started
	// on the errgroup below). A signer-allowlist load failure is a fatal configuration error.
	verifier, attRoots, attStatus, attSigners, err := buildVerifier(ctx, cfg, logger)
	if err != nil {
		return err
	}

	// ACME chain (lazy self-healing lego clients; DNS-01 provider selected by --acme-dns-provider).
	chain := buildACMEChain(cfg, lim, rec, logger)

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
	enrollBody, _ := config.ParseByteSize(cfg.LimitEnrollBody) // pre-validated by cfg.Validate()
	enrollHandler := enroll.NewHandler(enrollSvc, banIP, rec, enrollBody)

	// Phone control plane.
	phoneMgr := phoneconn.NewManager(phoneconn.Config{
		Router: reg, Logs: st, Recorder: rec, Logger: logger,
		NodeID: nodeID, NodeHost: nodeHost, NodeStart: nodeStart,
		RouteTTL: cfg.RouteTTL,
	})
	phoneHandler := phoneconn.NewHandler(phoneconn.HandlerConfig{
		Manager: phoneMgr, ValidName: validNameFunc(cfg), BanIP: banIP, BanTunnel: banTunnel,
		Reject:       rec.Reject,
		PingInterval: cfg.ControlPingInterval, StreamPending: cfg.LimitStreamPending,
		OnIssue: issueFunc(enrollSvc),
	})

	// Mesh cert (hot-swappable) + client + listener.
	meshCert := newMeshCertHolder(caObj, nodeID, cfg.MeshCertTTL, logger)
	meshClient := mesh.NewClient(meshCert.clientTLS(caObj), cfg.MeshPoolSize, cfg.MeshPoolMax, mesh.WithRecorder(rec))
	meshHandler := mesh.NewHandler(phoneMgr.OwnsConn, &bridgeAdapter{mgr: phoneMgr, dialBackTimeout: cfg.LimitDialBackTimeout})

	// Public edge.
	rawLn, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Listen, err)
	}
	ed := edge.New(edge.Config{
		EnrollHost: cfg.EnrollHost, ControlHost: cfg.ControlHost, TunnelDomain: cfg.TunnelDomain,
		MaxClients: cfg.MaxClients, ConnRate: cfg.LimitConnRate,
		Concurrent: cfg.LimitConcurrent, HandshakeTimeout: cfg.HandshakeTimeout, DialBackTimeout: cfg.LimitDialBackTimeout,
		IdleTimeout: cfg.LimitConnIdle, MinGrace: cfg.LimitConnMinGrace, EvictIdle: cfg.LimitConnEvictIdle,
		MinRate: mustBytes(cfg.LimitConnMinRate), ProtectRate: mustBytes(cfg.LimitConnProtectRate),
	}, rdb, banIP, banTunnel, rec,
		reg, phoneMgr, meshClient, lim, &edgeLogSink{st: st, logger: logger, nodeHost: nodeHost, nodeStart: nodeStart}, rawLn.Addr())

	// Reserved-host certs (ObtainSelf via the ACME chain, disk-persisted per node, degraded start).
	reserved := newReservedCerts(ctx, cfg.ACMEAccountDir, []string{cfg.EnrollHost, cfg.ControlHost},
		chain.ObtainSelf, chain.ShouldRenew, cfg.ACMERenewMargin, logger)

	// Reserved-host TLS terminators (enroll: server-TLS HTTP/1.1; control: HTTP/2 + mTLS with ConnMeta).
	// The enroll server is an UNAUTHENTICATED surface: its requests are small and short, so both the
	// full-request read and keep-alive idling are tightly bounded (idle TLS conns must not accumulate).
	enrollSrv := &http.Server{Handler: enrollHandler, ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout: 30 * time.Second, IdleTimeout: time.Minute,
		TLSConfig: &tls.Config{GetCertificate: reserved.getCertificateFor(cfg.EnrollHost), MinVersion: tls.VersionTLS12}}
	// The control server's idle timeout closes mTLS-authenticated HTTP/2 conns holding NO active stream
	// (a bound phone always keeps its /control stream open, so real connections are never idle).
	controlSrv := &http.Server{Handler: phoneHandler, ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout: 4 * cfg.ControlPingInterval,
		ConnContext: phoneconn.ConnContext,
		TLSConfig: &tls.Config{GetCertificate: reserved.getCertificateFor(cfg.ControlHost),
			ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: caObj.Pool(), MinVersion: tls.VersionTLS12}}
	if err := http2.ConfigureServer(controlSrv, &http2.Server{}); err != nil {
		return fmt.Errorf("configure control http2: %w", err)
	}

	// Mesh listener (mTLS mesh-role, HTTP/2).
	meshLn, err := net.Listen("tcp", cfg.MeshListen)
	if err != nil {
		return fmt.Errorf("mesh listen %s: %w", cfg.MeshListen, err)
	}
	meshSrv := &http.Server{Handler: meshHandler, ReadHeaderTimeout: readHeaderTimeout,
		TLSConfig: &tls.Config{GetCertificate: meshCert.getCert, ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs: caObj.Pool(), MinVersion: tls.VersionTLS12}}
	if err := http2.ConfigureServer(meshSrv, &http2.Server{}); err != nil {
		return fmt.Errorf("configure mesh http2: %w", err)
	}

	// Internal server (metrics + healthz + admin; never proxied).
	internalSrv := &http.Server{Addr: cfg.InternalListen, ReadHeaderTimeout: readHeaderTimeout,
		Handler: metrics.Handler(m.Registry(), rdb, adminStore, logger)}

	g, gctx := errgroup.WithContext(ctx)

	// Startup provisioning (best-effort at boot, then retried until it lands — the 90d/30d retention
	// rules are a documented compliance property, so one transient S3 error must not skip them).
	g.Go(func() error { return ensureLifecyclesRetry(gctx, st, logger) })

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
	g.Go(func() error { return serveInternal(gctx, internalSrv, logger) })

	// Edge accept loop.
	g.Go(func() error { ed.Serve(gctx, rawLn); return nil })

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
	g.Go(func() error { return heartbeatNode(gctx, reg, nodeID, cfg.MeshAdvertise, cfg.RouteTTL, logger) })
	g.Go(func() error { meshCert.rotateLoop(gctx, caObj); return nil })
	g.Go(func() error { return reserved.runRenewal(gctx, renewalScanInterval) })
	g.Go(func() error {
		rw := &renewalWatcher{mgr: phoneMgr, names: st, chain: chain, nonce: challengeFunc(enrollSvc), logger: logger}
		return rw.run(gctx, renewalScanInterval)
	})

	// Ban watcher with the live eviction hook.
	g.Go(func() error {
		ban.Watch(gctx, banEng, cfg.BanFile, cfg.DBIPCountryLiteCSV, cfg.BanPoll, func(e *ban.Engine) {
			phoneMgr.EvictBanned(func(name, fp string) bool { _, b := e.MatchTunnel(name, fp); return b })
		}, logger)
		return nil
	})

	<-gctx.Done()
	// Shutdown order: stop accepting new public connections → drain the HTTP servers → the schedulers +
	// phone/mesh goroutines unwind on gctx. Route/node entries are TTL'd, so deregistration is implicit.
	sctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()
	_ = rawLn.Close()
	_ = enrollSrv.Shutdown(sctx)
	_ = controlSrv.Shutdown(sctx)
	_ = meshSrv.Shutdown(sctx)
	_ = internalSrv.Shutdown(sctx)
	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// mustBytes parses a byte-size flag ALREADY validated by cfg.Validate() — a parse error is impossible.
func mustBytes(s string) int64 { n, _ := config.ParseByteSize(s); return n }
