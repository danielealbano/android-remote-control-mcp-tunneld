//go:build staging

package staging_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/client"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/server"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

const (
	leStagingDir   = "https://acme-staging-v02.api.letsencrypt.org/directory"
	gtsStagingDir  = "https://dv.acme-v02.test-api.pki.goog/directory"
	unreachableDir = "https://127.0.0.1:1/dir"
	alpnServed     = "acme tls-alpn-01 challenge served"
	httpServed     = "acme http-01 challenge served"
	stagingBucket  = "tunneld-staging"
)

type stagingEnv struct {
	host, user, domain string
	key, knownHosts    string
	gtsKey, leKey      string
	userRE             *regexp.Regexp
	fingerprintRE      *regexp.Regexp
	remoteVersionRE    *regexp.Regexp
}

func loadStagingEnv(t *testing.T) *stagingEnv {
	t.Helper()
	vals := map[string]string{}
	for _, name := range []string{
		"TUNNELD_STAGING_SSH_HOST", "TUNNELD_STAGING_SSH_USER", "TUNNELD_STAGING_SSH_KEY",
		"TUNNELD_STAGING_SSH_KNOWN_HOSTS", "TUNNELD_STAGING_DOMAIN",
		"TUNNELD_STAGING_GTS_ACCOUNT_KEY", "TUNNELD_STAGING_LE_ACCOUNT_KEY",
	} {
		v := os.Getenv(name)
		if v == "" {
			t.Fatalf("%s must be set when TUNNELD_STAGING_SSH_KEY is", name)
		}
		vals[name] = v
	}
	return &stagingEnv{
		host: vals["TUNNELD_STAGING_SSH_HOST"], user: vals["TUNNELD_STAGING_SSH_USER"],
		domain: vals["TUNNELD_STAGING_DOMAIN"], key: vals["TUNNELD_STAGING_SSH_KEY"],
		knownHosts: vals["TUNNELD_STAGING_SSH_KNOWN_HOSTS"],
		gtsKey:     vals["TUNNELD_STAGING_GTS_ACCOUNT_KEY"], leKey: vals["TUNNELD_STAGING_LE_ACCOUNT_KEY"],
		userRE:          regexp.MustCompile(`\b` + regexp.QuoteMeta(vals["TUNNELD_STAGING_SSH_USER"]) + `\b`),
		fingerprintRE:   regexp.MustCompile(`SHA256:[A-Za-z0-9+/=]+`),
		remoteVersionRE: regexp.MustCompile(`(remote software version|compat_banner: match:) .*?( pat |$)`),
	}
}

func (e *stagingEnv) redact(s string) string {
	s = strings.ReplaceAll(s, e.domain, "<staging-domain>")
	s = strings.ReplaceAll(s, e.host, "<staging-node>")
	s = e.fingerprintRE.ReplaceAllString(s, "SHA256:<redacted>")
	s = e.remoteVersionRE.ReplaceAllString(s, "$1 <redacted>$2")
	return e.userRE.ReplaceAllString(s, "<staging-user>")
}

func writeSecretFile(t *testing.T, dir, name, value string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(strings.TrimRight(value, "\r\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

type redactingWriter struct {
	mu      sync.Mutex
	redact  func(string) string
	out     io.Writer
	pending []byte
}

func (w *redactingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending = append(w.pending, p...)
	for {
		i := bytes.IndexByte(w.pending, '\n')
		if i < 0 {
			return len(p), nil
		}
		line := string(w.pending[:i])
		w.pending = w.pending[i+1:]
		if _, err := io.WriteString(w.out, w.redact(line)+"\n"); err != nil {
			return len(p), err
		}
	}
}

func (w *redactingWriter) flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.pending) == 0 {
		return nil
	}
	_, err := io.WriteString(w.out, w.redact(string(w.pending))+"\n")
	w.pending = nil
	return err
}

func redirectOutput(t *testing.T, env *stagingEnv) *redactingWriter {
	t.Helper()
	out := &redactingWriter{redact: env.redact, out: os.Stdout}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prevStderr, prevLog := os.Stderr, log.Writer()
	os.Stderr = w
	log.SetOutput(w)
	copied := make(chan error, 1)
	go func() {
		_, err := io.Copy(out, r)
		copied <- err
	}()
	t.Cleanup(func() {
		os.Stderr = prevStderr
		log.SetOutput(prevLog)
		if err := w.Close(); err != nil {
			t.Errorf("close the redirected stderr pipe: %v", err)
		}
		if err := <-copied; err != nil {
			t.Errorf("copy the redirected output: %v", err)
		}
		if err := r.Close(); err != nil {
			t.Errorf("close the redirected stderr reader: %v", err)
		}
		if err := out.flush(); err != nil {
			t.Errorf("flush the redirected output: %v", err)
		}
	})
	return out
}

func freeLocalPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

type tunnelOutcome int

const (
	tunnelEstablished tunnelOutcome = iota
	tunnelBusy
	tunnelFailed
)

func startTunnel(t *testing.T, env *stagingEnv, out io.Writer, keyPath, knownHostsPath string, edgePort, httpPort int) (*exec.Cmd, <-chan error, tunnelOutcome, error) {
	cmd := exec.Command("ssh", "-v", "-N", "-F", "/dev/null",
		"-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes", "-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile="+knownHostsPath, "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=10",
		"-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ServerAliveInterval=15",
		"-i", keyPath,
		"-R", "0.0.0.0:443:127.0.0.1:"+strconv.Itoa(edgePort),
		"-R", "0.0.0.0:80:127.0.0.1:"+strconv.Itoa(httpPort),
		env.user+"@"+env.host)
	cmd.Stdout = out
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, tunnelFailed, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, tunnelFailed, err
	}
	signal := make(chan tunnelOutcome, 1)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		var ok443, ok80, sent bool
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			line := sc.Text()
			if _, err := io.WriteString(out, "ssh: "+line+"\n"); err != nil {
				t.Errorf("write ssh output: %v", err)
			}
			if sent {
				continue
			}
			switch {
			case strings.Contains(line, "remote port forwarding failed"):
				signal <- tunnelBusy
				sent = true
			case strings.Contains(line, "remote forward success for: listen 0.0.0.0:443,"):
				ok443 = true
			case strings.Contains(line, "remote forward success for: listen 0.0.0.0:80,"):
				ok80 = true
			}
			if !sent && ok443 && ok80 {
				signal <- tunnelEstablished
				sent = true
			}
		}
		if err := sc.Err(); err != nil {
			t.Errorf("read ssh output: %v", err)
		}
	}()
	exited := make(chan error, 1)
	go func() {
		<-drained
		exited <- cmd.Wait()
	}()
	var outcome tunnelOutcome
	select {
	case outcome = <-signal:
	case <-drained:
		select {
		case outcome = <-signal:
		default:
			return nil, nil, tunnelFailed, <-exited
		}
	case <-time.After(60 * time.Second):
		killErr := cmd.Process.Kill()
		waitExited(t, env, exited)
		if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
			return nil, nil, tunnelFailed, fmt.Errorf("remote forwards not confirmed within 60s; kill ssh: %w", killErr)
		}
		return nil, nil, tunnelFailed, errors.New("remote forwards not confirmed within 60s")
	}
	if outcome == tunnelBusy {
		waitExited(t, env, exited)
	}
	return cmd, exited, outcome, nil
}

func waitExited(t *testing.T, env *stagingEnv, exited <-chan error) {
	t.Helper()
	err := <-exited
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Logf("ssh wait: %s", env.redact(err.Error()))
	}
}

func openTunnel(t *testing.T, env *stagingEnv, out io.Writer, edgePort, httpPort int) {
	t.Helper()
	dir := t.TempDir()
	keyPath := writeSecretFile(t, dir, "id", env.key)
	knownHostsPath := writeSecretFile(t, dir, "known_hosts", env.knownHosts)
	deadline := time.Now().Add(20 * time.Minute)
	for {
		cmd, exited, outcome, err := startTunnel(t, env, out, keyPath, knownHostsPath, edgePort, httpPort)
		switch outcome {
		case tunnelEstablished:
			t.Cleanup(func() {
				if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
					t.Errorf("stop the ssh tunnel: %v", err)
				}
				waitExited(t, env, exited)
			})
			return
		case tunnelBusy:
			if time.Now().After(deadline) {
				t.Fatal("remote forward ports busy")
			}
			t.Log("remote forward ports busy; retrying in 15s")
			time.Sleep(15 * time.Second)
		default:
			msg := "ssh tunnel failed"
			if err != nil {
				msg += ": " + err.Error()
			}
			t.Fatal(env.redact(msg))
		}
	}
}

func writeCA(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tunneld-staging-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "ca.pem")
	keyPath = filepath.Join(dir, "ca-key.pem")
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func randomLabel(t *testing.T, prefix string) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return prefix + hex.EncodeToString(b[:])
}

func waitTrue(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Second)
	}
	return false
}

func tunnelResponds(env *stagingEnv) error {
	req, err := http.NewRequest(http.MethodGet, "http://"+net.JoinHostPort(env.host, "80")+"/.well-known/acme-challenge/probe", nil)
	if err != nil {
		return err
	}
	req.Host = "probe." + env.domain
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(io.Discard, resp.Body)
	if err := errors.Join(copyErr, resp.Body.Close()); err != nil {
		return err
	}
	if resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("probe status %d, want 404", resp.StatusCode)
	}
	return nil
}

func bundleTrustPool(t *testing.T, env *stagingEnv, accountDir string, hosts ...string) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	for _, host := range hosts {
		raw, err := os.ReadFile(filepath.Join(accountDir, "self", host, "bundle.json"))
		if err != nil {
			t.Fatal(env.redact(err.Error()))
		}
		var b struct {
			CertPEM string `json:"cert_pem"`
		}
		if err := json.Unmarshal(raw, &b); err != nil {
			t.Fatal(env.redact(err.Error()))
		}
		if !pool.AppendCertsFromPEM([]byte(b.CertPEM)) {
			t.Fatalf("bundle for %s holds no certificate", env.redact(host))
		}
	}
	return pool
}

type stagingCase struct {
	name             string
	leDir, gtsDir    string
	le, gts, zerossl string
	wantCA           string
	served, unused   string
	writeLEKey       bool
}

func runStagingCase(t *testing.T, env *stagingEnv, out io.Writer, tc stagingCase, redisURL, s3URL, access, secret string, edgePort, httpPort int) {
	t.Helper()
	caCert, caKey := writeCA(t)
	signers := filepath.Join(t.TempDir(), "signers.txt")
	if err := os.WriteFile(signers, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	accountDir := t.TempDir()
	if tc.writeLEKey {
		writeAccountKey(t, accountDir, "letsencrypt", env.leKey)
	}
	writeAccountKey(t, accountDir, "gts", env.gtsKey)
	enrollHost := randomLabel(t, "e") + "." + env.domain
	controlHost := randomLabel(t, "c") + "." + env.domain
	edgeAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(edgePort))
	meshAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(freeLocalPort(t)))

	cfg := config.ServeCmd{
		RedisURL: redisURL, Listen: edgeAddr, MeshListen: meshAddr,
		InternalListen: net.JoinHostPort("127.0.0.1", strconv.Itoa(freeLocalPort(t))),
		MeshAdvertise:  meshAddr, MeshPoolSize: 4, MeshCertTTL: 24 * time.Hour,
		TunnelDomain: env.domain, EnrollHost: enrollHost, ControlHost: controlHost, NameLength: 10,
		DialBackAdvertise: edgeAddr, DialBackHTTPS: true, DialBackMTLS: true,
		CACert: caCert, CAKey: caKey, CertValidity: 4380 * time.Hour,
		S3Endpoint: s3URL, S3Region: "us-east-1", S3Bucket: stagingBucket,
		S3AccessKey: access, S3SecretKey: secret, S3ForcePathStyle: true,
		RegistryClaimTimeout: 3 * time.Second, RegistryClaimSettle: 5 * time.Second,
		AttestSignerDigestFile: signers,
		AttestRootURL:          "http://127.0.0.1:1/root", AttestStatusURL: "http://127.0.0.1:1/status",
		AttestRefresh: time.Hour, AttestStatusMaxStale: 24 * time.Hour, AttestationOptional: true,
		ACMEDirLE: tc.leDir, ACMEDirGTS: tc.gtsDir, ACMEDirZeroSSL: unreachableDir,
		ACMEEmail: "ops@free.example.com", ACMELEProfile: "shortlived", ACMEGTSValidity: 168 * time.Hour,
		ACMEAccountDir: accountDir, ACMEDNSProvider: "", ConnLogDir: t.TempDir(),
		ACMEChallengeLE: tc.le, ACMEChallengeGTS: tc.gts, ACMEChallengeZeroSSL: tc.zerossl,
		ACMEHTTPListen:    net.JoinHostPort("127.0.0.1", strconv.Itoa(httpPort)),
		ACMEEABZeroSSLKID: "changeme", ACMEEABZeroSSLHMAC: "changeme",
		ACMEGTSAccounts:           []string{"gts"},
		ACMEBudgetLEDomain:        "50/168h",
		ACMEBudgetLEOrders:        "300/3h",
		ACMEBudgetLEName:          "5/168h",
		ACMEBudgetGTSOrders:       "100/1h",
		ACMEBudgetGTSRequests:     "120/1m",
		ACMEBudgetGTSCertPolls:    "50/1m",
		ACMEBudgetZeroSSLOrders:   "200/1h:40",
		ACMEBudgetZeroSSLRequests: "240/1m",
		ACMEAttemptTimeoutLE:      20 * time.Second,
		ACMEAttemptTimeoutGTS:     40 * time.Second,
		ACMEAttemptTimeoutZeroSSL: 90 * time.Second,
		ACMEPollFirstLE:           2 * time.Second,
		ACMEPollFirstGTS:          5600 * time.Millisecond,
		ACMEPollFirstZeroSSL:      15200 * time.Millisecond,
		ACMEPollInterval:          2 * time.Second,
		ACMECooldownDefault:       time.Second, ACMEBackoffInitial: time.Second, ACMEBackoffMax: 5 * time.Second,
		ACMERenewMargin: 48 * time.Hour, IssuePerWeek: 10,
		RouteTTL: 30 * time.Second, ControlPingInterval: 30 * time.Second,
		LimitStreamPending: 64, LimitEnrollHour: 50, LimitEnrollMinute: 10, LimitEnrollBody: "64kb",
		MaxClients: 100, LimitConnRate: 100, LimitConcurrent: 8, LimitPackets: 100000, HandshakeTimeout: 5 * time.Second, LimitDialBackTimeout: 10 * time.Second,
		LimitConnIdle: 120 * time.Second, LimitConnMinGrace: 60 * time.Second, LimitConnEvictIdle: 1 * time.Second,
		LimitConnMinRate: "1kb", LimitConnProtectRate: "1mb", LimitBandwidth: "10mbit",
		LimitTrafficDay: "1gb", LimitTrafficWeek: "4gb",
		BanPoll: time.Second, ShutdownGrace: 3 * time.Second, Log: []string{"output=std;level=error"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config invalid: %s", env.redact(err.Error()))
	}

	logs := tunneltest.NewLogCounter(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	var runErr error
	runReported := false
	stopped := make(chan struct{})
	go func() {
		runErr = server.Run(ctx, cfg, logs.Logger(), "staging")
		close(stopped)
	}()
	defer func() {
		cancel()
		select {
		case <-stopped:
			if runErr != nil && !runReported {
				t.Errorf("server run: %s", env.redact(runErr.Error()))
			}
		case <-time.After(30 * time.Second):
			t.Error("server did not drain within 30s")
		}
	}()
	failIfStopped := func() {
		select {
		case <-stopped:
			runReported = true
			t.Fatalf("the server exited early: %s", env.redact(fmt.Sprint(runErr)))
		default:
		}
	}

	var probeErr error
	if !waitTrue(60*time.Second, func() bool {
		failIfStopped()
		probeErr = tunnelResponds(env)
		return probeErr == nil
	}) {
		t.Fatalf("the reverse tunnel never reached the local HTTP-01 listener: %s", env.redact(probeErr.Error()))
	}
	var bundleErr error
	if !waitTrue(5*time.Minute, func() bool {
		failIfStopped()
		for _, host := range []string{enrollHost, controlHost} {
			if _, bundleErr = os.Stat(filepath.Join(accountDir, "self", host, "bundle.json")); bundleErr != nil {
				return false
			}
		}
		return true
	}) {
		t.Fatalf("the staging CA never issued both reserved-host certificates: %s", env.redact(bundleErr.Error()))
	}

	roots := bundleTrustPool(t, env, accountDir, enrollHost, controlHost)
	enrollCtx, enrollCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer enrollCancel()
	ident, err := client.Enroll(enrollCtx, edgeAddr, enrollHost, controlHost, env.domain, roots)
	if err != nil {
		t.Fatalf("enroll: %s", env.redact(err.Error()))
	}
	if ident.CA != tc.wantCA {
		t.Fatalf("issuing CA = %q, want %q", ident.CA, tc.wantCA)
	}
	block, _ := pem.Decode(ident.PublicCertPEM)
	if block == nil {
		t.Fatal("public certificate is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(env.redact(err.Error()))
	}
	wantSAN := ident.Name + "." + env.domain
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != wantSAN {
		t.Fatalf("public certificate SANs = %s, want exactly <name>.<staging-domain>", env.redact(strings.Join(leaf.DNSNames, ",")))
	}
	if logs.Count(tc.served) < 1 {
		t.Fatalf("no %q record: the configured method did not answer", tc.served)
	}
	if n := logs.Count(tc.unused); n != 0 {
		t.Fatalf("%d %q records: the other method answered", n, tc.unused)
	}
}

func writeAccountKey(t *testing.T, accountDir, caID, value string) {
	t.Helper()
	dir := filepath.Join(accountDir, "accounts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeSecretFile(t, dir, caID+".key", value)
}

func TestStagingEnv_Redact(t *testing.T) {
	for name, value := range map[string]string{
		"TUNNELD_STAGING_SSH_HOST": "192.0.2.10", "TUNNELD_STAGING_SSH_USER": "root", "TUNNELD_STAGING_SSH_KEY": "changeme",
		"TUNNELD_STAGING_SSH_KNOWN_HOSTS": "changeme", "TUNNELD_STAGING_DOMAIN": "staging.example.test",
		"TUNNELD_STAGING_GTS_ACCOUNT_KEY": "changeme", "TUNNELD_STAGING_LE_ACCOUNT_KEY": "changeme",
	} {
		t.Setenv(name, value)
	}
	env := loadStagingEnv(t)
	tests := []struct{ in, want string }{
		{in: "debug1: Authenticating to 192.0.2.10:22 as 'root'", want: "debug1: Authenticating to <staging-node>:22 as '<staging-user>'"},
		{in: "issued e1a2b3c4.staging.example.test", want: "issued e1a2b3c4.<staging-domain>"},
		{in: "debug1: Server host key: ssh-ed25519 SHA256:Ab+/09xYz=", want: "debug1: Server host key: ssh-ed25519 SHA256:<redacted>"},
		{in: "debug1: Offering public key: /tmp/id ED25519 SHA256:Ab+/09xYz explicit", want: "debug1: Offering public key: /tmp/id ED25519 SHA256:<redacted> explicit"},
		{in: "debug1: Remote protocol version 2.0, remote software version OpenSSH_9.9p1 Distro-1", want: "debug1: Remote protocol version 2.0, remote software version <redacted>"},
		{in: "debug1: compat_banner: match: OpenSSH_9.9p1 Distro-1 pat OpenSSH* compat 0x04000000", want: "debug1: compat_banner: match: <redacted> pat OpenSSH* compat 0x04000000"},
		{in: "debug1: Local version string SSH-2.0-OpenSSH_9.6p1", want: "debug1: Local version string SSH-2.0-OpenSSH_9.6p1"},
		{in: "/rooted/path", want: "/rooted/path"},
	}
	for _, tc := range tests {
		if got := env.redact(tc.in); got != tc.want {
			t.Errorf("redact(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestStaging_ACMEValidation(t *testing.T) {
	if os.Getenv("TUNNELD_STAGING_SSH_KEY") == "" {
		t.Skip("TUNNELD_STAGING_SSH_KEY is not set; the real-CA staging tier needs the staging node")
	}
	env := loadStagingEnv(t)
	out := redirectOutput(t, env)
	t.Setenv("TUNNELD_ALLOW_ATTESTATION_OPTIONAL", "1")

	redisURL := tunneltest.StartValkey(t)
	s3URL, access, secret := tunneltest.StartMinIO(t)
	tunneltest.EnsureS3Bucket(t, s3URL, access, secret, stagingBucket)
	edgePort, httpPort := freeLocalPort(t), freeLocalPort(t)
	openTunnel(t, env, out, edgePort, httpPort)

	cases := []stagingCase{
		{
			name: "le-tls-alpn-01", leDir: leStagingDir, gtsDir: unreachableDir,
			le: config.ChallengeTLSALPN01, gts: config.ChallengeTLSALPN01, zerossl: config.ChallengeHTTP01,
			wantCA: "letsencrypt", served: alpnServed, unused: httpServed, writeLEKey: true,
		},
		{
			name: "le-http-01", leDir: leStagingDir, gtsDir: unreachableDir,
			le: config.ChallengeHTTP01, gts: config.ChallengeHTTP01, zerossl: config.ChallengeHTTP01,
			wantCA: "letsencrypt", served: httpServed, unused: alpnServed, writeLEKey: true,
		},
		{
			name: "gts-tls-alpn-01", leDir: unreachableDir, gtsDir: gtsStagingDir,
			le: config.ChallengeTLSALPN01, gts: config.ChallengeTLSALPN01, zerossl: config.ChallengeHTTP01,
			wantCA: "gts", served: alpnServed, unused: httpServed,
		},
		{
			name: "gts-http-01", leDir: unreachableDir, gtsDir: gtsStagingDir,
			le: config.ChallengeHTTP01, gts: config.ChallengeHTTP01, zerossl: config.ChallengeHTTP01,
			wantCA: "gts", served: httpServed, unused: alpnServed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runStagingCase(t, env, out, tc, redisURL, s3URL, access, secret, edgePort, httpPort)
		})
	}
}
