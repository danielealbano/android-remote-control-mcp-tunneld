//go:build staging

package staging_test

import (
	"bufio"
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
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
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
		userRE: regexp.MustCompile(`\b` + regexp.QuoteMeta(vals["TUNNELD_STAGING_SSH_USER"]) + `\b`),
	}
}

func (e *stagingEnv) redact(s string) string {
	s = strings.ReplaceAll(s, e.domain, "<staging-domain>")
	s = strings.ReplaceAll(s, e.host, "<staging-node>")
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

func discardStderr(t *testing.T) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prev := os.Stderr
	os.Stderr = w
	drained := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, r)
		close(drained)
	}()
	t.Cleanup(func() {
		os.Stderr = prev
		_ = w.Close()
		<-drained
		_ = r.Close()
	})
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

func startTunnel(env *stagingEnv, keyPath, knownHostsPath string, edgePort, httpPort int) (*exec.Cmd, <-chan error, tunnelOutcome, error) {
	cmd := exec.Command("ssh", "-v", "-N", "-F", "/dev/null",
		"-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes", "-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile="+knownHostsPath, "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=10",
		"-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ServerAliveInterval=15",
		"-i", keyPath,
		"-R", "0.0.0.0:443:127.0.0.1:"+strconv.Itoa(edgePort),
		"-R", "0.0.0.0:80:127.0.0.1:"+strconv.Itoa(httpPort),
		env.user+"@"+env.host)
	cmd.Stdout = io.Discard
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
		_ = cmd.Process.Kill()
		<-exited
		return nil, nil, tunnelFailed, errors.New("remote forwards not confirmed within 60s")
	}
	if outcome == tunnelBusy {
		<-exited
	}
	return cmd, exited, outcome, nil
}

func openTunnel(t *testing.T, env *stagingEnv, edgePort, httpPort int) {
	t.Helper()
	dir := t.TempDir()
	keyPath := writeSecretFile(t, dir, "id", env.key)
	knownHostsPath := writeSecretFile(t, dir, "known_hosts", env.knownHosts)
	deadline := time.Now().Add(20 * time.Minute)
	for {
		cmd, exited, outcome, err := startTunnel(env, keyPath, knownHostsPath, edgePort, httpPort)
		switch outcome {
		case tunnelEstablished:
			t.Cleanup(func() {
				_ = cmd.Process.Kill()
				<-exited
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

func tunnelResponds(env *stagingEnv) bool {
	req, err := http.NewRequest(http.MethodGet, "http://"+net.JoinHostPort(env.host, "80")+"/.well-known/acme-challenge/probe", nil)
	if err != nil {
		return false
	}
	req.Host = "probe." + env.domain
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusNotFound
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
	name                    string
	leDir, gtsDir           string
	le, gts, zerossl        string
	wantCA                  string
	served, unused          string
	writeLEKey, writeGTSKey bool
}

func runStagingCase(t *testing.T, env *stagingEnv, tc stagingCase, redisURL, s3URL, access, secret string, edgePort, httpPort int) {
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
	if tc.writeGTSKey {
		writeAccountKey(t, accountDir, "gts", env.gtsKey)
	}
	enrollHost := randomLabel(t, "e") + "." + env.domain
	controlHost := randomLabel(t, "c") + "." + env.domain
	edgeAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(edgePort))
	meshAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(freeLocalPort(t)))

	cfg := config.ServeCmd{
		RedisURL: redisURL, Listen: edgeAddr, MeshListen: meshAddr,
		InternalListen: net.JoinHostPort("127.0.0.1", strconv.Itoa(freeLocalPort(t))),
		MeshAdvertise:  meshAddr, MeshPoolSize: 4, MeshCertTTL: 24 * time.Hour,
		TunnelDomain: env.domain, EnrollHost: enrollHost, ControlHost: controlHost, NameLength: 10,
		CACert: caCert, CAKey: caKey, CertValidity: 4380 * time.Hour,
		S3Endpoint: s3URL, S3Region: "us-east-1", S3Bucket: stagingBucket,
		S3AccessKey: access, S3SecretKey: secret, S3ForcePathStyle: true,
		RegistryClaimTimeout: 3 * time.Second, RegistryClaimSettle: 5 * time.Second,
		AttestSignerDigestFile: signers,
		AttestRootURL:          "http://127.0.0.1:1/root", AttestStatusURL: "http://127.0.0.1:1/status",
		AttestRefresh: time.Hour, AttestStatusMaxStale: 24 * time.Hour, AttestationOptional: true,
		ACMEDirLE: tc.leDir, ACMEDirGTS: tc.gtsDir, ACMEDirZeroSSL: unreachableDir,
		ACMEEmail: "ops@free.example.com", ACMELEProfile: "shortlived", ACMEGTSValidity: 168 * time.Hour,
		ACMEAccountDir: accountDir, ACMEDNSProvider: "",
		ACMEChallengeLE: tc.le, ACMEChallengeGTS: tc.gts, ACMEChallengeZeroSSL: tc.zerossl,
		ACMEHTTPListen:      net.JoinHostPort("127.0.0.1", strconv.Itoa(httpPort)),
		ACMECooldownDefault: time.Second, ACMEBackoffInitial: time.Second, ACMEBackoffMax: 5 * time.Second,
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

	logs := tunneltest.NewLogCounter()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, cfg, logs.Logger(), "staging") }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("server did not drain within 30s")
		}
	}()

	if !waitTrue(60*time.Second, func() bool { return tunnelResponds(env) }) {
		t.Fatal("the reverse tunnel never reached the local HTTP-01 listener")
	}
	if !waitTrue(5*time.Minute, func() bool {
		for _, host := range []string{enrollHost, controlHost} {
			if _, err := os.Stat(filepath.Join(accountDir, "self", host, "bundle.json")); err != nil {
				return false
			}
		}
		return true
	}) {
		t.Fatal("the staging CA never issued both reserved-host certificates")
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

func TestStaging_ACMEValidation(t *testing.T) {
	if os.Getenv("TUNNELD_STAGING_SSH_KEY") == "" {
		t.Skip("TUNNELD_STAGING_SSH_KEY is not set; the real-CA staging tier needs the staging node")
	}
	env := loadStagingEnv(t)
	discardStderr(t)
	t.Setenv("TUNNELD_ALLOW_ATTESTATION_OPTIONAL", "1")

	redisURL := tunneltest.StartValkey(t)
	s3URL, access, secret := tunneltest.StartMinIO(t)
	tunneltest.EnsureS3Bucket(t, s3URL, access, secret, stagingBucket)
	edgePort, httpPort := freeLocalPort(t), freeLocalPort(t)
	openTunnel(t, env, edgePort, httpPort)

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
			wantCA: "gts", served: alpnServed, unused: httpServed, writeGTSKey: true,
		},
		{
			name: "gts-http-01", leDir: unreachableDir, gtsDir: gtsStagingDir,
			le: config.ChallengeHTTP01, gts: config.ChallengeHTTP01, zerossl: config.ChallengeHTTP01,
			wantCA: "gts", served: httpServed, unused: alpnServed, writeGTSKey: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runStagingCase(t, env, tc, redisURL, s3URL, access, secret, edgePort, httpPort)
		})
	}
}
