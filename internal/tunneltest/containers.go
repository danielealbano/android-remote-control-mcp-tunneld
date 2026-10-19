//go:build integration || e2e || staging

// SHARED testcontainers harness: ephemeral Valkey, MinIO (a plain-S3 stand-in), and a hermetic ACME test
// CA (Pebble + pebble-challtestsrv), each registered for teardown via t.Cleanup. It NEVER touches real
// Let's Encrypt / GTS / ZeroSSL. Image tags are pinned constants.

package tunneltest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Pinned container images. MinIO: a recent release with object-lifecycle support (no conditional-write
// feature is used — MinIO is a plain-S3 stand-in). Pebble + challtestsrv: the hermetic ACME test CA.
const (
	valkeyImage       = "valkey/valkey:9.1-alpine"
	minioImage        = "pgsty/silo:RELEASE.2026-09-16T00-00-00Z"
	pebbleImage       = "ghcr.io/letsencrypt/pebble:2.10.1"
	challtestsrvImage = "ghcr.io/letsencrypt/pebble-challtestsrv:2.10.1"

	// MinIO test credentials (placeholders — see project.md repository-hygiene rule).
	minioAccessKey = "test-access"
	minioSecretKey = "test-secret-changeme"

	s3Region = "us-east-1"
)

// startContainer starts one container via testcontainers-go, registering termination via t.Cleanup.
func startContainer(t *testing.T, req testcontainers.ContainerRequest) testcontainers.Container {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req, Started: true,
	})
	if err != nil {
		t.Fatalf("start container %s: %v", req.Image, err)
	}
	t.Cleanup(func() {
		if err := c.Terminate(context.Background()); err != nil {
			t.Logf("terminate container %s: %v", req.Image, err)
		}
	})
	return c
}

// endpoint returns the host:port the given exposed container port is mapped to on the host.
func endpoint(t *testing.T, c testcontainers.Container, port string) string {
	t.Helper()
	ep, err := c.PortEndpoint(context.Background(), port, "")
	if err != nil {
		t.Fatalf("container port %s: %v", port, err)
	}
	return ep
}

// newNetwork creates an ephemeral user-defined bridge network (so containers resolve each other by
// alias) and registers its removal.
func newNetwork(t *testing.T) *testcontainers.DockerNetwork {
	t.Helper()
	nw, err := tcnetwork.New(context.Background())
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	t.Cleanup(func() {
		if err := nw.Remove(context.Background()); err != nil {
			t.Logf("remove network %s: %v", nw.Name, err)
		}
	})
	return nw
}

// StartValkey starts an ephemeral Valkey (Redis-protocol) instance and returns its redis:// URL.
func StartValkey(t *testing.T) string {
	t.Helper()
	c := startContainer(t, testcontainers.ContainerRequest{
		Image:        valkeyImage,
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForListeningPort("6379/tcp"),
	})
	return "redis://" + endpoint(t, c, "6379/tcp")
}

func StartValkeySentinel(t *testing.T) (sentinelURL, masterURL string) {
	t.Helper()
	const masterName = "tunneld"
	master := startContainer(t, testcontainers.ContainerRequest{
		Image:        valkeyImage,
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForListeningPort("6379/tcp"),
	})
	ip, err := master.ContainerIP(context.Background())
	if err != nil {
		t.Fatalf("valkey master container ip: %v", err)
	}
	conf := fmt.Sprintf("port 26379\nsentinel monitor %s %s 6379 1\n", masterName, ip)
	sentinel := startContainer(t, testcontainers.ContainerRequest{
		Image:        valkeyImage,
		ExposedPorts: []string{"26379/tcp"},
		Files: []testcontainers.ContainerFile{{
			Reader: strings.NewReader(conf), ContainerFilePath: "/data/sentinel.conf", FileMode: 0o644,
		}},
		Cmd:        []string{"valkey-server", "/data/sentinel.conf", "--sentinel"},
		WaitingFor: wait.ForLog("+monitor master " + masterName),
	})
	return "redis://" + endpoint(t, sentinel, "26379/tcp") + "?master_name=" + masterName,
		"redis://" + net.JoinHostPort(ip, "6379")
}

// StartMinIO starts an ephemeral MinIO instance and returns (endpointURL, accessKey, secretKey). Use
// EnsureS3Bucket to create the target bucket.
func StartMinIO(t *testing.T) (url, access, secret string) {
	t.Helper()
	c := startContainer(t, testcontainers.ContainerRequest{
		Image:        minioImage,
		ExposedPorts: []string{"9000/tcp"},
		Env: map[string]string{
			"MINIO_ROOT_USER":     minioAccessKey,
			"MINIO_ROOT_PASSWORD": minioSecretKey,
		},
		Cmd:        []string{"server", "/data"},
		WaitingFor: wait.ForListeningPort("9000/tcp"),
	})
	return "http://" + endpoint(t, c, "9000/tcp"), minioAccessKey, minioSecretKey
}

// s3TestClient builds a path-style S3 client for the given endpoint/creds (matches store.NewS3Store's
// wiring so bucket setup uses the same addressing the store expects).
func s3TestClient(endpointURL, access, secret string) *s3.Client {
	creds := credentials.NewStaticCredentialsProvider(access, secret, "")
	return s3.New(s3.Options{
		Region:       s3Region,
		Credentials:  creds,
		BaseEndpoint: aws.String(endpointURL),
		UsePathStyle: true,
	})
}

// EnsureS3Bucket creates the bucket idempotently (already-owned is success). It retries briefly so a
// just-started MinIO that is not yet accepting API calls does not flake the test.
func EnsureS3Bucket(t *testing.T, endpointURL, access, secret, bucket string) {
	t.Helper()
	cli := s3TestClient(endpointURL, access, secret)
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, err := cli.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: aws.String(bucket)})
		if err == nil || bucketAlreadyOwned(err) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("create bucket %q: %v", bucket, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// S3ListKeys returns every object key under prefix (test assertions against real MinIO).
func S3ListKeys(t *testing.T, endpointURL, access, secret, bucket, prefix string) []string {
	t.Helper()
	cli := s3TestClient(endpointURL, access, secret)
	out, err := cli.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket), Prefix: aws.String(prefix),
	})
	if err != nil {
		t.Fatalf("list objects %q: %v", prefix, err)
	}
	keys := make([]string, 0, len(out.Contents))
	for _, o := range out.Contents {
		keys = append(keys, aws.ToString(o.Key))
	}
	return keys
}

func S3LifecycleConfigured(t *testing.T, endpointURL, access, secret, bucket string) bool {
	t.Helper()
	cli := s3TestClient(endpointURL, access, secret)
	_, err := cli.GetBucketLifecycleConfiguration(context.Background(), &s3.GetBucketLifecycleConfigurationInput{
		Bucket: aws.String(bucket),
	})
	var ae smithy.APIError
	switch {
	case err == nil:
		return true
	case errors.As(err, &ae) && ae.ErrorCode() == "NoSuchLifecycleConfiguration":
		return false
	default:
		t.Fatalf("get bucket lifecycle: %v", err)
		return false
	}
}

func bucketAlreadyOwned(err error) bool {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "BucketAlreadyOwnedByYou", "BucketAlreadyExists":
			return true
		}
	}
	return false
}

// PebbleEnv is a hermetic ACME test CA: a Pebble server whose DNS-01 validation is answered by a
// companion pebble-challtestsrv. It carries everything a caller needs to (a) point the tunneld ACME
// chain at Pebble, (b) let lego trust Pebble's ACME endpoint, (c) satisfy lego's DNS-01 propagation
// pre-check against challtestsrv, and (d) trust the leaf certs Pebble issues.
type PebbleEnv struct {
	// DirectoryURL is Pebble's ACME directory (https://127.0.0.1:<port>/dir).
	DirectoryURL string
	// MinicaPEM is Pebble's bundled test CA that signs its ACME + management endpoint certificates.
	// Feed it to lego via LEGO_CA_CERTIFICATES so the ACME client trusts Pebble.
	MinicaPEM []byte
	// MinicaFile is a temp file holding MinicaPEM (LEGO_CA_CERTIFICATES wants a path).
	MinicaFile string
	// IssuingRoots trusts the (per-run) CA Pebble signs issued leaf certificates with. A public/frontend
	// client verifying a phone's Pebble-issued cert uses this pool.
	IssuingRoots *x509.CertPool
	// IssuingRootsPEM is the raw PEM of IssuingRoots, adb-pushed to the device so the reference client
	// trusts tunneld's enroll/control server certs.
	IssuingRootsPEM []byte
	// DNSResolver is challtestsrv's DNS listener (host:port) — pass it as --acme-dns-resolver so lego's
	// DNS-01 propagation pre-check queries challtestsrv instead of the system/authoritative resolvers.
	DNSResolver string
	// ChallMgmtURL is challtestsrv's management API base (http://host:port) used to publish/clear TXT
	// records (POST /set-txt, /clear-txt).
	ChallMgmtURL string
	HostIP       string
	HTTPPort     int
	TLSPort      int
}

type pebbleSetup struct {
	hostValidation bool
	alternateRoots int
}

type PebbleOption func(*pebbleSetup) error

func WithHostValidation() PebbleOption {
	return func(s *pebbleSetup) error {
		s.hostValidation = true
		return nil
	}
}

func WithAlternateRoots(n int) PebbleOption {
	return func(s *pebbleSetup) error {
		if n < 1 {
			return fmt.Errorf("alternate roots must be >= 1, got %d", n)
		}
		s.alternateRoots = n
		return nil
	}
}

const pebbleHostConfigPath = "/test/config/pebble-host-validation.json"

func pebbleHostValidationConfig(t *testing.T, httpPort, tlsPort int) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"pebble": map[string]any{
		"listenAddress":                  "0.0.0.0:14000",
		"managementListenAddress":        "0.0.0.0:15000",
		"certificate":                    "test/certs/localhost/cert.pem",
		"privateKey":                     "test/certs/localhost/key.pem",
		"httpPort":                       httpPort,
		"tlsPort":                        tlsPort,
		"ocspResponderURL":               "",
		"externalAccountBindingRequired": false,
		"retryAfter":                     map[string]any{"authz": 3, "order": 5},
		"keyAlgorithm":                   "ecdsa",
		"profiles": map[string]any{
			"default":    map[string]any{"description": "default", "validityPeriod": 7776000},
			"shortlived": map[string]any{"description": "shortlived", "validityPeriod": 518400},
		},
	}})
	if err != nil {
		t.Fatalf("pebble host-validation config: %v", err)
	}
	return raw
}

func networkGateway(t *testing.T, nw *testcontainers.DockerNetwork) string {
	t.Helper()
	ctx := context.Background()
	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		t.Fatalf("docker client: %v", err)
	}
	defer func() {
		if err := cli.Close(); err != nil {
			t.Logf("close the docker client: %v", err)
		}
	}()
	res, err := cli.NetworkInspect(ctx, nw.ID, client.NetworkInspectOptions{})
	if err != nil {
		t.Fatalf("inspect network %s: %v", nw.Name, err)
	}
	for _, c := range res.Network.IPAM.Config {
		if c.Gateway.Is4() {
			return c.Gateway.String()
		}
	}
	t.Fatalf("network %s has no IPv4 gateway", nw.Name)
	return ""
}

func freePortOn(t *testing.T, ip string) int {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatalf("free port on %s: %v", ip, err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("release port probe on %s: %v", ip, err)
	}
	return port
}

// StartPebble starts Pebble + pebble-challtestsrv on a shared network and returns a fully-wired
// PebbleEnv. Pebble validates DNS-01 by querying challtestsrv (via the -dnsserver flag).
func StartPebble(t *testing.T, opts ...PebbleOption) *PebbleEnv {
	t.Helper()
	var setup pebbleSetup
	for _, opt := range opts {
		if err := opt(&setup); err != nil {
			t.Fatalf("pebble option: %v", err)
		}
	}
	nw := newNetwork(t)
	defaultIPv4 := "127.0.0.1"
	pebbleConfig := "/test/config/pebble-config.json"
	var files []testcontainers.ContainerFile
	var hostIP string
	var httpPort, tlsPort int
	if setup.hostValidation {
		hostIP = networkGateway(t, nw)
		httpPort, tlsPort = freePortOn(t, hostIP), freePortOn(t, hostIP)
		defaultIPv4 = hostIP
		pebbleConfig = pebbleHostConfigPath
		files = []testcontainers.ContainerFile{{
			Reader: bytes.NewReader(pebbleHostValidationConfig(t, httpPort, tlsPort)), ContainerFilePath: pebbleHostConfigPath, FileMode: 0o644,
		}}
	}

	// challtestsrv: DNS mock on 8053 (answers Pebble's validation queries) + management API on 8055.
	chal := startContainer(t, testcontainers.ContainerRequest{
		Image:          challtestsrvImage,
		ExposedPorts:   []string{"8053/tcp", "8053/udp", "8055/tcp"},
		Cmd:            []string{"-defaultIPv6", "", "-defaultIPv4", defaultIPv4},
		Networks:       []string{nw.Name},
		NetworkAliases: map[string][]string{nw.Name: {"challtestsrv"}},
		WaitingFor: wait.ForAll(
			wait.ForHTTP("/dns-request-history").WithPort("8055/tcp").WithMethod(http.MethodPost).
				WithBody(strings.NewReader(`{"host":"readiness.test"}`)),
			wait.ForNop(dnsAnswers("8053/udp")),
		).WithDeadline(pebbleStartupTimeout),
	})

	env := map[string]string{
		"PEBBLE_VA_NOSLEEP":      "1",
		"PEBBLE_WFE_NONCEREJECT": "0",
	}
	if setup.alternateRoots > 0 {
		env["PEBBLE_ALTERNATE_ROOTS"] = strconv.Itoa(setup.alternateRoots)
	}
	// Pebble: ACME directory on 14000, management (issuing roots) on 15000. NOSLEEP + no nonce rejection
	// make validation deterministic and fast for tests.
	pebble := startContainer(t, testcontainers.ContainerRequest{
		Image:          pebbleImage,
		ExposedPorts:   []string{"14000/tcp", "15000/tcp"},
		Cmd:            []string{"-config", pebbleConfig, "-dnsserver", "challtestsrv:8053"},
		Files:          files,
		Env:            env,
		Networks:       []string{nw.Name},
		NetworkAliases: map[string][]string{nw.Name: {"pebble"}},
		WaitingFor: wait.ForAll(
			pebbleHTTPSReady("/dir", "14000/tcp"),
			pebbleHTTPSReady("/roots/0", "15000/tcp"),
		).WithDeadline(pebbleStartupTimeout),
	})

	minica := copyFromContainer(t, pebble, "/test/certs/pebble.minica.pem")
	minicaFile := writeTempFile(t, "pebble-minica-*.pem", minica)

	mgmtEndpoint := endpoint(t, pebble, "15000/tcp")
	issuingRoots, issuingRootsPEM := fetchIssuingRoots(t, minica, mgmtEndpoint)

	return &PebbleEnv{
		DirectoryURL:    "https://" + endpoint(t, pebble, "14000/tcp") + "/dir",
		MinicaPEM:       minica,
		MinicaFile:      minicaFile,
		IssuingRoots:    issuingRoots,
		IssuingRootsPEM: issuingRootsPEM,
		DNSResolver:     endpoint(t, chal, "8053/udp"),
		ChallMgmtURL:    "http://" + endpoint(t, chal, "8055/tcp"),
		HostIP:          hostIP,
		HTTPPort:        httpPort,
		TLSPort:         tlsPort,
	}
}

const pebbleStartupTimeout = 60 * time.Second

func pebbleHTTPSReady(path, port string) *wait.HTTPStrategy {
	return wait.ForHTTP(path).WithPort(port).WithTLS(true).WithAllowInsecure(true).
		WithStartupTimeout(pebbleStartupTimeout)
}

func dnsAnswers(port string) func(context.Context, wait.StrategyTarget) error {
	return func(ctx context.Context, target wait.StrategyTarget) error {
		host, err := target.Host(ctx)
		if err != nil {
			return err
		}
		mapped, err := target.MappedPort(ctx, port)
		if err != nil {
			return err
		}
		addr := net.JoinHostPort(host, mapped.Port())
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		}}
		for {
			qctx, cancel := context.WithTimeout(ctx, time.Second)
			_, err := r.LookupNetIP(qctx, "ip4", "readiness.test.")
			cancel()
			if err == nil {
				return nil
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("dns %s not answering: %w", addr, err)
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
}

const pebbleEABConfig = "/test/config/pebble-config-external-account-bindings.json"

type pebbleEABConfigFile struct {
	Pebble struct {
		ExternalAccountMACKeys map[string]string `json:"externalAccountMACKeys"`
	} `json:"pebble"`
}

func StartPebbleEAB(t *testing.T) (directoryURL, minicaFile string, macKeys map[string]string) {
	t.Helper()
	c := startContainer(t, testcontainers.ContainerRequest{
		Image:        pebbleImage,
		ExposedPorts: []string{"14000/tcp"},
		Cmd:          []string{"-config", pebbleEABConfig},
		Env:          map[string]string{"PEBBLE_VA_NOSLEEP": "1", "PEBBLE_WFE_NONCEREJECT": "0"},
		WaitingFor:   pebbleHTTPSReady("/dir", "14000/tcp"),
	})
	var cfg pebbleEABConfigFile
	if err := json.Unmarshal(copyFromContainer(t, c, pebbleEABConfig), &cfg); err != nil {
		t.Fatalf("parse pebble EAB config: %v", err)
	}
	minica := copyFromContainer(t, c, "/test/certs/pebble.minica.pem")
	return "https://" + endpoint(t, c, "14000/tcp") + "/dir",
		writeTempFile(t, "pebble-eab-minica-*.pem", minica), cfg.Pebble.ExternalAccountMACKeys
}

// fetchIssuingRoots downloads Pebble's per-run issuing CA (management /roots/0), trusting the minica for
// the management endpoint's TLS, and returns a pool a frontend client uses to verify issued leaf certs.
func fetchIssuingRoots(t *testing.T, minica []byte, mgmtEndpoint string) (*x509.CertPool, []byte) {
	t.Helper()
	minicaPool := x509.NewCertPool()
	if !minicaPool.AppendCertsFromPEM(minica) {
		t.Fatal("pebble: minica PEM did not parse")
	}
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: minicaPool, MinVersion: tls.VersionTLS12}},
	}
	rootPEM := httpGet(t, client, "https://"+mgmtEndpoint+"/roots/0")
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		t.Fatal("pebble: issuing root PEM did not parse")
	}
	return pool, rootPEM
}

// PublishTXT sets a DNS-01 TXT record on challtestsrv (host MUST be the trailing-dotted
// _acme-challenge.<domain>. form). It is used by the in-test DNS shim (see StartACMEDNSShim).
func (p *PebbleEnv) PublishTXT(host, value string) error {
	return p.chalPost("/set-txt", map[string]string{"host": host, "value": value})
}

// ClearTXT removes a DNS-01 TXT record on challtestsrv.
func (p *PebbleEnv) ClearTXT(host string) error {
	return p.chalPost("/clear-txt", map[string]string{"host": host})
}

// chalMgmtTimeout bounds a challtestsrv management call so a hung management API cannot block the ACME
// DNS shim (and thus replica startup) indefinitely, matching the other timed HTTP helpers in this file.
const chalMgmtTimeout = 15 * time.Second

func (p *PebbleEnv) chalPost(path string, body map[string]string) (err error) {
	raw, err := json.Marshal(body) // string-map marshal cannot fail
	if err != nil {
		return err
	}
	hc := &http.Client{Timeout: chalMgmtTimeout}
	resp, err := hc.Post(p.ChallMgmtURL+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("challtestsrv %s: close response: %w", path, cerr))
		}
	}()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("challtestsrv %s: status %d", path, resp.StatusCode)
	}
	return nil
}

// StartACMEDNSShim starts an in-process HTTP server that adapts lego's httpreq DNS provider to
// challtestsrv: it translates POST /present {fqdn,value} → challtestsrv /set-txt {host,value} and
// POST /cleanup {fqdn,value} → challtestsrv /clear-txt {host}. Set HTTPREQ_ENDPOINT to the returned URL
// and --acme-dns-provider=httpreq so the real ACME chain publishes DNS-01 records into challtestsrv.
func StartACMEDNSShim(t *testing.T, p *PebbleEnv) (endpointURL string) {
	t.Helper()
	mux := http.NewServeMux()
	// decode returns ok=false on a malformed body or an empty fqdn, so a bad request is rejected rather
	// than silently publishing/clearing an empty-host TXT record.
	decode := func(r *http.Request) (fqdn, value string, ok bool) {
		var m struct {
			FQDN  string `json:"fqdn"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			t.Logf("acme dns shim: undecodable body: %v", err)
			return "", "", false
		}
		if m.FQDN == "" {
			return "", "", false
		}
		return m.FQDN, m.Value, true
	}
	mux.HandleFunc("/present", func(w http.ResponseWriter, r *http.Request) {
		fqdn, value, ok := decode(r)
		if !ok {
			http.Error(w, "bad present body", http.StatusBadRequest)
			return
		}
		if err := p.PublishTXT(fqdn, value); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/cleanup", func(w http.ResponseWriter, r *http.Request) {
		fqdn, _, ok := decode(r)
		if !ok {
			http.Error(w, "bad cleanup body", http.StatusBadRequest)
			return
		}
		if err := p.ClearTXT(fqdn); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// copyFromContainer reads a file out of a container.
func copyFromContainer(t *testing.T, c testcontainers.Container, path string) []byte {
	t.Helper()
	rc, err := c.CopyFileFromContainer(context.Background(), path)
	if err != nil {
		t.Fatalf("copy %s from container: %v", path, err)
	}
	defer CloseOrLog(t, rc)
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func writeTempFile(t *testing.T, pattern string, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), pattern)
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}
	return f.Name()
}

func httpGet(t *testing.T, client *http.Client, url string) []byte {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer CloseOrLog(t, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return data
}
