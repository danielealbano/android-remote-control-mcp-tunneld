//go:build integration || e2e

// SHARED testcontainers harness for the integration (//go:build integration) and e2e (//go:build e2e)
// tiers: ephemeral Valkey, MinIO (a plain-S3 stand-in), and a hermetic ACME test CA (Pebble +
// pebble-challtestsrv), each registered for teardown via t.Cleanup. It NEVER touches real Let's Encrypt /
// GTS / ZeroSSL (user decision: the automated tiers are hermetic). Image tags are pinned constants.

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
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Pinned container images. MinIO: a recent release with object-lifecycle support (no conditional-write
// feature is used — MinIO is a plain-S3 stand-in). Pebble + challtestsrv: the hermetic ACME test CA.
const (
	valkeyImage       = "valkey/valkey:9.1-alpine"
	minioImage        = "minio/minio:RELEASE.2025-09-07T16-13-09Z"
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
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
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
	t.Cleanup(func() { _ = nw.Remove(context.Background()) })
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

// S3LifecyclePrefixes returns the bucket's lifecycle expiration rules as prefix→days (test assertions).
func S3LifecyclePrefixes(t *testing.T, endpointURL, access, secret, bucket string) map[string]int32 {
	t.Helper()
	cli := s3TestClient(endpointURL, access, secret)
	out, err := cli.GetBucketLifecycleConfiguration(context.Background(), &s3.GetBucketLifecycleConfigurationInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		t.Fatalf("get bucket lifecycle: %v", err)
	}
	m := map[string]int32{}
	for _, r := range out.Rules {
		if r.Filter != nil && r.Filter.Prefix != nil && r.Expiration != nil && r.Expiration.Days != nil {
			m[*r.Filter.Prefix] = *r.Expiration.Days
		}
	}
	return m
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
}

// StartPebble starts Pebble + pebble-challtestsrv on a shared network and returns a fully-wired
// PebbleEnv. Pebble validates DNS-01 by querying challtestsrv (via the -dnsserver flag).
func StartPebble(t *testing.T) *PebbleEnv {
	t.Helper()
	nw := newNetwork(t)

	// challtestsrv: DNS mock on 8053 (answers Pebble's validation queries) + management API on 8055.
	chal := startContainer(t, testcontainers.ContainerRequest{
		Image:          challtestsrvImage,
		ExposedPorts:   []string{"8053/tcp", "8053/udp", "8055/tcp"},
		Cmd:            []string{"-defaultIPv6", "", "-defaultIPv4", "127.0.0.1"},
		Networks:       []string{nw.Name},
		NetworkAliases: map[string][]string{nw.Name: {"challtestsrv"}},
		WaitingFor:     wait.ForListeningPort("8055/tcp"),
	})

	// Pebble: ACME directory on 14000, management (issuing roots) on 15000. NOSLEEP + no nonce rejection
	// make validation deterministic and fast for tests.
	pebble := startContainer(t, testcontainers.ContainerRequest{
		Image:        pebbleImage,
		ExposedPorts: []string{"14000/tcp", "15000/tcp"},
		Cmd:          []string{"-config", "/test/config/pebble-config.json", "-dnsserver", "challtestsrv:8053"},
		Env: map[string]string{
			"PEBBLE_VA_NOSLEEP":      "1",
			"PEBBLE_WFE_NONCEREJECT": "0",
		},
		Networks:       []string{nw.Name},
		NetworkAliases: map[string][]string{nw.Name: {"pebble"}},
		WaitingFor:     wait.ForListeningPort("14000/tcp"),
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
	}
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

func (p *PebbleEnv) chalPost(path string, body map[string]string) error {
	raw, _ := json.Marshal(body) // string-map marshal cannot fail
	hc := &http.Client{Timeout: chalMgmtTimeout}
	resp, err := hc.Post(p.ChallMgmtURL+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
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
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil || m.FQDN == "" {
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
	defer func() { _ = rc.Close() }()
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
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return data
}
