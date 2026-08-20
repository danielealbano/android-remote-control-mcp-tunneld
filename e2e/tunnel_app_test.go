//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// tunnelAppPkg is the committed reference client (support/tunnel-app/, built via `make tunnel-app`).
const tunnelAppPkg = "com.example.tunnelapp"

// tunnelAppDevicePort is the device-side loopback port adb-reverse maps to the host replica's raw :443
// edge. The app dials 127.0.0.1:<this> and sets SNI to the reserved enroll/control host (or the assigned
// <name>.<tunnel-domain>), so the edge routes by SNI.
const tunnelAppDevicePort = 18443

// waitLoadStreams is the per-protocol concurrency of the /wait throughput check (h1 connections AND h2
// streams). Kept small: the ≤2*N ~1 MiB/s streams share the tunnel's per-direction bw bucket, sized above
// via replicaOpts.bandwidth so pacing does not engage.
const waitLoadStreams = 4

// TestE2E_ReferenceTunnelApp drives the committed reference client on a locally-connected Android device
// through the FULL flow with REAL Google-attested enrollment: it stands up a tunneld replica (attestation
// ON), adb-reverses the edge, pushes Pebble's issuing CA into the app, installs the committed APK
// (integrity-checked first), and drives enroll → serve → refresh over adb. A real public Go client dials
// the edge (SNI <name>.example.test, trusting Pebble) and asserts /info echoes the app nonce and reports a
// validating Pebble cert; after a refresh the cert changes but the nonce holds; and /wait delivers
// byte-exact, hash-matching streams concurrently over 4 HTTP/1.1 connections and 4 HTTP/2 streams. It
// SKIPS (never fails) without a single adb device and is NEVER run in CI with a device.
func TestE2E_ReferenceTunnelApp(t *testing.T) {
	serial, ok := attestDeviceSerial(t)
	if !ok {
		t.Skip("no single adb device connected")
	}

	apkPath := filepath.Join("..", "fixtures", "tunnel-app", "tunnel-app.apk")
	shaPath := filepath.Join("..", "fixtures", "tunnel-app", "tunnel-app.apk.sha256")
	signersPath := filepath.Join("..", "fixtures", "tunnel-app", "signers.allow")

	// Integrity-gate the committed APK against its committed digest before installing anything.
	wantSum, err := os.ReadFile(shaPath)
	if err != nil {
		t.Fatalf("read committed APK sha256: %v", err)
	}
	if got := apkSHA256(t, apkPath); got != strings.TrimSpace(string(wantSum)) {
		t.Fatalf("committed tunnel-app APK sha256 mismatch: got %s want %s (run 'make tunnel-app')",
			got, strings.TrimSpace(string(wantSum)))
	}

	inf := startE2EInfra(t)
	// Attestation ON (NOT optional): the seven-point gate runs against the live Google root/status sets and
	// the committed debug signer allowlist. Generous bandwidth/concurrency so the /wait pacing does not
	// throttle the concurrent ~1 MiB/s streams.
	edge := inf.startReplica(t, replicaOpts{
		attestRootURL:    googleAttestRootURL,
		attestStatusURL:  googleAttestStatusURL,
		attestSignerFile: signersPath,
		bandwidth:        "100mbit",
		concurrent:       32,
	})
	_, edgePort, err := net.SplitHostPort(edge)
	if err != nil {
		t.Fatalf("split edge addr %q: %v", edge, err)
	}

	// Bridge device→host: the app's 127.0.0.1:tunnelAppDevicePort reaches the host replica's edge.
	adb(t, serial, "reverse", "tcp:"+strconv.Itoa(tunnelAppDevicePort), "tcp:"+edgePort)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "adb", "-s", serial, "reverse", "--remove", "tcp:"+strconv.Itoa(tunnelAppDevicePort)).Run()
	})

	adb(t, serial, "shell", "input", "keyevent", "KEYCODE_WAKEUP")
	adbCtx(t, serial, adbInstallTimeout, "install", "-r", apkPath)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "adb", "-s", serial, "uninstall", tunnelAppPkg).Run()
	})
	// Android 12+ blocks a background broadcast receiver from calling startForegroundService(); put the app
	// on the power allowlist (as a real user-installed tunnel app would be exempted from battery
	// optimization) so its CommandReceiver may start the foreground TunnelService.
	adb(t, serial, "shell", "cmd", "deviceidle", "whitelist", "+"+tunnelAppPkg)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "adb", "-s", serial, "shell", "cmd", "deviceidle", "whitelist", "-"+tunnelAppPkg).Run()
	})
	// install -r keeps app data, so clear any stale status files from a prior interrupted run.
	adbRunAs(t, serial, tunnelAppPkg, "rm -f files/ready files/error files/info.json")

	// Deliver Pebble's issuing CA into the app's own storage (SELinux blocks an untrusted_app from reading
	// /data/local/tmp, so push via run-as instead). The app trusts it for tunneld's enroll/control certs.
	caB64 := base64.StdEncoding.EncodeToString(inf.pebble.IssuingRootsPEM)
	adbRunAs(t, serial, tunnelAppPkg, "mkdir -p files && echo "+caB64+" | base64 -d > files/pebble-ca.pem")
	dataDir := strings.TrimSpace(string(adbRunAs(t, serial, tunnelAppPkg, "pwd")))
	caPath := dataDir + "/files/pebble-ca.pem"

	// A fresh app-payload nonce (unrelated to the server attestation nonce), echoed by /info to prove the
	// tunnel reached THIS app instance.
	var appNonceBytes [16]byte
	if _, err := rand.Read(appNonceBytes[:]); err != nil {
		t.Fatal(err)
	}
	appNonce := hex.EncodeToString(appNonceBytes[:])

	// FLAG_INCLUDE_STOPPED_PACKAGES (0x20): the freshly-installed app is in the stopped state, so the
	// broadcast must be allowed to wake its manifest-declared receiver.
	amBroadcast(t, serial, "enroll",
		"edgePort", strconv.Itoa(tunnelAppDevicePort),
		"appNonce", appNonce,
		"pebbleCaPath", caPath,
		"enrollHost", e2eEnrollHost,
		"controlHost", e2eControlHost,
		"tunnelDomain", e2eTunnelDomain,
	)

	// The app enrolls → issues → starts its local server → opens the duplex /control (binding the route),
	// then writes info.json + the `ready` marker (the assigned name).
	name := strings.TrimSpace(string(pollAppFile(t, serial, tunnelAppPkg, "ready", 150*time.Second)))
	if name == "" {
		t.Fatal("app ready marker was empty")
	}
	fqdn := name + "." + e2eTunnelDomain
	t.Logf("app ready: name=%s fqdn=%s", name, fqdn)

	// Validate the phone's presented cert directly (the handshake already chained it to Pebble with
	// ServerName=fqdn; assert SAN + a sane validity window explicitly).
	assertPhoneCert(t, edge, fqdn, inf.pebble.IssuingRoots)

	// Public roundtrip #1: /info through the tunnel — echoes the app nonce and the current TLS cert digest.
	var info1 infoResp
	var infoErr error
	if !waitBool(90*time.Second, func() bool {
		r, gerr := fetchInfo(edge, fqdn, inf.pebble.IssuingRoots)
		if gerr != nil {
			infoErr = gerr
			return false
		}
		info1 = r
		return true
	}) {
		t.Fatalf("public /info never succeeded through the tunnel: %v", infoErr)
	}
	if info1.Nonce != appNonce {
		t.Fatalf("/info nonce = %q, want app nonce %q", info1.Nonce, appNonce)
	}
	if info1.Name != name {
		t.Fatalf("/info name = %q, want %q", info1.Name, name)
	}
	if info1.SAN != fqdn {
		t.Fatalf("/info san = %q, want %q", info1.SAN, fqdn)
	}
	if info1.TLSCertSHA256 == "" {
		t.Fatal("/info returned empty tls_cert_sha256")
	}
	f1 := info1.TLSCertSHA256

	// Refresh: force a fresh /issue (new TLS key + Pebble cert) and hot-swap the server cert. Clear the
	// completion markers first; the app rewrites them after the swap.
	adbRunAs(t, serial, tunnelAppPkg, "rm -f files/ready files/error")
	amBroadcast(t, serial, "refresh")
	if name2 := strings.TrimSpace(string(pollAppFile(t, serial, tunnelAppPkg, "ready", 150*time.Second))); name2 != name {
		t.Fatalf("after refresh the assigned name changed: %q -> %q", name, name2)
	}

	// Public roundtrip #2: the nonce is unchanged but the cert digest changed (renewal rotated it).
	var info2 infoResp
	if !waitBool(90*time.Second, func() bool {
		r, gerr := fetchInfo(edge, fqdn, inf.pebble.IssuingRoots)
		if gerr != nil || r.TLSCertSHA256 == f1 {
			return false
		}
		info2 = r
		return true
	}) {
		t.Fatalf("/info tls_cert_sha256 never changed after refresh (still %s)", f1)
	}
	if info2.Nonce != appNonce {
		t.Fatalf("after refresh /info nonce = %q, want %q", info2.Nonce, appNonce)
	}
	assertPhoneCert(t, edge, fqdn, inf.pebble.IssuingRoots) // still validating after the swap
	t.Logf("refresh rotated the cert: %s -> %s", f1, info2.TLSCertSHA256)

	// /wait throughput: byte-exact, hash-matching streams concurrently over N h1 connections and N h2
	// streams (the h2 streams multiplex over ONE tunnel connection).
	runWaitLoad(t, edge, fqdn, inf.pebble.IssuingRoots)

	amBroadcast(t, serial, "stop")
}

// amBroadcast sends `am broadcast -a com.example.tunnelapp.<cmd> -n <pkg>/.CommandReceiver` with
// FLAG_INCLUDE_STOPPED_PACKAGES and the given string extras (key, value pairs).
func amBroadcast(t *testing.T, serial, cmd string, kv ...string) {
	t.Helper()
	args := []string{"shell", "am", "broadcast",
		"-a", tunnelAppPkg + "." + cmd,
		"-n", tunnelAppPkg + "/.CommandReceiver",
		"-f", "0x00000020"}
	for i := 0; i+1 < len(kv); i += 2 {
		args = append(args, "-e", kv[i], kv[i+1])
	}
	adb(t, serial, args...)
}

// pollAppFile polls (via run-as) until files/<name> exists (→ returns its content) or files/error appears
// (→ fails), or the timeout elapses.
func pollAppFile(t *testing.T, serial, pkg, name string, timeout time.Duration) []byte {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		status := string(adbRunAs(t, serial, pkg,
			"if [ -f files/error ]; then echo ERR; cat files/error; "+
				"elif [ -f files/"+name+" ]; then echo OK; cat files/"+name+"; fi"))
		switch {
		case strings.HasPrefix(status, "ERR"):
			t.Fatalf("tunnel-app error before files/%s: %s", name, strings.TrimSpace(strings.TrimPrefix(status, "ERR")))
		case strings.HasPrefix(status, "OK"):
			return []byte(strings.TrimSpace(strings.TrimPrefix(status, "OK")))
		}
		if time.Now().After(deadline) {
			t.Fatalf("tunnel-app did not produce files/%s within %s", name, timeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

type infoResp struct {
	Nonce         string `json:"nonce"`
	TLSCertSHA256 string `json:"tls_cert_sha256"`
	NotBefore     int64  `json:"not_before"`
	NotAfter      int64  `json:"not_after"`
	Name          string `json:"name"`
	SAN           string `json:"san"`
	Issuer        string `json:"issuer"`
}

// fetchInfo GETs /info through the tunnel (HTTP/1.1) and decodes the JSON.
func fetchInfo(edge, fqdn string, roots *x509.CertPool) (infoResp, error) {
	var out infoResp
	status, body, err := h1Get(edge, fqdn, "/info", roots)
	if err != nil {
		return out, err
	}
	if status != http.StatusOK {
		return out, fmt.Errorf("/info status %d", status)
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("decode /info %q: %w", body, err)
	}
	return out, nil
}

// assertPhoneCert dials the edge as a public client, verifies the phone's leaf chains to Pebble for fqdn,
// and asserts the SAN and a sane validity window.
func assertPhoneCert(t *testing.T, edge, fqdn string, roots *x509.CertPool) {
	t.Helper()
	conn, err := dialTunnelTLS(edge, fqdn, roots)
	if err != nil {
		t.Fatalf("public TLS handshake to %s failed: %v", fqdn, err)
	}
	defer func() { _ = conn.Close() }()
	leaf := conn.ConnectionState().PeerCertificates[0]
	if err := leaf.VerifyHostname(fqdn); err != nil {
		t.Fatalf("phone cert SAN does not cover %s: %v (dns=%v)", fqdn, err, leaf.DNSNames)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		t.Fatalf("phone cert validity window unsane: not_before=%s not_after=%s now=%s",
			leaf.NotBefore, leaf.NotAfter, now)
	}
	if leaf.Issuer.String() == leaf.Subject.String() {
		t.Fatalf("phone cert is self-signed, expected a Pebble-issued cert: %s", leaf.Subject)
	}
}

// h1Client builds an HTTP/1.1 client over a single fresh tunnel connection (SNI fqdn, trusting roots,
// dialing the edge). It offers the "http/1.1" ALPN protocol (as a real client does): the phone's
// Ktor/Netty server negotiates ALPN and closes a connection that selects no protocol. TLSNextProto is
// emptied so the http.Transport itself performs no h2 upgrade.
func h1Client(edge, fqdn string, roots *x509.CertPool) *http.Client {
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := &tls.Dialer{Config: &tls.Config{
				ServerName: fqdn, RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
			}}
			return d.DialContext(ctx, "tcp", edge)
		},
		TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
		DisableKeepAlives: true,
	}
	return &http.Client{Transport: tr, Timeout: 90 * time.Second}
}

func h1Get(edge, fqdn, path string, roots *x509.CertPool) (int, []byte, error) {
	c := h1Client(edge, fqdn, roots)
	defer c.CloseIdleConnections()
	resp, err := c.Get("https://" + fqdn + path)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, body, err
}

// h2Client builds an HTTP/2 client over ONE tunnel connection (SNI fqdn + h2 ALPN); concurrent requests
// multiplex as streams.
func h2Client(edge, fqdn string, roots *x509.CertPool) *http.Client {
	tr := &http2.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			d := &tls.Dialer{Config: &tls.Config{
				ServerName: fqdn, RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"},
			}}
			return d.DialContext(ctx, "tcp", edge)
		},
	}
	return &http.Client{Transport: tr, Timeout: 90 * time.Second}
}

// runWaitLoad drives waitLoadStreams HTTP/1.1 connections and waitLoadStreams HTTP/2 streams concurrently
// against /wait, verifying each stream's payload hash matches its trailer (byte-exact delivery).
func runWaitLoad(t *testing.T, edge, fqdn string, roots *x509.CertPool) {
	t.Helper()
	const seconds = 2 // modest so total volume stays small
	h2c := h2Client(edge, fqdn, roots)
	defer h2c.CloseIdleConnections()

	var wg sync.WaitGroup
	errs := make(chan error, 2*waitLoadStreams)
	for i := 0; i < waitLoadStreams; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := waitOnce(h1Client(edge, fqdn, roots), fqdn, seconds); err != nil {
				errs <- fmt.Errorf("h1: %w", err)
			}
		}()
		go func() {
			defer wg.Done()
			if err := waitOnce(h2c, fqdn, seconds); err != nil {
				errs <- fmt.Errorf("h2: %w", err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("/wait stream failed: %v", err)
	}
}

// waitOnce GETs /wait?seconds=N with client c and verifies the streamed payload hashes to the trailer.
func waitOnce(c *http.Client, fqdn string, seconds int) error {
	resp, err := c.Get("https://" + fqdn + "/wait?seconds=" + strconv.Itoa(seconds))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return verifyWait(resp.Body)
}

// verifyWait parses the /wait body (`<total>\n` + <total> payload bytes + `\n<sha256-hex>\n`), hashes the
// payload as it reads, and asserts the computed hash equals the trailer.
func verifyWait(r io.Reader) error {
	br := bufio.NewReader(r)
	totalLine, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read total line: %w", err)
	}
	total, err := strconv.ParseInt(strings.TrimSpace(totalLine), 10, 64)
	if err != nil {
		return fmt.Errorf("parse total %q: %w", totalLine, err)
	}
	h := sha256.New()
	if _, err := io.CopyN(h, br, total); err != nil {
		return fmt.Errorf("read %d payload bytes: %w", total, err)
	}
	trailer, err := io.ReadAll(br)
	if err != nil {
		return fmt.Errorf("read trailer: %w", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	want := strings.TrimSpace(string(trailer))
	if got != want {
		return fmt.Errorf("payload hash mismatch: got %s want %s", got, want)
	}
	return nil
}
