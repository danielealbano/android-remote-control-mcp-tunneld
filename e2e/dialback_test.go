//go:build e2e

package e2e

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

const (
	dialBackRequests    = 6
	dialBackTimeout     = 3 * time.Second
	dialBackDevicePortA = 18451
	dialBackDevicePortB = 18452
)

func TestE2E_DialBackAcrossReplicas(t *testing.T) {
	serial, ok := attestDeviceSerial(t)
	if !ok {
		t.Skip("no single adb device connected")
	}

	apkPath := filepath.Join("..", "fixtures", "tunnel-app", "tunnel-app.apk")
	shaPath := filepath.Join("..", "fixtures", "tunnel-app", "tunnel-app.apk.sha256")
	signersPath := filepath.Join("..", "fixtures", "tunnel-app", "signers.allow")
	wantSum, err := os.ReadFile(shaPath)
	if err != nil {
		t.Fatalf("read committed APK sha256: %v", err)
	}
	if got := apkSHA256(t, apkPath); got != strings.TrimSpace(string(wantSum)) {
		t.Fatalf("committed tunnel-app APK sha256 mismatch: got %s want %s (run 'make tunnel-app')",
			got, strings.TrimSpace(string(wantSum)))
	}

	inf := startE2EInfra(t)
	opts := replicaOpts{
		attestRootURL:    googleAttestRootURL,
		attestStatusURL:  googleAttestStatusURL,
		attestSignerFile: signersPath,
		dialBack:         dialBackTimeout,
	}
	optsA, optsB := opts, opts
	optsA.dialBackAdvertise = "127.0.0.1:" + strconv.Itoa(dialBackDevicePortA)
	optsB.dialBackAdvertise = "127.0.0.1:" + strconv.Itoa(dialBackDevicePortB)
	owner := inf.startReplica(t, optsA)
	other := inf.startReplica(t, optsB)
	for _, r := range []struct {
		devicePort int
		edge       string
	}{{dialBackDevicePortA, owner}, {dialBackDevicePortB, other}} {
		_, port, err := net.SplitHostPort(r.edge)
		if err != nil {
			t.Fatalf("split edge addr %q: %v", r.edge, err)
		}
		adb(t, serial, "reverse", "tcp:"+strconv.Itoa(r.devicePort), "tcp:"+port)
		t.Cleanup(func() { adbCleanup(t, serial, "reverse", "--remove", "tcp:"+strconv.Itoa(r.devicePort)) })
	}
	fwd := startRoundRobinForwarder(t, owner, other)
	t.Logf("replica A %s (phone control), replica B %s, phone forwarder %s", owner, other, fwd.addr())
	_, fwdPort, err := net.SplitHostPort(fwd.addr())
	if err != nil {
		t.Fatalf("split forwarder addr %q: %v", fwd.addr(), err)
	}

	adb(t, serial, "reverse", "tcp:"+strconv.Itoa(tunnelAppDevicePort), "tcp:"+fwdPort)
	t.Cleanup(func() { adbCleanup(t, serial, "reverse", "--remove", "tcp:"+strconv.Itoa(tunnelAppDevicePort)) })
	adb(t, serial, "shell", "input", "keyevent", "KEYCODE_WAKEUP")
	adbCtx(t, serial, adbInstallTimeout, "install", "-r", apkPath)
	adbRunAs(t, serial, tunnelAppPkg, "rm -f files/ready files/error files/info.json")

	caB64 := base64.StdEncoding.EncodeToString(inf.pebble.IssuingRootsPEM)
	adbRunAs(t, serial, tunnelAppPkg, "mkdir -p files && echo "+caB64+" | base64 -d > files/pebble-ca.pem")
	dataDir := strings.TrimSpace(string(adbRunAs(t, serial, tunnelAppPkg, "pwd")))

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		adbCleanup(t, serial, amCommandArgs(tunnelAppPkg, "stop")...)
	})
	forgetTunnelApp(t, serial)
	amCommand(t, serial, tunnelAppPkg, "enroll",
		"edgePort", strconv.Itoa(tunnelAppDevicePort),
		"appNonce", hex.EncodeToString(nonce[:]),
		"caPath", dataDir+"/files/pebble-ca.pem",
		"enrollHost", e2eEnrollHost,
		"controlHost", e2eControlHost,
		"tunnelDomain", e2eTunnelDomain,
	)
	name := strings.TrimSpace(string(pollAppFile(t, serial, tunnelAppPkg, "ready", 150*time.Second)))
	if name == "" {
		t.Fatal("app ready marker was empty")
	}
	fqdn := name + "." + e2eTunnelDomain

	var infoErr error
	if !waitBool(90*time.Second, func() bool {
		_, infoErr = fetchInfo(owner, fqdn, inf.pebble.IssuingRoots)
		return infoErr == nil
	}) {
		t.Fatalf("public /info never succeeded with every phone connection on replica A: %v", infoErr)
	}
	pid := strings.TrimSpace(string(adb(t, serial, "shell", "pidof", tunnelAppPkg)))
	t.Logf("tunnel %s bound on replica A and reachable; phone connections now alternate B, A, B, ...", fqdn)
	fwd.startRoundRobin()

	var failures []string
	for i := 1; i <= dialBackRequests; i++ {
		entry, label := owner, "A"
		if i%2 == 0 {
			entry, label = other, "B"
		}
		start := time.Now()
		info, err := fetchInfo(entry, fqdn, inf.pebble.IssuingRoots)
		switch {
		case err != nil:
			failures = append(failures, fmt.Sprintf("request %d via %s failed after %s: %v", i, label, time.Since(start).Round(time.Millisecond), err))
		case info.Name != name:
			failures = append(failures, fmt.Sprintf("request %d via %s reached %q, want %q", i, label, info.Name, name))
		default:
			t.Logf("request %d via %s ok in %s", i, label, time.Since(start).Round(time.Millisecond))
		}
		time.Sleep(time.Second)
	}
	t.Logf("phone connections per replica: A=%d B=%d", fwd.accepted(0), fwd.accepted(1))
	if len(failures) > 0 {
		t.Logf("tunnel app log (pid %s):\n%s", pid, adb(t, serial, "logcat", "-d", "--pid="+pid))
		t.Fatalf("%d/%d public requests failed:\n%s", len(failures), dialBackRequests, strings.Join(failures, "\n"))
	}
}

func TestE2E_DialBackModes(t *testing.T) {
	inf := startE2EInfra(t)
	for _, mode := range []struct {
		name string
		opts replicaOpts
	}{
		{name: "https-no-mtls", opts: replicaOpts{dialBackNoMTLS: true}},
		{name: "plain", opts: replicaOpts{dialBackPlain: true}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			edgeA := inf.startReplica(t, mode.opts)
			edgeB := inf.startReplica(t, mode.opts)
			_, ident := echoPhone(t, inf, edgeA, edgeA)
			fqdn := ident.Name + "." + e2eTunnelDomain
			for _, entry := range []struct{ label, edge string }{{"owner A", edgeA}, {"non-owner B", edgeB}} {
				var lastErr error
				if !waitBool(30*time.Second, func() bool {
					lastErr = frontendRoundtrip(entry.edge, fqdn, inf.pebble.IssuingRoots)
					return lastErr == nil
				}) {
					t.Fatalf("%s roundtrip entering %s never succeeded: %v", mode.name, entry.label, lastErr)
				}
			}
		})
	}
}

func TestE2E_SplicesEndWhenPhoneDisconnects(t *testing.T) {
	inf := startE2EInfra(t)
	edgeA := inf.startReplica(t, replicaOpts{})
	edgeB := inf.startReplica(t, replicaOpts{})
	fwd := startRoundRobinForwarder(t, edgeA)
	_, ident := echoPhone(t, inf, edgeA, fwd.addr())
	fqdn := ident.Name + "." + e2eTunnelDomain

	var lastErr error
	if !waitBool(30*time.Second, func() bool {
		lastErr = frontendRoundtrip(edgeB, fqdn, inf.pebble.IssuingRoots)
		return lastErr == nil
	}) {
		t.Fatalf("roundtrip entering B never succeeded: %v", lastErr)
	}
	live, err := dialTunnelTLS(edgeB, fqdn, inf.pebble.IssuingRoots)
	if err != nil {
		t.Fatalf("open a live splice through B: %v", err)
	}
	defer tunneltest.CloseLogged(live)
	if err := echoOn(live); err != nil {
		t.Fatalf("the live splice through B does not echo: %v", err)
	}

	fwd.cut()
	start := time.Now()
	if err := live.SetReadDeadline(start.Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = live.Read(make([]byte, 1))
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the splice entered through B must end once the phone's control connection to A closes, read = %v", err)
	}
	t.Logf("splice through B ended %s after the control connection was cut: %v", time.Since(start).Round(time.Millisecond), err)
}

type roundRobinForwarder struct {
	t        *testing.T
	ln       net.Listener
	backends []string
	counts   []atomic.Int64
	rr       atomic.Bool
	next     atomic.Uint64
	wg       sync.WaitGroup

	mu      sync.Mutex
	closing bool
	conns   map[net.Conn]struct{}
}

func startRoundRobinForwarder(t *testing.T, backends ...string) *roundRobinForwarder {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("forwarder listen: %v", err)
	}
	f := &roundRobinForwarder{t: t, ln: ln, backends: backends, counts: make([]atomic.Int64, len(backends)), conns: map[net.Conn]struct{}{}}
	f.wg.Add(1)
	go f.serve()
	t.Cleanup(f.close)
	return f
}

func (f *roundRobinForwarder) addr() string { return f.ln.Addr().String() }

func (f *roundRobinForwarder) startRoundRobin() { f.rr.Store(true) }

func (f *roundRobinForwarder) accepted(i int) int64 { return f.counts[i].Load() }

func (f *roundRobinForwarder) pick() int {
	if !f.rr.Load() {
		return 0
	}
	return int(f.next.Add(1) % uint64(len(f.backends)))
}

func (f *roundRobinForwarder) serve() {
	defer f.wg.Done()
	for {
		c, err := f.ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				f.t.Logf("forwarder accept: %v", err)
			}
			return
		}
		i := f.pick()
		f.counts[i].Add(1)
		f.t.Logf("forwarder: phone connection %s -> replica %c (%s)", c.RemoteAddr(), 'A'+i, f.backends[i])
		f.wg.Add(1)
		go f.pipe(c, f.backends[i])
	}
}

func (f *roundRobinForwarder) pipe(c net.Conn, backend string) {
	defer f.wg.Done()
	b, err := net.DialTimeout("tcp", backend, 5*time.Second)
	if err != nil {
		f.t.Logf("forwarder dial %s: %v", backend, err)
		tunneltest.CloseOrLog(f.t, c)
		return
	}
	if !f.track(c, b) {
		tunneltest.CloseOrLog(f.t, c)
		tunneltest.CloseOrLog(f.t, b)
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); f.copy(b, c) }()
	go func() { defer wg.Done(); f.copy(c, b) }()
	wg.Wait()
	f.untrack(c, b)
	tunneltest.CloseOrLog(f.t, c)
	tunneltest.CloseOrLog(f.t, b)
}

func (f *roundRobinForwarder) copy(dst, src net.Conn) {
	if _, err := io.Copy(dst, src); err != nil && !errors.Is(err, net.ErrClosed) {
		f.t.Logf("forwarder copy %s -> %s: %v", src.RemoteAddr(), dst.RemoteAddr(), err)
	}
	if tc, ok := dst.(*net.TCPConn); ok {
		if err := tc.CloseWrite(); err != nil && !errors.Is(err, net.ErrClosed) {
			f.t.Logf("forwarder half-close %s: %v", dst.RemoteAddr(), err)
		}
	}
}

func (f *roundRobinForwarder) track(conns ...net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closing {
		return false
	}
	for _, c := range conns {
		f.conns[c] = struct{}{}
	}
	return true
}

func (f *roundRobinForwarder) untrack(conns ...net.Conn) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range conns {
		delete(f.conns, c)
	}
}

func (f *roundRobinForwarder) cut() {
	f.mu.Lock()
	open := make([]net.Conn, 0, len(f.conns))
	for c := range f.conns {
		open = append(open, c)
	}
	f.mu.Unlock()
	for _, c := range open {
		tunneltest.CloseOrLog(f.t, c)
	}
}

func (f *roundRobinForwarder) close() {
	tunneltest.CloseOrLog(f.t, f.ln)
	f.mu.Lock()
	f.closing = true
	open := make([]net.Conn, 0, len(f.conns))
	for c := range f.conns {
		open = append(open, c)
	}
	f.mu.Unlock()
	for _, c := range open {
		tunneltest.CloseOrLog(f.t, c)
	}
	f.wg.Wait()
}
