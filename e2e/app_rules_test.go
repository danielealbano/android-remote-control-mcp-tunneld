//go:build e2e

package e2e

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

const (
	appRulesDevicePort = 18446
	unreachableACMEDir = "https://127.0.0.1:1/dir"
)

func attestedOpts(fixture string) replicaOpts {
	return replicaOpts{
		attestRootURL:     googleAttestRootURL,
		attestStatusURL:   googleAttestStatusURL,
		attestSignerFile:  filepath.Join("..", "fixtures", fixture, "signers.allow"),
		dialBackAdvertise: "127.0.0.1:" + strconv.Itoa(appRulesDevicePort),
	}
}

func startFailingIssuer(t *testing.T, inf *e2eInfra, opts replicaOpts) string {
	t.Helper()
	inf.startReplica(t, opts)
	broken := opts
	broken.acmeDirLE, broken.acmeDirGTS = unreachableACMEDir, unreachableACMEDir
	return inf.startReplica(t, broken)
}

func reverseVia(t *testing.T, serial, edge string) *tunneltest.BlackholeProxy {
	t.Helper()
	p := tunneltest.StartBlackholeProxy(t, edge)
	_, port, err := net.SplitHostPort(p.Addr())
	if err != nil {
		t.Fatalf("split proxy addr %q: %v", p.Addr(), err)
	}
	adb(t, serial, "reverse", "tcp:"+strconv.Itoa(appRulesDevicePort), "tcp:"+port)
	t.Cleanup(func() { adbCleanup(t, serial, "reverse", "--remove", "tcp:"+strconv.Itoa(appRulesDevicePort)) })
	return p
}

func prepareApp(t *testing.T, serial string, inf *e2eInfra, pkg, fixture string) string {
	t.Helper()
	apkPath := filepath.Join("..", "fixtures", fixture, fixture+".apk")
	wantSum, err := os.ReadFile(apkPath + ".sha256")
	if err != nil {
		t.Fatalf("read committed APK sha256: %v", err)
	}
	if got := apkSHA256(t, apkPath); got != strings.TrimSpace(string(wantSum)) {
		t.Fatalf("committed %s APK sha256 mismatch: got %s want %s (run 'make %s')", fixture, got, strings.TrimSpace(string(wantSum)), fixture)
	}
	adb(t, serial, "shell", "input", "keyevent", "KEYCODE_WAKEUP")
	adbCtx(t, serial, adbInstallTimeout, "install", "-r", apkPath)
	t.Cleanup(func() {
		adbCleanup(t, serial, amCommandArgs(pkg, "stop")...)
	})
	adbRunAs(t, serial, pkg, "rm -f files/ready files/error files/info.json files/names.txt files/failures.txt files/forgotten")
	caB64 := base64.StdEncoding.EncodeToString(inf.pebble.IssuingRootsPEM)
	adbRunAs(t, serial, pkg, "mkdir -p files && echo "+caB64+" | base64 -d > files/pebble-ca.pem")
	return strings.TrimSpace(string(adbRunAs(t, serial, pkg, "pwd"))) + "/files/pebble-ca.pem"
}

func enrollTunnelApp(t *testing.T, serial, caPath string) string {
	t.Helper()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	appNonce := hex.EncodeToString(nonce[:])
	amCommand(t, serial, tunnelAppPkg, "enroll",
		"edgePort", strconv.Itoa(appRulesDevicePort),
		"appNonce", appNonce,
		"caPath", caPath,
		"enrollHost", e2eEnrollHost,
		"controlHost", e2eControlHost,
		"tunnelDomain", e2eTunnelDomain,
	)
	return appNonce
}

func forgetTunnelApp(t *testing.T, serial string) {
	t.Helper()
	adbRunAs(t, serial, tunnelAppPkg, "rm -f files/forgotten")
	amCommand(t, serial, tunnelAppPkg, "forget",
		"enrollHost", e2eEnrollHost,
		"controlHost", e2eControlHost,
		"tunnelDomain", e2eTunnelDomain,
	)
	pollAppFile(t, serial, tunnelAppPkg, "forgotten", 60*time.Second)
}

func pollAppError(t *testing.T, serial, pkg string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		status := string(adbRunAs(t, serial, pkg, "if [ -f files/error ]; then echo ERR; cat files/error; fi"))
		if rest, ok := strings.CutPrefix(status, "ERR"); ok {
			return strings.TrimSpace(rest)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not produce files/error within %s", pkg, timeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func metricSeriesValue(t *testing.T, internalAddr, series string) float64 {
	t.Helper()
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get("http://" + internalAddr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer tunneltest.CloseOrLog(t, resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics: %v", err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if v, ok := strings.CutPrefix(line, series+" "); ok {
			f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err != nil {
				t.Fatalf("parse %q: %v", line, err)
			}
			return f
		}
	}
	return 0
}

const (
	acmeFailedSeries = `tunneld_rejections_total{reason="acme-failed"}`
	enrolledSeries   = `tunneld_enrollments_total{result="ok"}`
)

func readyName(t *testing.T, serial, pkg string) string {
	t.Helper()
	name := strings.TrimSpace(string(pollAppFile(t, serial, pkg, "ready", 150*time.Second)))
	if name == "" {
		t.Fatal("app ready marker was empty")
	}
	return name
}

func readAppInfo(t *testing.T, serial string) infoResp {
	t.Helper()
	var info infoResp
	raw := adbRunAs(t, serial, tunnelAppPkg, "cat files/info.json")
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatalf("decode files/info.json %q: %v", raw, err)
	}
	return info
}

func TestE2E_ReferenceTunnelAppReconnectsAfterSilence(t *testing.T) {
	serial, ok := attestDeviceSerial(t)
	if !ok {
		t.Skip("no single adb device connected")
	}
	inf := startE2EInfra(t)
	edge := inf.startReplica(t, attestedOpts("tunnel-app"))
	p := reverseVia(t, serial, edge)
	caPath := prepareApp(t, serial, inf, tunnelAppPkg, "tunnel-app")
	forgetTunnelApp(t, serial)
	appNonce := enrollTunnelApp(t, serial, caPath)
	fqdn := readyName(t, serial, tunnelAppPkg) + "." + e2eTunnelDomain

	before := p.Accepted()
	p.Freeze()
	if !waitBool(150*time.Second, func() bool { return p.Accepted() > before }) {
		t.Fatalf("the app never dialed a new control connection after the old one went silent (accepted %d)", p.Accepted())
	}
	var lastErr error
	if !waitBool(90*time.Second, func() bool {
		info, err := fetchInfo(edge, fqdn, inf.pebble.IssuingRoots)
		switch {
		case err != nil:
			lastErr = err
		case info.Nonce != appNonce:
			lastErr = fmt.Errorf("/info nonce %q, want %q", info.Nonce, appNonce)
		default:
			return true
		}
		return false
	}) {
		t.Fatalf("/info never succeeded over the new control connection: %v", lastErr)
	}
}

func TestE2E_ReferenceTunnelAppRenewRetrySucceeds(t *testing.T) {
	serial, ok := attestDeviceSerial(t)
	if !ok {
		t.Skip("no single adb device connected")
	}
	prevLevel := strings.TrimSpace(string(adb(t, serial, "shell", "getprop", "log.tag.TunnelApp")))
	adb(t, serial, "shell", "setprop", "log.tag.TunnelApp", "W")
	t.Cleanup(func() { adbCleanup(t, serial, "shell", "setprop", "log.tag.TunnelApp", "'"+prevLevel+"'") })
	inf := startE2EInfra(t)
	opts := attestedOpts("tunnel-app")
	opts.leNameBudget = "1/60s"
	opts.acmeDirGTS = unreachableACMEDir
	opts.backoffInitial, opts.backoffMax = 2*time.Minute, 2*time.Minute
	edge := inf.startReplica(t, opts)
	reverseVia(t, serial, edge)
	caPath := prepareApp(t, serial, inf, tunnelAppPkg, "tunnel-app")
	forgetTunnelApp(t, serial)
	enrollTunnelApp(t, serial, caPath)
	name := readyName(t, serial, tunnelAppPkg)
	before := readAppInfo(t, serial)

	ropts, err := redis.ParseURL(inf.redisURL)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(ropts)
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	nameBudget := "acme-budget:letsencrypt:name:" + name + "." + e2eTunnelDomain
	pipe := rdb.Pipeline()
	pipe.HSet(context.Background(), nameBudget, "t", "0", "at", strconv.FormatInt(time.Now().UnixMilli(), 10))
	pipe.PExpire(context.Background(), nameBudget, time.Hour)
	if _, err := pipe.Exec(context.Background()); err != nil {
		t.Fatalf("empty the name budget: %v", err)
	}
	adb(t, serial, "logcat", "-c")
	adbRunAs(t, serial, tunnelAppPkg, "rm -f files/ready files/info.json")
	amCommand(t, serial, tunnelAppPkg, "refresh")
	if got := readyName(t, serial, tunnelAppPkg); got != name {
		t.Fatalf("after the refresh the assigned name changed: %q -> %q", name, got)
	}

	logs := string(adb(t, serial, "logcat", "-d", "-v", "raw", "-s", "TunnelApp:W"))
	retries := regexp.MustCompile(`issuance failed; retry (\d+) in (\d+)ms`).FindAllStringSubmatch(logs, -1)
	if len(retries) != 1 || retries[0][1] != "1" {
		t.Fatalf("want exactly one server-paced retry, got %v; log:\n%s", retries, logs)
	}
	ms, err := strconv.Atoi(retries[0][2])
	if err != nil {
		t.Fatal(err)
	}
	if ms <= 5000 || ms > 70000 {
		t.Fatalf("retry wait %d ms, want the LE name wait plus 1-10 s (5000, 70000]", ms)
	}
	after := readAppInfo(t, serial)
	if after.Name != name || after.TLSCertSHA256 == before.TLSCertSHA256 {
		t.Fatalf("after the renewal info.json = %+v, want name %s and a cert other than %s", after, name, before.TLSCertSHA256)
	}
	if v := metricSeriesValue(t, inf.internal[edge], acmeFailedSeries); v != 1 {
		t.Fatalf("%s = %v, want 1 (only the first attempt failed)", acmeFailedSeries, v)
	}
}

func TestE2E_ReferenceTunnelAppIssueGivesUp(t *testing.T) {
	serial, ok := attestDeviceSerial(t)
	if !ok {
		t.Skip("no single adb device connected")
	}
	inf := startE2EInfra(t)
	edgeB := startFailingIssuer(t, inf, attestedOpts("tunnel-app"))
	reverseVia(t, serial, edgeB)
	caPath := prepareApp(t, serial, inf, tunnelAppPkg, "tunnel-app")
	forgetTunnelApp(t, serial)
	enrollTunnelApp(t, serial, caPath)
	t.Logf("the app gave up: %s", pollAppError(t, serial, tunnelAppPkg, 150*time.Second))
	if v := metricSeriesValue(t, inf.internal[edgeB], acmeFailedSeries); v != 4 {
		t.Fatalf("%s = %v, want 4 (the first attempt and 3 retries)", acmeFailedSeries, v)
	}
	if v := metricSeriesValue(t, inf.internal[edgeB], enrolledSeries); v != 1 {
		t.Fatalf("%s = %v, want 1", enrolledSeries, v)
	}
}

func TestE2E_ReferenceTunnelAppResumesAfterRestart(t *testing.T) {
	serial, ok := attestDeviceSerial(t)
	if !ok {
		t.Skip("no single adb device connected")
	}
	inf := startE2EInfra(t)
	edge := inf.startReplica(t, attestedOpts("tunnel-app"))
	reverseVia(t, serial, edge)
	caPath := prepareApp(t, serial, inf, tunnelAppPkg, "tunnel-app")
	forgetTunnelApp(t, serial)
	enrollTunnelApp(t, serial, caPath)
	name := readyName(t, serial, tunnelAppPkg)
	enrolled := metricSeriesValue(t, inf.internal[edge], enrolledSeries)

	amCommand(t, serial, tunnelAppPkg, "stop")
	adb(t, serial, "shell", "am", "force-stop", tunnelAppPkg)
	adbRunAs(t, serial, tunnelAppPkg, "rm -f files/ready files/error files/info.json")
	appNonce := enrollTunnelApp(t, serial, caPath)
	if got := readyName(t, serial, tunnelAppPkg); got != name {
		t.Fatalf("after a restart the app came back as %q, want its saved identity %q", got, name)
	}
	if v := metricSeriesValue(t, inf.internal[edge], enrolledSeries); v != enrolled {
		t.Fatalf("%s = %v after the restart, want %v (the app must resume, not enroll again)", enrolledSeries, v, enrolled)
	}
	fqdn := name + "." + e2eTunnelDomain
	var lastErr error
	if !waitBool(90*time.Second, func() bool {
		info, err := fetchInfo(edge, fqdn, inf.pebble.IssuingRoots)
		switch {
		case err != nil:
			lastErr = err
		case info.Nonce != appNonce:
			lastErr = fmt.Errorf("/info nonce %q, want %q", info.Nonce, appNonce)
		default:
			return true
		}
		return false
	}) {
		t.Fatalf("/info never reached the resumed app: %v", lastErr)
	}

	amCommand(t, serial, tunnelAppPkg, "stop")
	forgetTunnelApp(t, serial)
	adbRunAs(t, serial, tunnelAppPkg, "rm -f files/ready files/error files/info.json")
	enrollTunnelApp(t, serial, caPath)
	if got := readyName(t, serial, tunnelAppPkg); got == name {
		t.Fatalf("after forget the app kept the name %q, want a new enrollment", got)
	}
	if v := metricSeriesValue(t, inf.internal[edge], enrolledSeries); v != enrolled+1 {
		t.Fatalf("%s = %v after forget, want %v", enrolledSeries, v, enrolled+1)
	}
}

func e2eRegistry(t *testing.T, inf *e2eInfra) *router.Registry {
	t.Helper()
	opt, err := redis.ParseURL(inf.redisURL)
	if err != nil {
		t.Fatalf("parse redis url: %v", err)
	}
	rdb := redis.NewClient(opt)
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	reg, err := router.NewRegistry(rdb, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func assertStopUnbinds(t *testing.T, reg *router.Registry, names []string, stop func()) {
	t.Helper()
	ctx := context.Background()
	for _, name := range names {
		if _, _, ok, err := reg.LookupRoute(ctx, name); err != nil || !ok {
			t.Fatalf("route of %s must be bound before stop: ok=%v err=%v", name, ok, err)
		}
	}
	stop()
	var lastErr error
	if !waitBool(5*time.Second, func() bool {
		for _, name := range names {
			_, _, ok, err := reg.LookupRoute(ctx, name)
			if err != nil || ok {
				lastErr = err
				return false
			}
		}
		return true
	}) {
		t.Fatalf("stop must unbind every route within 5 s (last lookup error: %v)", lastErr)
	}
}

func TestE2E_ReferenceTunnelAppStopUnbindsAtOnce(t *testing.T) {
	serial, ok := attestDeviceSerial(t)
	if !ok {
		t.Skip("no single adb device connected")
	}
	inf := startE2EInfra(t)
	edge := inf.startReplica(t, attestedOpts("tunnel-app"))
	reverseVia(t, serial, edge)
	caPath := prepareApp(t, serial, inf, tunnelAppPkg, "tunnel-app")
	forgetTunnelApp(t, serial)
	enrollTunnelApp(t, serial, caPath)
	name := readyName(t, serial, tunnelAppPkg)
	assertStopUnbinds(t, e2eRegistry(t, inf), []string{name}, func() { amCommand(t, serial, tunnelAppPkg, "stop") })
}
