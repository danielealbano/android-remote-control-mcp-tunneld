//go:build e2e && soak

package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/support/soak-client/soak"
)

const (
	soakAppPkg        = "com.example.soakapp"
	soakAppDevicePort = 18444

	soakAppClientDevicePort = 18445
	soakFirstPhones         = 3
	soakPhones              = 4
)

func TestE2E_SoakApp(t *testing.T) {
	serial, ok := attestDeviceSerial(t)
	if !ok {
		t.Skip("no single adb device connected")
	}

	apkPath := filepath.Join("..", "fixtures", "soak-app", "soak-app.apk")
	shaPath := filepath.Join("..", "fixtures", "soak-app", "soak-app.apk.sha256")
	signersPath := filepath.Join("..", "fixtures", "soak-app", "signers.allow")
	wantSum, err := os.ReadFile(shaPath)
	if err != nil {
		t.Fatalf("read committed APK sha256: %v", err)
	}
	if got := apkSHA256(t, apkPath); got != strings.TrimSpace(string(wantSum)) {
		t.Fatalf("committed soak-app APK sha256 mismatch: got %s want %s (run 'make soak-app')",
			got, strings.TrimSpace(string(wantSum)))
	}

	inf := startE2EInfra(t)
	attested := replicaOpts{
		attestRootURL:    googleAttestRootURL,
		attestStatusURL:  googleAttestStatusURL,
		attestSignerFile: signersPath,
	}
	phoneOpts, clientOpts := attested, attested
	phoneOpts.dialBackAdvertise = "127.0.0.1:" + strconv.Itoa(soakAppDevicePort)
	clientOpts.dialBackAdvertise = "127.0.0.1:" + strconv.Itoa(soakAppClientDevicePort)
	phoneEdge := inf.startReplica(t, phoneOpts)
	clientEdge := inf.startReplica(t, clientOpts)
	_, edgePort, err := net.SplitHostPort(phoneEdge)
	if err != nil {
		t.Fatalf("split edge addr %q: %v", phoneEdge, err)
	}
	_, clientEdgePort, err := net.SplitHostPort(clientEdge)
	if err != nil {
		t.Fatalf("split edge addr %q: %v", clientEdge, err)
	}

	adb(t, serial, "reverse", "tcp:"+strconv.Itoa(soakAppDevicePort), "tcp:"+edgePort)
	t.Cleanup(func() { adbCleanup(t, serial, "reverse", "--remove", "tcp:"+strconv.Itoa(soakAppDevicePort)) })
	adb(t, serial, "reverse", "tcp:"+strconv.Itoa(soakAppClientDevicePort), "tcp:"+clientEdgePort)
	t.Cleanup(func() { adbCleanup(t, serial, "reverse", "--remove", "tcp:"+strconv.Itoa(soakAppClientDevicePort)) })
	adb(t, serial, "shell", "input", "keyevent", "KEYCODE_WAKEUP")
	adbCtx(t, serial, adbInstallTimeout, "install", "-r", apkPath)
	adbRunAs(t, serial, soakAppPkg, "rm -f files/ready files/error files/names.txt files/forgotten")

	caB64 := base64.StdEncoding.EncodeToString(inf.pebble.IssuingRootsPEM)
	adbRunAs(t, serial, soakAppPkg, "mkdir -p files && echo "+caB64+" | base64 -d > files/pebble-ca.pem")
	dataDir := strings.TrimSpace(string(adbRunAs(t, serial, soakAppPkg, "pwd")))

	amCommand(t, serial, soakAppPkg, "forget",
		"enrollHost", e2eEnrollHost,
		"controlHost", e2eControlHost,
		"tunnelDomain", e2eTunnelDomain,
	)
	pollAppFile(t, serial, soakAppPkg, "forgotten", 60*time.Second)

	start := func(count int) []string {
		t.Helper()
		adbRunAs(t, serial, soakAppPkg, "rm -f files/ready")
		amCommand(t, serial, soakAppPkg, "start",
			"count", strconv.Itoa(count),
			"spacingSeconds", "0",
			"parallel", "true",
			"edgePort", strconv.Itoa(soakAppDevicePort),
			"caPath", dataDir+"/files/pebble-ca.pem",
			"enrollHost", e2eEnrollHost,
			"controlHost", e2eControlHost,
			"tunnelDomain", e2eTunnelDomain,
		)
		if got := strings.TrimSpace(string(pollAppFile(t, serial, soakAppPkg, "ready", 300*time.Second))); got != strconv.Itoa(count) {
			failures := adbRunAs(t, serial, soakAppPkg, "cat files/failures.txt 2>/dev/null; true")
			t.Fatalf("ready marker = %q, want %d phones; failures: %s", got, count, failures)
		}
		names := strings.Fields(string(adbRunAs(t, serial, soakAppPkg, "cat files/names.txt")))
		if len(names) != count {
			t.Fatalf("names.txt lists %v, want %d names", names, count)
		}
		return names
	}
	t.Cleanup(func() {
		adbCleanup(t, serial, amCommandArgs(soakAppPkg, "stop")...)
	})

	first := start(soakFirstPhones)
	scaled := start(soakPhones)
	if strings.Join(scaled[:soakFirstPhones], ",") != strings.Join(first, ",") {
		t.Fatalf("scaling to %d phones changed the running ones: %v -> %v", soakPhones, first, scaled)
	}
	adbCtx(t, serial, adbInstallTimeout, "install", "-r", apkPath)
	names := start(soakPhones)
	if strings.Join(names, ",") != strings.Join(scaled, ",") {
		t.Fatalf("after a reinstall the phones were not resumed: %v -> %v", scaled, names)
	}
	t.Logf("soak phones bound to replica %s (scaled from %d, resumed after a reinstall): %v", phoneEdge, soakFirstPhones, names)

	dir := t.TempDir()
	namesFile := filepath.Join(dir, "names.txt")
	if err := os.WriteFile(namesFile, []byte(strings.Join(names, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "pebble-ca.pem")
	if err := os.WriteFile(caFile, inf.pebble.IssuingRootsPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "soak.csv")
	var summary, logs bytes.Buffer
	err = soak.Run(context.Background(), []string{
		"--names-file", namesFile, "--domain", e2eTunnelDomain, "--ca-file", caFile, "--connect", clientEdge,
		"--interval", "1s", "--req-bytes", "1024", "--resp-bytes", "5120", "--reconnect", "20s",
		"--duration", "60s", "--out", out,
	}, &summary, slog.New(slog.NewTextHandler(&logs, nil)))
	t.Logf("soak summary through replica %s:\n%s", clientEdge, summary.String())
	if err != nil {
		t.Fatalf("soak run: %v; logs: %s", err, logs.String())
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	type totals struct{ ok, errors, newConns, up, down int }
	per := map[string]*totals{}
	for _, r := range rows[1:] {
		tt := per[r[1]]
		if tt == nil {
			tt = &totals{}
			per[r[1]] = tt
		}
		for i, dst := range []*int{&tt.ok, &tt.errors, &tt.newConns, &tt.up, &tt.down} {
			col := []int{2, 3, 9, 10, 11}[i]
			v, err := strconv.Atoi(r[col])
			if err != nil {
				t.Fatalf("CSV row %v column %d: %v", r, col, err)
			}
			*dst += v
		}
	}
	for _, name := range names {
		tt := per[name]
		if tt == nil {
			t.Fatalf("no CSV rows for phone %s", name)
		}
		if tt.errors != 0 {
			t.Fatalf("phone %s: %d failed operations; logs: %s", name, tt.errors, logs.String())
		}
		if tt.ok < 40 {
			t.Fatalf("phone %s: %d successful operations in 60 s at 1/s, want at least 40", name, tt.ok)
		}
		if tt.newConns < 2 || tt.newConns >= tt.ok {
			t.Fatalf("phone %s: %d new connections for %d operations; want reuse plus reconnects", name, tt.newConns, tt.ok)
		}
		if tt.down < tt.ok*1024 || tt.up < tt.ok*204 {
			t.Fatalf("phone %s: bytes up=%d down=%d for %d operations", name, tt.up, tt.down, tt.ok)
		}
	}
}

func forgetSoakPhones(t *testing.T, serial string) {
	t.Helper()
	amCommand(t, serial, soakAppPkg, "forget",
		"enrollHost", e2eEnrollHost,
		"controlHost", e2eControlHost,
		"tunnelDomain", e2eTunnelDomain,
	)
	pollAppFile(t, serial, soakAppPkg, "forgotten", 60*time.Second)
}

func startSoakPhones(t *testing.T, serial, caPath string, count int) string {
	t.Helper()
	adbRunAs(t, serial, soakAppPkg, "rm -f files/ready files/failures.txt")
	amCommand(t, serial, soakAppPkg, "start",
		"count", strconv.Itoa(count),
		"spacingSeconds", "0",
		"parallel", "true",
		"edgePort", strconv.Itoa(appRulesDevicePort),
		"caPath", caPath,
		"enrollHost", e2eEnrollHost,
		"controlHost", e2eControlHost,
		"tunnelDomain", e2eTunnelDomain,
	)
	return strings.TrimSpace(string(pollAppFile(t, serial, soakAppPkg, "ready", 300*time.Second)))
}

func TestE2E_SoakAppReconnectsAfterSilence(t *testing.T) {
	serial, ok := attestDeviceSerial(t)
	if !ok {
		t.Skip("no single adb device connected")
	}
	inf := startE2EInfra(t)
	edge := inf.startReplica(t, attestedOpts("soak-app"))
	p := reverseVia(t, serial, edge)
	caPath := prepareApp(t, serial, inf, soakAppPkg, "soak-app")
	forgetSoakPhones(t, serial)
	if got := startSoakPhones(t, serial, caPath, 2); got != "2" {
		t.Fatalf("ready marker = %q, want 2 phones; failures: %s", got, adbRunAs(t, serial, soakAppPkg, "cat files/failures.txt 2>/dev/null; true"))
	}

	before := p.Accepted()
	p.Freeze()
	if !waitBool(150*time.Second, func() bool { return p.Accepted() >= before+2 }) {
		t.Fatalf("the phones never dialed new control connections after the old ones went silent (accepted %d -> %d)", before, p.Accepted())
	}

	names := strings.Fields(string(adbRunAs(t, serial, soakAppPkg, "cat files/names.txt")))
	if len(names) != 2 {
		t.Fatalf("names.txt lists %v, want 2 names", names)
	}
	dir := t.TempDir()
	namesFile := filepath.Join(dir, "names.txt")
	if err := os.WriteFile(namesFile, []byte(strings.Join(names, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "pebble-ca.pem")
	if err := os.WriteFile(caFile, inf.pebble.IssuingRootsPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "soak.csv")
	var summary, logs bytes.Buffer
	err := soak.Run(context.Background(), []string{
		"--names-file", namesFile, "--domain", e2eTunnelDomain, "--ca-file", caFile, "--connect", edge,
		"--interval", "1s", "--req-bytes", "1024", "--resp-bytes", "5120", "--reconnect", "20s",
		"--duration", "20s", "--out", out,
	}, &summary, slog.New(slog.NewTextHandler(&logs, nil)))
	t.Logf("soak summary:\n%s", summary.String())
	if err != nil {
		t.Fatalf("soak run: %v; logs: %s", err, logs.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	okOps, errOps := map[string]int{}, 0
	for _, r := range rows[1:] {
		okN, okErr := strconv.Atoi(r[2])
		errN, errErr := strconv.Atoi(r[3])
		if okErr != nil || errErr != nil {
			t.Fatalf("CSV row %v: ok %v, errors %v", r, okErr, errErr)
		}
		okOps[r[1]] += okN
		errOps += errN
	}
	if errOps != 0 {
		t.Fatalf("%d failed operations after the reconnect; logs: %s", errOps, logs.String())
	}
	for _, n := range names {
		if okOps[n] == 0 {
			t.Fatalf("phone %s served no operation after the reconnect", n)
		}
	}
}

func TestE2E_SoakAppIssueGivesUpWithoutReEnrolling(t *testing.T) {
	serial, ok := attestDeviceSerial(t)
	if !ok {
		t.Skip("no single adb device connected")
	}
	inf := startE2EInfra(t)
	edgeB := startFailingIssuer(t, inf, attestedOpts("soak-app"))
	reverseVia(t, serial, edgeB)
	caPath := prepareApp(t, serial, inf, soakAppPkg, "soak-app")
	forgetSoakPhones(t, serial)
	for round, wantFailed := range []float64{4, 8} {
		if got := startSoakPhones(t, serial, caPath, 1); got != "0" {
			t.Fatalf("start %d: ready marker = %q, want 0 phones", round+1, got)
		}
		if failures := string(adbRunAs(t, serial, soakAppPkg, "cat files/failures.txt")); !strings.Contains(failures, "phone 0:") {
			t.Fatalf("start %d: failures.txt = %q, want phone 0 listed", round+1, failures)
		}
		if v := metricSeriesValue(t, inf.internal[edgeB], acmeFailedSeries); v != wantFailed {
			t.Fatalf("start %d: %s = %v, want %v", round+1, acmeFailedSeries, v, wantFailed)
		}
		if v := metricSeriesValue(t, inf.internal[edgeB], enrolledSeries); v != 1 {
			t.Fatalf("start %d: %s = %v, want 1 (the saved phone resumes with issuance only)", round+1, enrolledSeries, v)
		}
	}
}

func TestE2E_SoakAppStopUnbindsAtOnce(t *testing.T) {
	serial, ok := attestDeviceSerial(t)
	if !ok {
		t.Skip("no single adb device connected")
	}
	inf := startE2EInfra(t)
	edge := inf.startReplica(t, attestedOpts("soak-app"))
	reverseVia(t, serial, edge)
	caPath := prepareApp(t, serial, inf, soakAppPkg, "soak-app")
	forgetSoakPhones(t, serial)
	if got := startSoakPhones(t, serial, caPath, 2); got != "2" {
		t.Fatalf("ready marker = %q, want 2 phones; failures: %s", got, adbRunAs(t, serial, soakAppPkg, "cat files/failures.txt 2>/dev/null; true"))
	}
	names := strings.Fields(string(adbRunAs(t, serial, soakAppPkg, "cat files/names.txt")))
	if len(names) != 2 {
		t.Fatalf("names.txt lists %v, want 2 names", names)
	}
	assertStopUnbinds(t, e2eRegistry(t, inf), names, func() { amCommand(t, serial, soakAppPkg, "stop") })
}
