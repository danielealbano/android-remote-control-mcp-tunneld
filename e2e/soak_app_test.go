//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"log/slog"
	"net"
	"os"
	"os/exec"
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
	soakFirstPhones   = 3
	soakPhones        = 4
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
	phoneEdge := inf.startReplica(t, attested)
	clientEdge := inf.startReplica(t, attested)
	_, edgePort, err := net.SplitHostPort(phoneEdge)
	if err != nil {
		t.Fatalf("split edge addr %q: %v", phoneEdge, err)
	}

	adb(t, serial, "reverse", "tcp:"+strconv.Itoa(soakAppDevicePort), "tcp:"+edgePort)
	t.Cleanup(func() { adbCleanup(t, serial, "reverse", "--remove", "tcp:"+strconv.Itoa(soakAppDevicePort)) })
	adb(t, serial, "shell", "input", "keyevent", "KEYCODE_WAKEUP")
	adbCtx(t, serial, adbInstallTimeout, "install", "-r", apkPath)
	t.Cleanup(func() { adbCleanup(t, serial, "uninstall", soakAppPkg) })
	adb(t, serial, "shell", "cmd", "deviceidle", "whitelist", "+"+soakAppPkg)
	t.Cleanup(func() { adbCleanup(t, serial, "shell", "cmd", "deviceidle", "whitelist", "-"+soakAppPkg) })
	adbRunAs(t, serial, soakAppPkg, "rm -f files/ready files/error files/names.txt")

	caB64 := base64.StdEncoding.EncodeToString(inf.pebble.IssuingRootsPEM)
	adbRunAs(t, serial, soakAppPkg, "mkdir -p files && echo "+caB64+" | base64 -d > files/pebble-ca.pem")
	dataDir := strings.TrimSpace(string(adbRunAs(t, serial, soakAppPkg, "pwd")))

	start := func(count int) []string {
		t.Helper()
		adbRunAs(t, serial, soakAppPkg, "rm -f files/ready")
		amBroadcast(t, serial, soakAppPkg, "start",
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
		adbCleanup(t, serial, "shell", "am", "broadcast", "-a", soakAppPkg+".stop", "-n", soakAppPkg+"/.CommandReceiver", "-f", "0x00000020")
	})

	first := start(soakFirstPhones)
	scaled := start(soakPhones)
	if strings.Join(scaled[:soakFirstPhones], ",") != strings.Join(first, ",") {
		t.Fatalf("scaling to %d phones changed the running ones: %v -> %v", soakPhones, first, scaled)
	}
	adbCtx(t, serial, adbInstallTimeout, "install", "-r", apkPath)
	adb(t, serial, "shell", "cmd", "deviceidle", "whitelist", "+"+soakAppPkg)
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

func adbCleanup(t *testing.T, serial string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "adb", append([]string{"-s", serial}, args...)...).CombinedOutput()
	if err != nil {
		t.Logf("adb cleanup failed: %v: %s", err, out)
	} else if msg := strings.TrimSpace(string(out)); msg != "" {
		t.Logf("adb cleanup: %s", msg)
	}
}
