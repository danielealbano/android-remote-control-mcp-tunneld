package ban

import (
	"bytes"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// captureLog returns a logger writing Warn+Error records into the returned buffer (for warn/error
// assertions).
func captureLog() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})), &buf
}

func writeBan(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestFreshEnginePanicSafe(t *testing.T) {
	e := NewEngine()
	if _, ok := e.Match(mustAddr("1.2.3.4")); ok {
		t.Error("fresh engine must not match any IP")
	}
	if _, ok := e.MatchTunnel("x", "y"); ok {
		t.Error("fresh engine must not match any tunnel")
	}
}

func TestMatchSingleIPVia32(t *testing.T) {
	dir := t.TempDir()
	f := writeBan(t, dir, "bans.txt", "ip 9.9.9.9\n")
	e := NewEngine()
	if err := e.Load([]string{f}, "", nil, discardLog()); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Match(mustAddr("9.9.9.9")); !ok {
		t.Error("9.9.9.9 must match")
	}
	if _, ok := e.Match(mustAddr("9.9.9.8")); ok {
		t.Error("9.9.9.8 must NOT match (single ip is /32)")
	}
}

func TestMatchCIDRCoversRange(t *testing.T) {
	dir := t.TempDir()
	f := writeBan(t, dir, "bans.txt", "cidr 10.1.0.0/16\n")
	e := NewEngine()
	if err := e.Load([]string{f}, "", nil, discardLog()); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Match(mustAddr("10.1.42.7")); !ok {
		t.Error("address inside cidr must match")
	}
	if _, ok := e.Match(mustAddr("10.2.0.1")); ok {
		t.Error("address outside cidr must NOT match")
	}
}

func TestMatchReturnsReasonSource(t *testing.T) {
	dir := t.TempDir()
	f := writeBan(t, dir, "bans.txt", "# header comment\nip 9.9.9.9\n")
	e := NewEngine()
	if err := e.Load([]string{f}, "", nil, discardLog()); err != nil {
		t.Fatal(err)
	}
	src, ok := e.Match(mustAddr("9.9.9.9"))
	if !ok {
		t.Fatal("expected match")
	}
	if src.Reason != ReasonIP {
		t.Errorf("reason = %q, want banned_ip", src.Reason)
	}
	if src.File != f || src.Line != 2 {
		t.Errorf("source = %s:%d, want %s:2", src.File, src.Line, f)
	}
}

func TestUnionAcrossMultipleFiles(t *testing.T) {
	dir := t.TempDir()
	a := writeBan(t, dir, "a.txt", "ip 1.1.1.1\n")
	b := writeBan(t, dir, "b.txt", "ip 2.2.2.2\n")
	e := NewEngine()
	if err := e.Load([]string{a, b}, "", nil, discardLog()); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Match(mustAddr("1.1.1.1")); !ok {
		t.Error("entry from file A must match")
	}
	if _, ok := e.Match(mustAddr("2.2.2.2")); !ok {
		t.Error("entry from file B must match")
	}
}

func TestReloadSwapsAtomically(t *testing.T) {
	dir := t.TempDir()
	f := writeBan(t, dir, "bans.txt", "ip 1.1.1.1\n")
	e := NewEngine()
	if err := e.Load([]string{f}, "", nil, discardLog()); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Match(mustAddr("1.1.1.1")); !ok {
		t.Fatal("1.1.1.1 must match before reload")
	}
	writeBan(t, dir, "bans.txt", "ip 2.2.2.2\n")
	if err := e.Load([]string{f}, "", nil, discardLog()); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Match(mustAddr("2.2.2.2")); !ok {
		t.Error("new entry must match after reload")
	}
	if _, ok := e.Match(mustAddr("1.1.1.1")); ok {
		t.Error("removed entry must NOT match after reload")
	}
}

func TestMatchTunnelNameAndFingerprint(t *testing.T) {
	dir := t.TempDir()
	f := writeBan(t, dir, "bans.txt", "tunnel-name abcdef2345\ntunnel-fingerprint sha256:deadbeef\n")
	e := NewEngine()
	if err := e.Load([]string{f}, "", nil, discardLog()); err != nil {
		t.Fatal(err)
	}
	if src, ok := e.MatchTunnel("abcdef2345", ""); !ok || src.Reason != ReasonTunnelName {
		t.Errorf("name ban: ok=%v reason=%q", ok, src.Reason)
	}
	if src, ok := e.MatchTunnel("other", "sha256:deadbeef"); !ok || src.Reason != ReasonTunnelFingerprint {
		t.Errorf("fingerprint ban: ok=%v reason=%q", ok, src.Reason)
	}
	if _, ok := e.MatchTunnel("nope", "nope"); ok {
		t.Error("unbanned tunnel must not match")
	}
}

func TestMissingBanFileSkipped(t *testing.T) {
	dir := t.TempDir()
	good := writeBan(t, dir, "good.txt", "ip 1.1.1.1\n")
	missing := filepath.Join(dir, "absent.txt")
	e := NewEngine()
	if err := e.Load([]string{good, missing}, "", nil, discardLog()); err != nil {
		t.Fatalf("absent file must not fail load: %v", err)
	}
	if _, ok := e.Match(mustAddr("1.1.1.1")); !ok {
		t.Error("other file must still be enforced when one is absent")
	}
	writeBan(t, dir, "absent.txt", "ip 2.2.2.2\n")
	if err := e.Load([]string{good, missing}, "", nil, discardLog()); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Match(mustAddr("2.2.2.2")); !ok {
		t.Error("newly-created file's entries must load on next reload")
	}
}

func TestWatchFiresOnReloadOnMtimeChange(t *testing.T) {
	dir := t.TempDir()
	f := writeBan(t, dir, "bans.txt", "ip 1.1.1.1\n")
	e := NewEngine()
	var reloads int32
	w := &watcher{e: e, files: []string{f}, onReload: func(*Engine) { atomic.AddInt32(&reloads, 1) }, log: discardLog()}
	w.initial()
	if atomic.LoadInt32(&reloads) != 1 {
		t.Fatalf("initial load must fire onReload once, got %d", reloads)
	}
	writeBan(t, dir, "bans.txt", "ip 2.2.2.2\n")
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(f, future, future); err != nil {
		t.Fatal(err)
	}
	w.tick()
	if atomic.LoadInt32(&reloads) != 2 {
		t.Errorf("mtime change must fire onReload again, got %d", reloads)
	}
	if _, ok := e.Match(mustAddr("2.2.2.2")); !ok {
		t.Error("reloaded entry must match")
	}
}

func TestBan_MappedIPv6Matches(t *testing.T) {
	dir := t.TempDir()
	f := writeBan(t, dir, "bans.txt", "ip ::ffff:9.9.9.9\n")
	e := NewEngine()
	if err := e.Load([]string{f}, "", nil, discardLog()); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Match(mustAddr("9.9.9.9")); !ok {
		t.Error("a mapped-form ip entry (::ffff:9.9.9.9) must match the plain IPv4 lookup")
	}
}

func TestBan_IPv6EntriesMatch(t *testing.T) {
	dir := t.TempDir()
	f := writeBan(t, dir, "bans.txt", "ip 2001:db8::1\ncidr 2001:db8:1::/48\n")
	e := NewEngine()
	if err := e.Load([]string{f}, "", nil, discardLog()); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Match(mustAddr("2001:db8::1")); !ok {
		t.Error("IPv6 ip entry must match")
	}
	if _, ok := e.Match(mustAddr("2001:db8:1::abcd")); !ok {
		t.Error("IPv6 cidr entry must match an address inside it")
	}
	if _, ok := e.Match(mustAddr("2001:db8:2::1")); ok {
		t.Error("IPv6 address outside the cidr must NOT match")
	}
}

func TestParseLine_ExtraTokensRejected(t *testing.T) {
	for _, line := range []string{"country XX YY", "ip 1.1.1.1 2.2.2.2", "cidr 10.0.0.0/8 extra"} {
		if _, _, err := ParseLine(line); err == nil {
			t.Errorf("ParseLine(%q) expected error (extra tokens)", line)
		}
	}
	if kind, val, err := ParseLine("ip 1.1.1.1"); err != nil || kind != "ip" || val != "1.1.1.1" {
		t.Errorf("valid two-token line rejected: kind=%q val=%q err=%v", kind, val, err)
	}
}

func TestExpandCountries_SkipsMalformedRow(t *testing.T) {
	dir := t.TempDir()
	csv := writeBan(t, dir, "dbip.csv", "garbage-line\n1.0.0.0,notanip,XX\n1.0.0.0,1.0.0.255,XX\n")
	prefixes, err := ExpandCountries(csv, map[string]struct{}{"XX": {}})
	if err != nil {
		t.Fatalf("malformed rows must be skipped, not fatal: %v", err)
	}
	if len(prefixes) == 0 {
		t.Error("the one valid XX row must still expand")
	}
}

func TestExpandCountries_AbsentWantedCodeIsLegal(t *testing.T) {
	dir := t.TempDir()
	csv := writeBan(t, dir, "dbip.csv", dbipFixture) // has XX/YY/ZZ
	prefixes, err := ExpandCountries(csv, map[string]struct{}{"QQ": {}})
	if err != nil {
		t.Fatalf("a valid CSV whose wanted code is absent must be legal (no error): %v", err)
	}
	if len(prefixes) != 0 {
		t.Errorf("absent wanted code must yield empty prefixes, got %d", len(prefixes))
	}
}

func TestBanLoad_PresentCSVFailureKeepsSnapshot(t *testing.T) {
	dir := t.TempDir()
	csv := writeBan(t, dir, "dbip.csv", dbipFixture)
	f := writeBan(t, dir, "bans.txt", "country XX\nip 5.5.5.5\n")
	e := NewEngine()
	if err := e.Load([]string{f}, csv, nil, discardLog()); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Match(mustAddr("1.0.0.5")); !ok {
		t.Fatal("XX must match after the first good load")
	}
	// Replace the CSV with content that yields zero parseable rows (present-but-garbage).
	writeBan(t, dir, "dbip.csv", "not,an,ip\nrow,at,all\n")
	if err := e.Load([]string{f}, csv, nil, discardLog()); err == nil {
		t.Error("a present CSV with zero parseable rows must cause a load error")
	}
	if _, ok := e.Match(mustAddr("1.0.0.5")); !ok {
		t.Error("the previous snapshot (with country bans) must be preserved on a present-CSV failure")
	}
}

func TestWatcher_DetectsDeletionAndEqualMtime(t *testing.T) {
	dir := t.TempDir()
	f := writeBan(t, dir, "bans.txt", "ip 1.1.1.1\n")
	e := NewEngine()
	var reloads int32
	w := &watcher{e: e, files: []string{f}, onReload: func(*Engine) { atomic.AddInt32(&reloads, 1) }, log: discardLog()}
	w.initial()
	if atomic.LoadInt32(&reloads) != 1 {
		t.Fatalf("initial reload count = %d", reloads)
	}
	// Replace with an OLDER mtime (the old max-mtime watcher would miss this).
	writeBan(t, dir, "bans.txt", "ip 2.2.2.2\n")
	older := time.Now().Add(-time.Hour)
	_ = os.Chtimes(f, older, older)
	w.tick()
	if atomic.LoadInt32(&reloads) != 2 {
		t.Errorf("an older-mtime replacement must reload, count = %d", reloads)
	}
	if _, ok := e.Match(mustAddr("2.2.2.2")); !ok {
		t.Error("reloaded entry must match")
	}
	// A previously-loaded file that VANISHES is refused, never silently unbanned: the reload is skipped
	// and the previous snapshot is kept.
	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	w.tick()
	if atomic.LoadInt32(&reloads) != 2 {
		t.Errorf("a vanished loaded file must NOT reload, count = %d", reloads)
	}
	if _, ok := e.Match(mustAddr("2.2.2.2")); !ok {
		t.Error("previous bans must remain enforced after a refused deletion")
	}
}

func TestWatcher_RetriesAfterFailedLoad(t *testing.T) {
	dir := t.TempDir()
	f := writeBan(t, dir, "bans.txt", "ip 1.1.1.1\n")
	e := NewEngine()
	var reloads int32
	w := &watcher{e: e, files: []string{f}, onReload: func(*Engine) { atomic.AddInt32(&reloads, 1) }, log: discardLog()}
	w.initial()
	// Make the next load fail (file → directory).
	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f, 0o755); err != nil {
		t.Fatal(err)
	}
	w.tick()
	if atomic.LoadInt32(&reloads) != 1 {
		t.Fatalf("a failed load must NOT fire onReload, count = %d", reloads)
	}
	// Fix it — the failed load did not consume the change, so the next tick retries.
	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	writeBan(t, dir, "bans.txt", "ip 3.3.3.3\n")
	w.tick()
	if atomic.LoadInt32(&reloads) != 2 {
		t.Errorf("the watcher must retry after a failed load, count = %d", reloads)
	}
	if _, ok := e.Match(mustAddr("3.3.3.3")); !ok {
		t.Error("the retried load must apply the fixed file")
	}
}

func TestWatchLoadErrorKeepsPreviousSnapshot(t *testing.T) {
	dir := t.TempDir()
	f := writeBan(t, dir, "bans.txt", "ip 1.1.1.1\n")
	e := NewEngine()
	var reloads int32
	w := &watcher{e: e, files: []string{f}, onReload: func(*Engine) { atomic.AddInt32(&reloads, 1) }, log: discardLog()}
	w.initial()
	if atomic.LoadInt32(&reloads) != 1 {
		t.Fatalf("initial onReload count = %d", reloads)
	}
	// Replace the file with a directory → a hard read error on the next Load.
	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f, 0o755); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(f, future, future)
	w.tick()
	if atomic.LoadInt32(&reloads) != 1 {
		t.Errorf("load error must NOT fire onReload, count = %d", reloads)
	}
	if _, ok := e.Match(mustAddr("1.1.1.1")); !ok {
		t.Error("previous snapshot must be preserved on load error")
	}
}

func TestParseFile_4in6ShortPrefixSkippedWithWarn(t *testing.T) {
	dir := t.TempDir()
	f := writeBan(t, dir, "bans.txt", "cidr ::ffff:1.2.3.4/64\ncidr ::ffff:1.2.3.4/120\n")
	log, buf := captureLog()
	p, err := parseFile(f, log)
	if err != nil {
		t.Fatalf("parseFile error: %v", err)
	}
	if len(p.prefixes) != 1 {
		t.Fatalf("the /64 4-in-6 entry must be skipped and only the /120 mapped, got %d prefixes", len(p.prefixes))
	}
	if got, want := p.prefixes[0].prefix, netip.MustParsePrefix("1.2.3.0/24"); got != want {
		t.Errorf("/120 4-in-6 must map to %v, got %v", want, got)
	}
	if !strings.Contains(buf.String(), "skipping 4-in-6 cidr") {
		t.Errorf("a warn must be logged for the skipped /64 entry; log = %q", buf.String())
	}
}

func TestWatcher_VanishedFileKeepsSnapshot(t *testing.T) {
	dir := t.TempDir()
	f := writeBan(t, dir, "bans.txt", "ip 1.1.1.1\n")
	e := NewEngine()
	var reloads int32
	log, buf := captureLog()
	w := &watcher{e: e, files: []string{f}, onReload: func(*Engine) { atomic.AddInt32(&reloads, 1) }, log: log}
	w.initial()
	if _, ok := e.Match(mustAddr("1.1.1.1")); !ok {
		t.Fatal("initial ban must be enforced")
	}
	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	w.tick()
	if atomic.LoadInt32(&reloads) != 1 {
		t.Errorf("a vanished loaded file must NOT reload, count = %d", reloads)
	}
	if _, ok := e.Match(mustAddr("1.1.1.1")); !ok {
		t.Error("bans must remain enforced after the file vanished")
	}
	if !strings.Contains(buf.String(), "disappeared") {
		t.Errorf("an error must be logged when a loaded file vanishes; log = %q", buf.String())
	}
	// Restore → the watcher reloads.
	writeBan(t, dir, "bans.txt", "ip 2.2.2.2\n")
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(f, future, future); err != nil {
		t.Fatal(err)
	}
	w.tick()
	if atomic.LoadInt32(&reloads) != 2 {
		t.Errorf("restoring the file must reload, count = %d", reloads)
	}
	if _, ok := e.Match(mustAddr("2.2.2.2")); !ok {
		t.Error("restored bans must be enforced")
	}
}

func TestWatcher_VanishedCSVKeepsSnapshot(t *testing.T) {
	dir := t.TempDir()
	csv := writeBan(t, dir, "dbip.csv", dbipFixture)
	f := writeBan(t, dir, "bans.txt", "country XX\n")
	e := NewEngine()
	var reloads int32
	log, buf := captureLog()
	w := &watcher{e: e, files: []string{f}, csv: csv, onReload: func(*Engine) { atomic.AddInt32(&reloads, 1) }, log: log}
	w.initial()
	if _, ok := e.Match(mustAddr("1.0.0.5")); !ok {
		t.Fatal("country XX must be enforced after initial load")
	}
	if err := os.Remove(csv); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	w.tick()
	if atomic.LoadInt32(&reloads) != 1 {
		t.Errorf("a vanished loaded CSV must NOT reload, count = %d", reloads)
	}
	if _, ok := e.Match(mustAddr("1.0.0.5")); !ok {
		t.Error("country bans must remain enforced after the CSV vanished")
	}
	if !strings.Contains(buf.String(), "disappeared") {
		t.Errorf("an error must be logged when the loaded CSV vanishes; log = %q", buf.String())
	}
}

func TestWatcher_FirstDeployAbsenceStillSkips(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "never.txt") // never created
	e := NewEngine()
	var reloads int32
	w := &watcher{e: e, files: []string{f}, onReload: func(*Engine) { atomic.AddInt32(&reloads, 1) }, log: discardLog()}
	w.initial()
	if atomic.LoadInt32(&reloads) != 1 {
		t.Fatalf("a first-deploy absent file must still complete the initial load, count = %d", reloads)
	}
	w.tick() // still absent, no change → no reload
	if atomic.LoadInt32(&reloads) != 1 {
		t.Errorf("an unchanged absent file must not reload, count = %d", reloads)
	}
	// When the file finally appears it loads.
	writeBan(t, dir, "never.txt", "ip 8.8.8.8\n")
	w.tick()
	if atomic.LoadInt32(&reloads) != 2 {
		t.Errorf("the appearing file must reload, count = %d", reloads)
	}
	if _, ok := e.Match(mustAddr("8.8.8.8")); !ok {
		t.Error("the appeared file's ban must be enforced")
	}
}

func TestWatcher_TornReadRetries(t *testing.T) {
	dir := t.TempDir()
	f := writeBan(t, dir, "bans.txt", "ip 1.1.1.1\n")
	e := NewEngine()
	var reloads int32
	w := &watcher{e: e, files: []string{f}, onReload: func(*Engine) { atomic.AddInt32(&reloads, 1) }, log: discardLog()}
	// Seed the last-loaded baseline so the tick sees a change and proceeds past the fast-path check.
	base := time.Now()
	w.last = map[string]fileState{f: {exists: true, modTime: base, size: 11}}
	// Script the fingerprint source: the file appears to change once (torn) between the pre-load and the
	// first post-load fingerprint, then stabilizes — forcing exactly one retry inside the tick.
	seq := []fileState{
		{exists: true, modTime: base.Add(time.Second), size: 11},     // top cur
		{exists: true, modTime: base.Add(2 * time.Second), size: 11}, // attempt 0 after (differs → retry)
		{exists: true, modTime: base.Add(2 * time.Second), size: 11}, // attempt 1 after (stable → commit)
	}
	var calls int
	w.stat = func(string) fileState {
		i := calls
		if i >= len(seq) {
			i = len(seq) - 1
		}
		calls++
		return seq[i]
	}
	w.tick()
	if calls != 3 {
		t.Errorf("expected a torn-read retry (3 fingerprint reads), got %d", calls)
	}
	if atomic.LoadInt32(&reloads) != 1 {
		t.Errorf("a stable-after-retry load must commit exactly once, count = %d", reloads)
	}
	if _, ok := e.Match(mustAddr("1.1.1.1")); !ok {
		t.Error("the retried load must apply the file")
	}
}
