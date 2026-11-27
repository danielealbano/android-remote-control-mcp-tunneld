package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/atomicfile"
)

func TestMetrics_Format(t *testing.T) {
	t.Parallel()
	want := "# HELP arc_active_users Phones (one per tunnel name) with a control connection in the last window, from tunneld's lists of phones seen.\n" +
		"# TYPE arc_active_users gauge\n" +
		"arc_active_users{window=\"24h\"} 3\narc_active_users{window=\"7d\"} 5\narc_active_users{window=\"30d\"} 6\n" +
		"# HELP arc_active_users_counted_timestamp_seconds Time of the count in arc_active_users.\n" +
		"# TYPE arc_active_users_counted_timestamp_seconds gauge\narc_active_users_counted_timestamp_seconds 1795694400\n"
	if got := metrics(map[string]int{"24h": 3, "7d": 5, "30d": 6}, time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)); got != want {
		t.Fatalf("metrics = %q, want %q", got, want)
	}
}

func TestWriteTextfile_WritesTheCounts(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "arc_active_users.prom")
	if err := writeTextfile(atomicfile.Write, path, map[string]int{"24h": 1, "7d": 2, "30d": 3}, testNow); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != wantCounts(1, 2, 3) {
		t.Fatalf("textfile = %q, %v", got, err)
	}
}
