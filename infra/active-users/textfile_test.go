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
		"# HELP arc_recurring_active_users Phones (one per tunnel name) with a control connection in the last window and in the window of the same length before it, from tunneld's lists of phones seen.\n" +
		"# TYPE arc_recurring_active_users gauge\n" +
		"arc_recurring_active_users{window=\"24h\"} 1\narc_recurring_active_users{window=\"7d\"} 2\narc_recurring_active_users{window=\"30d\"} 4\n" +
		"# HELP arc_active_users_counted_timestamp_seconds Time of the count in arc_active_users and arc_recurring_active_users.\n" +
		"# TYPE arc_active_users_counted_timestamp_seconds gauge\narc_active_users_counted_timestamp_seconds 1795694400\n"
	n := counts{active: map[string]int{"24h": 3, "7d": 5, "30d": 6}, recurring: map[string]int{"24h": 1, "7d": 2, "30d": 4}}
	if got := metrics(n, time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)); got != want {
		t.Fatalf("metrics = %q, want %q", got, want)
	}
}

func TestWriteTextfile_WritesTheCounts(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "arc_active_users.prom")
	n := counts{active: map[string]int{"24h": 1, "7d": 2, "30d": 3}, recurring: map[string]int{"24h": 0, "7d": 1, "30d": 2}}
	if err := writeTextfile(atomicfile.Write, path, n, testNow); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != wantCounts(1, 2, 3, 0, 1, 2) {
		t.Fatalf("textfile = %q, %v", got, err)
	}
}
