package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/atomicfile"
)

func TestMetrics_OneSeriesPerAppKeyVersionAndAddress(t *testing.T) {
	t.Parallel()
	list := attemptList{Apps: map[string][]attempt{
		"dev.example.copy": {
			{At: time.Unix(1_800_000_000, 0), IP: "198.51.100.7", Key: "aa", Version: 2},
			{At: time.Unix(1_800_000_500, 0), IP: "198.51.100.7", Key: "aa", Version: 2, Verified: true},
			{At: time.Unix(1_800_000_300, 0), IP: "198.51.100.7", Key: "aa", Version: 2},
			{At: time.Unix(1_800_000_900, 0), IP: "203.0.113.9", Key: "aa", Version: 2},
		},
		`dev."quoted"\app`: {{At: time.Unix(1_800_001_000, 0), IP: "198.51.100.7", Key: "bb", Version: 1}},
	}}
	want := `# HELP arc_refused_app_attempts Refused enrollment attempts per app, signing key, app version and source address.
# TYPE arc_refused_app_attempts gauge
arc_refused_app_attempts{app="dev.\"quoted\"\\app",key="bb",version="1",ip="198.51.100.7"} 1
arc_refused_app_attempts{app="dev.example.copy",key="aa",version="2",ip="198.51.100.7"} 3
arc_refused_app_attempts{app="dev.example.copy",key="aa",version="2",ip="203.0.113.9"} 1
# HELP arc_refused_app_first_seen_timestamp_seconds Time of the first refused enrollment attempt per app, signing key, app version and source address.
# TYPE arc_refused_app_first_seen_timestamp_seconds gauge
arc_refused_app_first_seen_timestamp_seconds{app="dev.\"quoted\"\\app",key="bb",version="1",ip="198.51.100.7"} 1800001000
arc_refused_app_first_seen_timestamp_seconds{app="dev.example.copy",key="aa",version="2",ip="198.51.100.7"} 1800000000
arc_refused_app_first_seen_timestamp_seconds{app="dev.example.copy",key="aa",version="2",ip="203.0.113.9"} 1800000900
# HELP arc_refused_app_last_seen_timestamp_seconds Time of the last refused enrollment attempt per app, signing key, app version and source address.
# TYPE arc_refused_app_last_seen_timestamp_seconds gauge
arc_refused_app_last_seen_timestamp_seconds{app="dev.\"quoted\"\\app",key="bb",version="1",ip="198.51.100.7"} 1800001000
arc_refused_app_last_seen_timestamp_seconds{app="dev.example.copy",key="aa",version="2",ip="198.51.100.7"} 1800000500
arc_refused_app_last_seen_timestamp_seconds{app="dev.example.copy",key="aa",version="2",ip="203.0.113.9"} 1800000900
`
	if got := metrics(list); got != want {
		t.Fatalf("metrics =\n%s\nwant\n%s", got, want)
	}
}

func TestLabelValue_EscapesNewlines(t *testing.T) {
	t.Parallel()
	if got := labelValue("a\nb"); got != `a\nb` {
		t.Fatalf("labelValue = %q", got)
	}
}

func TestWriteTextfile_ReplacesTheFileReadableByAll(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "arc_refused_apps.prom")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	list := attemptList{Apps: map[string][]attempt{"dev.example.copy": {{At: time.Unix(1_800_000_000, 0), IP: "198.51.100.7", Key: "aa"}}}}
	if err := writeTextfile(atomicfile.Write, path, list); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `arc_refused_app_attempts{app="dev.example.copy"`) {
		t.Fatalf("file = %s", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, want 0644 so node_exporter can read it", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries, want only the file", len(entries))
	}
}

func TestWriteTextfile_MissingDirectoryFails(t *testing.T) {
	t.Parallel()
	if err := writeTextfile(atomicfile.Write, filepath.Join(t.TempDir(), "missing", "x.prom"), attemptList{}); err == nil {
		t.Fatal("writing into a missing directory must fail")
	}
}
