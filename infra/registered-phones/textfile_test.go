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
	want := "# HELP arc_registered_phones Phones enrolled since the first counted day that got a certificate, renewed or not, kept even when their name record is gone.\n" +
		"# TYPE arc_registered_phones gauge\narc_registered_phones 34\n" +
		"# HELP arc_registered_phones_counted_timestamp_seconds Time of the count in arc_registered_phones.\n" +
		"# TYPE arc_registered_phones_counted_timestamp_seconds gauge\narc_registered_phones_counted_timestamp_seconds 1794052800\n"
	if got := metrics(34, time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)); got != want {
		t.Fatalf("metrics = %q, want %q", got, want)
	}
}

func TestWriteTextfile_WritesTheCount(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "arc_registered_phones.prom")
	if err := writeTextfile(atomicfile.Write, path, 7, testNow); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != metrics(7, testNow) {
		t.Fatalf("textfile = %q, %v", got, err)
	}
}
