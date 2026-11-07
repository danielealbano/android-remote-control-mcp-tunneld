package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMetrics_Format(t *testing.T) {
	t.Parallel()
	want := "# HELP arc_registered_phones Phones enrolled since the first counted day that got a certificate, renewed or not.\n" +
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
	if err := writeTextfile(path, 7, testNow); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != metrics(7, testNow) {
		t.Fatalf("textfile = %q, %v", got, err)
	}
}

func TestRemoveTextfile(t *testing.T) {
	t.Parallel()
	cause := errors.New("count failed")
	dir := t.TempDir()
	path := filepath.Join(dir, "arc_registered_phones.prom")
	if err := removeTextfile(path, cause); err != cause {
		t.Fatalf("removing a missing file = %v, want the cause alone", err)
	}
	if err := os.WriteFile(path, []byte(metrics(1, testNow)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeTextfile(path, cause); err != cause {
		t.Fatalf("removeTextfile = %v, want the cause alone", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the file must be gone, stat = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(path, "inside"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := removeTextfile(path, cause)
	if !errors.Is(err, cause) || !errors.Is(err, errTextfileKept) {
		t.Fatalf("a failed removal = %v, want the cause joined with errTextfileKept", err)
	}
}
