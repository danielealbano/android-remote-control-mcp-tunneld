package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMetrics_Format(t *testing.T) {
	t.Parallel()
	want := "# HELP arc_registered_phones Phones enrolled since the first counted day that got a certificate, renewed or not.\n" +
		"# TYPE arc_registered_phones gauge\narc_registered_phones 34\n"
	if got := metrics(34); got != want {
		t.Fatalf("metrics = %q, want %q", got, want)
	}
}

func TestWriteTextfile_ReplacesTheFileReadableByNodeExporter(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "arc_registered_phones.prom")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeTextfile(path, 7); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != metrics(7) {
		t.Fatalf("textfile = %q, %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, %v, want 0644", info.Mode().Perm(), err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("the directory must hold only the textfile: %v, %v", entries, err)
	}
}

func TestRemoveTextfile(t *testing.T) {
	t.Parallel()
	cause := errors.New("count failed")
	path := filepath.Join(t.TempDir(), "arc_registered_phones.prom")
	if err := removeTextfile(path, cause); err != cause {
		t.Fatalf("removing a missing file = %v, want the cause alone", err)
	}
	if err := os.WriteFile(path, []byte(metrics(1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeTextfile(path, cause); err != cause {
		t.Fatalf("removeTextfile = %v, want the cause alone", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the file must be gone, stat = %v", err)
	}
}
