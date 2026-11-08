package atomicfile_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/atomicfile"
)

func TestWrite_ReplacesTheFileWithTheGivenMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "x.prom")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o644, 0o600} {
		if err := atomicfile.Write(path, []byte("x 1\n"), mode); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != "x 1\n" {
			t.Fatalf("file = %q, %v", got, err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("mode = %v, %v, want %v", info.Mode().Perm(), err, mode)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("the directory must hold only the file: %v, %v", entries, err)
	}
}

func TestWrite_MissingDirectoryFails(t *testing.T) {
	t.Parallel()
	err := atomicfile.Write(filepath.Join(t.TempDir(), "missing", "x.prom"), []byte("x 1\n"), 0o644)
	if err == nil || !strings.Contains(err.Error(), "to flush the file to disk") || errors.Is(err, atomicfile.ErrNotFlushed) {
		t.Fatalf("Write = %v, want a directory open error", err)
	}
}

func TestWrite_AFailedReplaceLeavesNoTemporaryFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "x.prom")
	if err := os.MkdirAll(filepath.Join(path, "inside"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := atomicfile.Write(path, []byte("x 1\n"), 0o644)
	if err == nil || !strings.Contains(err.Error(), "replace "+path) {
		t.Fatalf("Write = %v, want a replace error", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "x.prom" {
		t.Fatalf("the temporary file must be removed: %v, %v", entries, err)
	}
}

func TestWrite_ADirectoryThatCannotBeOpenedFailsBeforeTheFileIsReplaced(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root opens a directory without read permission")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "x.prom")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Errorf("restore the directory mode: %v", err)
		}
	})
	err := atomicfile.Write(path, []byte("new"), 0o644)
	if err == nil || !strings.Contains(err.Error(), "to flush the file to disk") || errors.Is(err, atomicfile.ErrNotFlushed) {
		t.Fatalf("Write = %v, want a directory open error", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "old" {
		t.Fatalf("the file must stay as it was: %q, %v", got, err)
	}
}
