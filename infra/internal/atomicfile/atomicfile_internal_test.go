package atomicfile

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSyncDir_AMissingDirectoryFails(t *testing.T) {
	t.Parallel()
	err := syncDir(filepath.Join(t.TempDir(), "missing"))
	if err == nil || !strings.Contains(err.Error(), "to flush the replaced file to disk") {
		t.Fatalf("syncDir = %v, want an open error", err)
	}
}
