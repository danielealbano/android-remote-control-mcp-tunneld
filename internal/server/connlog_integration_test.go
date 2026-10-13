//go:build integration

package server

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

func TestIntegration_ConnLogSpoolLeftoverUploadedAtBoot(t *testing.T) {
	dir := t.TempDir()
	name := "20260101T000000.000000000Z-deadbeefdeadbeef.jsonl"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(`{"schema":1,"event":"start","tunnel":"leftover"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := startIntegrationServer(t, func(c *config.ServeCmd) { c.ConnLogDir = dir })
	key := "tunnel-logs/2026/01/01/" + name
	if !waitBool(30*time.Second, func() bool {
		return slices.Contains(tunneltest.S3ListKeys(t, env.s3URL, env.s3Access, env.s3Secret, itBucket, "tunnel-logs/2026/01/01/"), key)
	}) {
		t.Fatalf("a spool file left from a previous run must be uploaded at boot as %s", key)
	}
	if !waitBool(10*time.Second, func() bool {
		_, err := os.Stat(filepath.Join(dir, name))
		return errors.Is(err, fs.ErrNotExist)
	}) {
		t.Fatal("an uploaded leftover spool file must be deleted locally")
	}
}
