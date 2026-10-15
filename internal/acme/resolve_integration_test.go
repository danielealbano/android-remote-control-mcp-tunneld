//go:build integration

package acme_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/acme"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

func readAccountKey(t *testing.T, accountDir, id string) *ecdsa.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(accountDir, "accounts", id+".key"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("account key %s is not PEM", id)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestNewLegoClient_ResolveOnlyNeverCreates(t *testing.T) {
	env := tunneltest.StartPebble(t)
	t.Setenv("LEGO_CA_CERTIFICATES", env.MinicaFile)
	dir := t.TempDir()
	resolve := func(key *ecdsa.PrivateKey, label string) error {
		_, err := acme.NewLegoClient(context.Background(), acme.LegoConfig{
			CAID: acme.CAGTS, DirectoryURL: env.DirectoryURL, Email: "ops@example.test",
			AccountKey: key, ResolveOnly: true, Label: label,
		})
		return err
	}
	unregistered := tunneltest.WriteACMEAccountKey(t, dir, "gts-1")
	for i := range 2 {
		if err := resolve(unregistered, "gts-1"); err == nil || !strings.Contains(err.Error(), "tunneld never creates this account") {
			t.Fatalf("call %d: NewLegoClient = %v, want the unknown account refused", i+1, err)
		}
	}
	tunneltest.RegisterACMEAccountKey(t, dir, "gts-2", env.DirectoryURL)
	if err := resolve(readAccountKey(t, dir, "gts-2"), "gts-2"); err != nil {
		t.Fatalf("a registered key must resolve: %v", err)
	}
}
