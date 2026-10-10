//go:build integration

package acme_test

import (
	"context"
	"strings"
	"testing"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/acme"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

func TestNewLegoClient_EABRegistration(t *testing.T) {
	dirURL, minicaFile, macKeys := tunneltest.StartPebbleEAB(t)
	if macKeys["kid-1"] == "" || macKeys["kid-2"] == "" {
		t.Fatalf("pebble EAB config must provide kid-1 and kid-2, got %d keys", len(macKeys))
	}
	t.Setenv("LEGO_CA_CERTIFICATES", minicaFile)
	tests := []struct {
		name    string
		hmac    string
		wantErr bool
	}{
		{name: "mismatched key", hmac: macKeys["kid-2"], wantErr: true},
		{name: "valid key", hmac: macKeys["kid-1"], wantErr: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := acme.NewLegoClient(context.Background(), acme.LegoConfig{
				CAID: "eab-test", DirectoryURL: dirURL, Email: "ops@example.test",
				EABKID: "kid-1", EABHMAC: tc.hmac,
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("NewLegoClient err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "EAB register") {
				t.Fatalf("the mismatched key must fail at EAB registration, got %v", err)
			}
		})
	}
}
