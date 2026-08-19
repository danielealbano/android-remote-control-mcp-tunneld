package store

import (
	"errors"
	"testing"
)

// TestMustConnID_RandFailureFallback forces the crypto/rand failure path and asserts MustConnID returns
// the deterministic non-empty fallback (an empty id would be 400-refused by the dial-back match).
func TestMustConnID_RandFailureFallback(t *testing.T) {
	orig := connIDRand
	t.Cleanup(func() { connIDRand = orig })
	connIDRand = func([]byte) (int, error) { return 0, errors.New("no entropy") }

	if _, err := NewConnID(); err == nil {
		t.Fatal("NewConnID must return an error when the entropy source fails")
	}
	if id := MustConnID(); id != "00000000" {
		t.Fatalf("MustConnID must fall back to the non-empty %q, got %q", "00000000", id)
	}
}
