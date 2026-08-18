package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

func TestNameRecordJSONRoundTrip(t *testing.T) {
	in := store.NameRecord{
		Schema:        1,
		EnrolledAt:    time.Unix(1000, 0).UTC(),
		LastRenewedAt: time.Unix(2000, 0).UTC(),
		IdentityKeyFP: "sha256:abc",
		ClaimNonce:    "0011223344556677",
	}
	in.SetCert(store.CertInfo{
		CA: "letsencrypt", Serial: "01", NotBefore: time.Unix(1000, 0).UTC(),
		NotAfter: time.Unix(9000, 0).UTC(), ARIID: "ari-1",
	})
	in.Device = store.DeviceInfo{OSVersion: 160000, OSPatch: 202607, SecurityLevel: "tee"}

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	// ca is TOP-LEVEL (a sibling of cert), and no cert-PEM/key/chain fields exist.
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["ca"]; !ok {
		t.Error("ca must be a top-level field")
	}
	// The schema keeps the CA ONLY at the top level — the cert sub-object must not repeat it.
	if certObj, ok := raw["cert"].(map[string]any); !ok {
		t.Error("cert sub-object missing")
	} else if _, dup := certObj["ca"]; dup {
		t.Error("ca must NOT appear inside the cert sub-object")
	}
	if raw["claim_nonce"] != "0011223344556677" {
		t.Errorf("claim_nonce missing/wrong: %v", raw["claim_nonce"])
	}
	dev, _ := raw["device"].(map[string]any)
	if dev["os_version"] == nil {
		t.Error("device.os_version must be present")
	}
	// The record stores only an identity-key FINGERPRINT — never PEM material, private keys, or chains.
	for _, forbidden := range []string{"-----begin", "private_key", "cert_pem", "\"chain\"", "\"pem\""} {
		if strings.Contains(strings.ToLower(string(b)), forbidden) {
			t.Errorf("record JSON must not contain %q material: %s", forbidden, b)
		}
	}

	var out store.NameRecord
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.CA != "letsencrypt" || out.Cert.NotBefore.IsZero() || out.ClaimNonce != in.ClaimNonce {
		t.Errorf("round-trip mismatch: %+v", out)
	}
}

func TestEventJSONOmitEmpty(t *testing.T) {
	start := store.Event{Schema: 1, Event: "start", Conn: "aabbccddee", Type: "phone", Tunnel: "t"}
	b, _ := json.Marshal(start)
	if strings.Contains(string(b), "ts_end") || strings.Contains(string(b), "bytes_in") ||
		strings.Contains(string(b), "sni") {
		t.Errorf("start/phone event leaked end-only or public-only fields: %s", b)
	}
	pub := store.Event{Schema: 1, Event: "end", Type: "public", SNI: "x.example.test",
		TSEnd: time.Unix(1, 0), BytesIn: 5}
	b, _ = json.Marshal(pub)
	if !strings.Contains(string(b), "sni") || !strings.Contains(string(b), "ts_end") {
		t.Errorf("public end event should carry sni + ts_end: %s", b)
	}
}

var connIDRe = regexp.MustCompile(`^[0-9a-f]{10}$`)

func TestNewConnIDShapeAndEpoch(t *testing.T) {
	sess := time.Unix(1_000_000, 0)
	id, err := store.NewConnID(sess, sess.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !connIDRe.MatchString(id) {
		t.Errorf("conn id %q is not 10 lowercase hex", id)
	}
	// The 3-byte seconds prefix is deterministic for a fixed elapsed time; only the last 2 bytes (4
	// hex) are random.
	id2, _ := store.NewConnID(sess, sess.Add(5*time.Second))
	if id[:6] != id2[:6] {
		t.Errorf("seconds prefix should be stable: %s vs %s", id, id2)
	}
}

func TestLogKeyLayoutAndSort(t *testing.T) {
	ev := store.Event{Event: "start", Conn: "aabbccddee", Tunnel: "k7m2x9qwp4",
		TSStart: time.Date(2026, 8, 17, 14, 12, 33, 482910114, time.UTC)}
	key := store.LogKey(ev)
	want := "tunnel-logs/k7m2x9qwp4/2026/08/17/20260817T141233.482910114Z-aabbccdd-start.json"
	if key != want {
		t.Errorf("LogKey = %q, want %q", key, want)
	}
	// Chronological string sort: a later event sorts after an earlier one under the same day prefix.
	later := ev
	later.TSStart = ev.TSStart.Add(time.Second)
	if store.LogKey(ev) >= store.LogKey(later) {
		t.Error("keys must sort chronologically")
	}
}

func TestRejectedKeyLayout(t *testing.T) {
	ev := store.RejectedEnrollment{TS: time.Date(2026, 8, 17, 1, 2, 3, 4, time.UTC)}
	key := store.RejectedKey(ev)
	if !strings.HasPrefix(key, "rejected-enroll/2026/08/17/") || !strings.HasSuffix(key, ".json") {
		t.Errorf("RejectedKey layout wrong: %q", key)
	}
}

func TestFakeGetPutDeleteRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := tunneltest.NewStore()
	if _, err := s.GetName(ctx, "x"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("absent name should be ErrNotFound, got %v", err)
	}
	rec := store.NameRecord{Schema: 1, ClaimNonce: "n1"}
	if err := s.PutName(ctx, "x", rec); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetName(ctx, "x")
	if err != nil || got.ClaimNonce != "n1" {
		t.Fatalf("get after put: %+v %v", got, err)
	}
	if err := s.DeleteName(ctx, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetName(ctx, "x"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after delete should be ErrNotFound, got %v", err)
	}
}

func TestFakeFailAndZombiePut(t *testing.T) {
	ctx := context.Background()
	s := tunneltest.NewStore()

	s.FailNextPut = errors.New("clean fail")
	if err := s.PutName(ctx, "a", store.NameRecord{}); err == nil {
		t.Error("FailNextPut should error")
	}
	if _, err := s.GetName(ctx, "a"); !errors.Is(err, store.ErrNotFound) {
		t.Error("clean fail must not write")
	}

	s.ZombieNextPut = errors.New("timeout but landed")
	if err := s.PutName(ctx, "b", store.NameRecord{ClaimNonce: "z"}); err == nil {
		t.Error("ZombieNextPut should error")
	}
	got, err := s.GetName(ctx, "b")
	if err != nil || got.ClaimNonce != "z" {
		t.Errorf("zombie put must land the record despite the error: %+v %v", got, err)
	}
}

func TestFakePutRejectedEnrollment(t *testing.T) {
	ctx := context.Background()
	s := tunneltest.NewStore()
	if err := s.PutRejectedEnrollment(ctx, store.RejectedEnrollment{Reason: "attest-signer"}); err != nil {
		t.Fatal(err)
	}
	if len(s.Rejected) != 1 || s.Rejected[0].Reason != "attest-signer" {
		t.Errorf("evidence not captured: %+v", s.Rejected)
	}
}
