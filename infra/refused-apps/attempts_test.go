package main

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/attest"
)

func TestToAttempt_Variants(t *testing.T) {
	at := time.Date(2026, 11, 3, 2, 48, 0, 123, time.UTC)
	tests := []struct {
		name         string
		reason       string
		spec         func(*chainSpec)
		revoked      revokedSerials
		wantVerified bool
	}{
		{name: "a locked, verified phone refused for its signing key is verified", reason: "attest-signer", wantVerified: true},
		{name: "a refusal after the chain verified but the challenge did not is verified", reason: "attest-challenge", wantVerified: true},
		{name: "an untrusted chain is never verified", reason: "attest-untrusted"},
		{name: "a revoked chain is never verified", reason: "attest-revoked"},
		{name: "an unknown reason is never verified", reason: "conn-rate"},
		{name: "a chain revoked since the attempt is not verified", reason: "attest-signer", revoked: revokedSerials{"1234": true}},
		{name: "an unlocked phone is not verified", reason: "attest-signer", spec: func(s *chainSpec) { s.locked = false }},
		{name: "a self-signed boot is not verified", reason: "attest-signer", spec: func(s *chainSpec) { s.bootState = attest.BootSelfSigned }},
		{name: "a software attestation is not verified", reason: "attest-signer", spec: func(s *chainSpec) { s.securityLevel = attest.SecuritySoftware }},
		{name: "a boot state outside the TEE list is not verified", reason: "attest-signer", spec: func(s *chainSpec) { s.rootInTEE = false }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := goodChain()
			if tc.spec != nil {
				tc.spec(&s)
			}
			revoked := tc.revoked
			if revoked == nil {
				revoked = revokedSerials{}
			}
			app, got := toAttempt(evidence(t, at, "198.51.100.7", tc.reason, s), revoked)
			want := attempt{At: at, IP: "198.51.100.7", Key: hex.EncodeToString(s.digest), Version: 20011770, Verified: tc.wantVerified}
			if app != "dev.example.copy" || got != want {
				t.Fatalf("toAttempt = %q %+v, want %q %+v", app, got, "dev.example.copy", want)
			}
		})
	}
}

func TestToAttempt_KeyFromTheAttestationWhenTheRecordHasNone(t *testing.T) {
	t.Parallel()
	s := goodChain()
	ev := evidence(t, time.Unix(1_800_000_000, 0), "198.51.100.7", "attest-signer", s)
	ev.SignerDigestHex = ""
	_, got := toAttempt(ev, revokedSerials{})
	if got.Key != hex.EncodeToString(s.digest) {
		t.Fatalf("key = %q, want the attested digest", got.Key)
	}
}

func TestToAttempt_UnreadableChainKeepsTheRecordFields(t *testing.T) {
	t.Parallel()
	ev := evidence(t, time.Unix(1_800_000_000, 0), "198.51.100.7", "attest-untrusted", goodChain())
	ev.AttestChainPEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	app, got := toAttempt(ev, revokedSerials{})
	want := attempt{At: ev.TS.UTC(), IP: "198.51.100.7", Key: ev.SignerDigestHex}
	if app != "dev.example.copy" || got != want {
		t.Fatalf("toAttempt = %q %+v, want the record's own package, address and key", app, got)
	}
}

func TestAttemptList_AddSkipsKnownAttempts(t *testing.T) {
	t.Parallel()
	early := attempt{At: time.Unix(1_800_000_000, 5), IP: "198.51.100.7", Key: "aa", Version: 1}
	late := attempt{At: time.Unix(1_800_000_100, 0), IP: "198.51.100.7", Key: "aa", Version: 1}
	list := attemptList{Apps: map[string][]attempt{"dev.example.copy": {late}}}
	idx := list.index()
	if list.add(idx, "dev.example.copy", late) {
		t.Fatal("an attempt already on file was added again")
	}
	if !list.add(idx, "dev.example.copy", early) {
		t.Fatal("a new attempt was not added")
	}
	if list.add(idx, "dev.example.copy", early) {
		t.Fatal("the same new attempt was added twice")
	}
	other := late
	other.IP = "203.0.113.9"
	if !list.add(idx, "dev.example.copy", other) {
		t.Fatal("an attempt from another address at the same time was not added")
	}
	if !list.add(idx, "dev.example.other", late) {
		t.Fatal("the same attempt under another app was not added")
	}
	got := list.Apps["dev.example.copy"]
	if len(got) != 3 || !got[0].At.Equal(early.At) || list.count() != 4 {
		t.Fatalf("attempts = %+v, count %d; want 3 sorted by time and 4 in all", got, list.count())
	}
}
