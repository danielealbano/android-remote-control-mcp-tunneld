package wire

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestControlFrameRoundTrip(t *testing.T) {
	cases := []struct {
		ct      ControlType
		payload any
	}{
		{CtrlOpen, OpenPayload{Token: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", Addr: "203.0.113.10:443", UseHTTPS: true, UseMTLS: true}},
		{CtrlPing, nil},
		{CtrlPong, nil},
		{CtrlRenewNudge, RenewNudgePayload{Nonce: "00112233", ARIWindow: "2026-08-20T00:00:00Z"}},
	}
	for _, tc := range cases {
		enc, err := EncodeControl(tc.ct, tc.payload)
		if err != nil {
			t.Fatalf("encode %d: %v", tc.ct, err)
		}
		if ControlType(enc[0]) != tc.ct {
			t.Errorf("type byte = %d, want %d", enc[0], tc.ct)
		}
		ct, body, err := DecodeControl(enc)
		if err != nil || ct != tc.ct {
			t.Fatalf("decode %d: ct=%d err=%v", tc.ct, ct, err)
		}
		// Byte-exactness: re-encoding the decoded payload yields identical bytes.
		if tc.payload != nil {
			want, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(body, want) {
				t.Errorf("payload bytes mismatch for %d: got %s want %s", tc.ct, body, want)
			}
		} else if len(body) != 0 {
			t.Errorf("no-payload frame %d has body %q", tc.ct, body)
		}
		if op, ok := tc.payload.(OpenPayload); ok {
			var got OpenPayload
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatalf("unmarshal OPEN: %v", err)
			}
			if got != op {
				t.Errorf("OPEN round-trip = %+v, want %+v", got, op)
			}
		}
	}
}

func TestOpenPayload_JSONFieldNames(t *testing.T) {
	b, err := json.Marshal(OpenPayload{Token: "t", Addr: "a:1", UseHTTPS: true, UseMTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	want := []string{"token", "addr", "use_https", "use_mtls"}
	if len(m) != len(want) {
		t.Fatalf("OPEN keys = %v, want exactly %v", m, want)
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Errorf("OPEN JSON lacks %q: %s", k, b)
		}
	}
}

func TestDialBackConstantsFrozen(t *testing.T) {
	if DialBackPath != "/api/v1/data" {
		t.Errorf("DialBackPath = %q", DialBackPath)
	}
	if DialBackHeader != "X-Dial-Token" {
		t.Errorf("DialBackHeader = %q", DialBackHeader)
	}
	if DialUpgrade != "tunneld-dial" {
		t.Errorf("DialUpgrade = %q", DialUpgrade)
	}
}

// TestControlTypeValuesFrozen pins the numeric wire values of the frame set — docs/PROTOCOL.md §3
// is the canonical contract the Kotlin client conforms to, so these bytes must never drift.
func TestControlTypeValuesFrozen(t *testing.T) {
	want := map[ControlType]byte{CtrlOpen: 1, CtrlPing: 2, CtrlPong: 3, CtrlRenewNudge: 4}
	for ct, v := range want {
		if byte(ct) != v {
			t.Errorf("frame type value drifted: %d != %d", byte(ct), v)
		}
	}
}

func TestChunkSizeConstant(t *testing.T) {
	if ChunkSize != 16384 {
		t.Errorf("ChunkSize = %d, want 16384 (pacing slice size)", ChunkSize)
	}
}

func TestControlRejectsOversizeAndMalformed(t *testing.T) {
	if _, _, err := DecodeControl([]byte{1, 2}); err == nil {
		t.Error("short frame should error")
	}
	// Length field claims more bytes than present.
	bad := []byte{byte(CtrlPing), 0, 0, 0, 9, 1, 2, 3}
	if _, _, err := DecodeControl(bad); err == nil {
		t.Error("length/payload mismatch should error")
	}
}
