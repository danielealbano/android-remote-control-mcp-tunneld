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
		{CtrlOpen, OpenPayload{StreamID: "aabbccddee"}},
		{CtrlClose, ClosePayload{StreamID: "aabbccddee", Reason: "client-close"}},
		{CtrlPing, nil},
		{CtrlPong, nil},
		{CtrlRenewNudge, RenewNudgePayload{Nonce: "00112233", ARIWindow: "2026-08-20T00:00:00Z"}},
		{CtrlError, ErrorPayload{Reason: "rate_limited", Retryable: true, RetryAfter: 3600}},
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
			want, _ := json.Marshal(tc.payload)
			if !bytes.Equal(body, want) {
				t.Errorf("payload bytes mismatch for %d: got %s want %s", tc.ct, body, want)
			}
		} else if len(body) != 0 {
			t.Errorf("no-payload frame %d has body %q", tc.ct, body)
		}
	}
}

func TestMeshStreamOpenRoundTrip(t *testing.T) {
	h := StreamOpenHeader{Tunnel: "k7m2x9qwp4", ConnID: "1122334455", StreamID: "aabbccddee"}
	enc, err := EncodeStreamOpen(h)
	if err != nil {
		t.Fatal(err)
	}
	got, n, err := DecodeStreamOpen(enc)
	if err != nil || n != len(enc) {
		t.Fatalf("decode: n=%d err=%v", n, err)
	}
	if got != h {
		t.Errorf("round-trip mismatch: %+v vs %+v", got, h)
	}
	// A data payload following the header is not consumed by the decoder.
	withData := append(enc, []byte("RAW-TLS-BYTES")...)
	_, consumed, _ := DecodeStreamOpen(withData)
	if consumed != len(enc) {
		t.Errorf("decoder consumed %d, should stop at the header boundary %d", consumed, len(enc))
	}
}

func TestChunkSizeConstant(t *testing.T) {
	if ChunkSize != 32768 {
		t.Errorf("ChunkSize = %d, want 32768 (pacing slice size)", ChunkSize)
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
