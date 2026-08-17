package wire

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"
)

func ctHeader() http.Header { return http.Header{"Content-Type": {"application/json"}} }

// authFrameHeader marshals the AUTH frame header ({cert, signature}) with fixed placeholder values so
// the frame bytes are deterministic. The wire contract is field order cert-then-signature; the future
// Kotlin client MUST emit the same shape.
func authFrameHeader() []byte {
	b, _ := json.Marshal(struct {
		Cert      string `json:"cert"`
		Signature string `json:"signature"`
	}{Cert: "Zm9vLWNlcnQ=", Signature: "YmFyLXNpZw=="})
	return b
}

func TestFrameEncodeDecodeRoundTrip(t *testing.T) {
	big := bytes.Repeat([]byte{0xab}, ChunkSize)
	cases := []struct {
		name         string
		typ          FrameType
		header, body []byte
	}{
		{"challenge no body", CHALLENGE, []byte(`{"nonce":"abc"}`), nil},
		{"auth no body", AUTH, []byte(`{"cert":"x","signature":"y"}`), nil},
		{"request head", REQUEST_HEAD, EncodeReqHeader(&ReqEnvelope{ReqID: "r1", Method: "POST", Path: "/mcp", Host: "h"}), nil},
		{"request body chunk 32k", REQUEST_BODY_CHUNK, EncodeReqIDHeader("r1"), big},
		{"request end", REQUEST_END, EncodeReqIDHeader("r1"), nil},
		{"response head", RESPONSE_HEAD, EncodeRespHeader("r1", 200, nil), nil},
		{"response body chunk empty", RESPONSE_BODY_CHUNK, EncodeReqIDHeader("r1"), []byte{}},
		{"response end", RESPONSE_END, EncodeReqIDHeader("r1"), nil},
		{"error", ERROR, EncodeErrorHeader("r1", "boom"), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc := EncodeFrame(tc.typ, tc.header, tc.body)
			typ, hdr, body, err := DecodeFrame(enc)
			if err != nil {
				t.Fatal(err)
			}
			if typ != tc.typ {
				t.Errorf("type = %d, want %d", typ, tc.typ)
			}
			if !bytes.Equal(hdr, tc.header) {
				t.Errorf("header mismatch")
			}
			if !bytes.Equal(body, tc.body) && (len(body) != 0 || len(tc.body) != 0) {
				t.Errorf("body mismatch: %d vs %d", len(body), len(tc.body))
			}
		})
	}
	if _, _, _, err := DecodeFrame([]byte{0x01, 0x00}); err == nil {
		t.Error("short frame must error")
	}
}

// TestGoldenFrameFixtures pins canonical frame encodings against committed golden files so the Go
// and future Kotlin clients cannot drift.
func TestGoldenFrameFixtures(t *testing.T) {
	cases := map[string][]byte{
		"request_head.frame": EncodeFrame(REQUEST_HEAD, EncodeReqHeader(&ReqEnvelope{
			ReqID: "req-0001", Method: "POST", Path: "/mcp", RawQuery: "", Host: "abc2345678.example.test",
			Header: ctHeader(),
		}), nil),
		"request_body_chunk.frame":  EncodeFrame(REQUEST_BODY_CHUNK, EncodeReqIDHeader("req-0001"), []byte("hello-body")),
		"request_end.frame":         EncodeFrame(REQUEST_END, EncodeReqIDHeader("req-0001"), nil),
		"response_head.frame":       EncodeFrame(RESPONSE_HEAD, EncodeRespHeader("req-0001", 200, ctHeader()), nil),
		"response_body_chunk.frame": EncodeFrame(RESPONSE_BODY_CHUNK, EncodeReqIDHeader("req-0001"), []byte("hello-body")),
		"response_end.frame":        EncodeFrame(RESPONSE_END, EncodeReqIDHeader("req-0001"), nil),
		"error.frame":               EncodeFrame(ERROR, EncodeErrorHeader("req-0001", "backend error"), nil),
		"auth.frame":                EncodeFrame(AUTH, authFrameHeader(), nil),
	}
	for name, got := range cases {
		want, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s golden drift: got %d bytes, want %d", name, len(got), len(want))
		}
	}
}

func TestWire_DecodeErrors(t *testing.T) {
	if _, _, err := DecodeReqHeader([]byte("{not json"), nil); err == nil {
		t.Error("DecodeReqHeader must error on a malformed header (no fabricated request)")
	}
	hdr := EncodeReqHeader(&ReqEnvelope{ReqID: "r1", Method: "POST", Path: "/mcp", Host: "h"})
	if id, req, err := DecodeReqHeader(hdr, []byte("body")); err != nil || req == nil || id != "r1" {
		t.Errorf("valid header: id=%q req=%v err=%v", id, req, err)
	}
	if _, err := UnmarshalReq([]byte{0x00, 0x01}); err == nil {
		t.Error("UnmarshalReq must error on a too-short buffer")
	}
	if _, err := UnmarshalResp([]byte{0x00}); err == nil {
		t.Error("UnmarshalResp must error on a too-short buffer")
	}
	if _, err := UnmarshalReq([]byte{0x00, 0x00, 0x00, 0x0a, 0x7b}); err == nil {
		t.Error("UnmarshalReq must error when the header length overruns the buffer")
	}
}

func TestGoldenFrameFixtures_ChallengeAndAuth(t *testing.T) {
	t.Run("challenge", func(t *testing.T) {
		data, err := os.ReadFile("testdata/challenge.frame")
		if err != nil {
			t.Fatal(err)
		}
		typ, hdr, body, err := DecodeFrame(data)
		if err != nil {
			t.Fatalf("challenge.frame is not a valid frame: %v", err)
		}
		if typ != CHALLENGE {
			t.Errorf("type = %d, want CHALLENGE(%d)", typ, CHALLENGE)
		}
		if len(body) != 0 {
			t.Errorf("CHALLENGE must carry no body, got %d bytes", len(body))
		}
		var h struct {
			Nonce []byte `json:"nonce"`
		}
		if err := json.Unmarshal(hdr, &h); err != nil {
			t.Fatalf("CHALLENGE header is not valid JSON: %v", err)
		}
		if len(h.Nonce) != 32 {
			t.Errorf("nonce = %d bytes, want 32", len(h.Nonce))
		}
	})

	t.Run("auth", func(t *testing.T) {
		data, err := os.ReadFile("testdata/auth.frame")
		if err != nil {
			t.Fatal(err)
		}
		typ, hdr, body, err := DecodeFrame(data)
		if err != nil {
			t.Fatalf("auth.frame is not a valid frame: %v", err)
		}
		if typ != AUTH {
			t.Errorf("type = %d, want AUTH(%d)", typ, AUTH)
		}
		if len(body) != 0 {
			t.Errorf("AUTH must carry no body, got %d bytes", len(body))
		}
		var h struct {
			Cert      string `json:"cert"`
			Signature string `json:"signature"`
		}
		if err := json.Unmarshal(hdr, &h); err != nil {
			t.Fatalf("AUTH header is not valid JSON: %v", err)
		}
		if h.Cert == "" || h.Signature == "" {
			t.Errorf("AUTH must carry both cert and signature, got cert=%q signature=%q", h.Cert, h.Signature)
		}
	})
}

func TestFrameReqIDExtraction(t *testing.T) {
	if id := FrameReqID(EncodeReqIDHeader("xyz")); id != "xyz" {
		t.Errorf("FrameReqID = %q, want xyz", id)
	}
	if id := FrameReqID(EncodeErrorHeader("eid", "msg")); id != "eid" {
		t.Errorf("FrameReqID(error) = %q, want eid", id)
	}
}
