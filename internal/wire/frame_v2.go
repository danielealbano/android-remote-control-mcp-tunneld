// Package wire is the v2 (E2E) wire contract: the length-framed control-stream codec (dial-back, ping,
// renewal nudge) and ChunkSize (the opaque data-splice pacing size). See docs/PROTOCOL.md — the
// canonical contract both the Go and Kotlin clients conform to.
package wire

import (
	"encoding/binary"
	"encoding/json"
	"errors"
)

// Wire protocol v2 (the E2E contract). The phone's HTTP/2 CONTROL stream carries length-framed control
// messages defined here. The DATA stream is an OPAQUE raw byte splice (it carries interactive TLS
// records; HTTP/2 END_STREAM is teardown), so it has NO framing — ChunkSize is only the
// bandwidth-pacing slice size. The mesh stream identifies itself via HTTP/2 request
// headers (X-Tunnel / X-Conn-Id / X-Stream-Id — docs/PROTOCOL.md §5); its body is the opaque splice.
//
// The control-frame enum is a DISTINCT type ControlType with permanent Ctrl-prefixed names.

// ControlType identifies a v2 control-stream frame. Layout: [type:1][payloadLen:4 BE][payload JSON].
type ControlType byte

const (
	CtrlOpen       ControlType = iota + 1 // server→phone dial-back for ONE public connection {streamID}
	CtrlPing                              // liveness
	CtrlPong                              // liveness
	CtrlRenewNudge                        // server→phone {nonce, ariWindow}: "renew now" — the phone answers by calling POST /issue (mTLS)
)

// maxControlPayload bounds a control-frame payload. The v2 control stream carries only small frames
// (dial-back announcements, liveness, the renewal nudge); certificate material (attestation chains,
// CSRs, issued certs) travels over the mTLS POST /issue endpoint, NOT the stream.
const maxControlPayload = 1 << 20 // 1 MiB

// ChunkSize is the paced-copy read/slice size — the max body bytes read and charged per bandwidth
// window step at the edge, and nothing more: HTTP/2 framing and flow control use the library defaults
// (docs/PROTOCOL.md §6). It is internal (the data stream is an opaque, unframed splice — see the
// package overview), NOT part of the phone-client wire contract.
const ChunkSize = 16 * 1024

// --- payloads ---

// OpenPayload announces an incoming public connection to dial back; streamID is the per-public-
// connection id, DISTINCT from the phone connection's route connID.
type OpenPayload struct {
	StreamID string `json:"stream_id"`
}

// RenewNudgePayload prompts a renewal: the phone answers by calling POST /issue (mTLS) with a fresh
// attestation over Nonce plus rotated identity + TLS CSRs. Nonce is a single-use, server-minted challenge
// (Valkey-stored, like an initial-enrollment nonce); ARIWindow is the advisory suggested renewal time.
type RenewNudgePayload struct {
	Nonce     string `json:"nonce"` // hex
	ARIWindow string `json:"ari_window,omitempty"`
}

var (
	// ErrControlTooLarge is returned when a control frame exceeds maxControlPayload.
	ErrControlTooLarge = errors.New("wire: control frame too large")
	// ErrControlMalformed is returned for a truncated/invalid control frame.
	ErrControlMalformed = errors.New("wire: malformed control frame")
)

// EncodeControl encodes a v2 control frame with a JSON payload.
func EncodeControl(t ControlType, payload any) ([]byte, error) {
	var body []byte
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = b
	}
	if len(body) > maxControlPayload {
		return nil, ErrControlTooLarge
	}
	out := make([]byte, 5+len(body))
	out[0] = byte(t)
	binary.BigEndian.PutUint32(out[1:5], uint32(len(body)))
	copy(out[5:], body)
	return out, nil
}

// DecodeControl parses a v2 control frame, returning the type and raw JSON payload.
func DecodeControl(data []byte) (ControlType, []byte, error) {
	if len(data) < 5 {
		return 0, nil, ErrControlMalformed
	}
	n := binary.BigEndian.Uint32(data[1:5])
	if n > maxControlPayload || int(n) != len(data)-5 {
		return 0, nil, ErrControlMalformed
	}
	return ControlType(data[0]), data[5:], nil
}
