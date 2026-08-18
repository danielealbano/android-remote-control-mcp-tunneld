package wire

import (
	"encoding/binary"
	"encoding/json"
	"errors"
)

// Wire protocol v2 (Plan 3, E2E). The phone's HTTP/2 CONTROL stream carries length-framed control
// messages defined here. The DATA stream is an OPAQUE raw byte splice (it carries interactive TLS
// records; HTTP/2 END_STREAM is teardown), so it has NO framing — ChunkSize (retained from frame.go)
// is only the bandwidth-pacing slice size. The mesh stream is prefixed with ONE StreamOpen header.
//
// These v2 types are ADDED alongside the Plan-1 frame codec (kept until the US13 teardown). To avoid
// colliding with the still-present v1 constants (CHALLENGE…ERROR), the v2 control-frame enum is a
// DISTINCT type ControlType with permanent Ctrl-prefixed names.

// ControlType identifies a v2 control-stream frame. Layout: [type:1][payloadLen:4 BE][payload JSON].
type ControlType byte

const (
	CtrlOpen           ControlType = iota + 1 // server→phone dial-back for ONE public connection {streamID}
	CtrlClose                                 // {streamID, reason}
	CtrlPing                                  // liveness
	CtrlPong                                  // liveness
	CtrlRenewNudge                            // server→phone {ariWindow}
	CtrlRenewRequest                          // phone→server (initiate renewal)
	CtrlRenewChallenge                        // server→phone {nonce}
	CtrlRenewSubmit                           // phone→server {attestationChainPEM, identityCSR, tlsCSR}
	CtrlCertPush                              // server→phone {identityCertPEM, publicCertPEM}
	CtrlError                                 // {reason, retryable, retryAfter}
)

// maxControlPayload bounds a control-frame payload (renewal frames carry PEM chains + CSRs).
const maxControlPayload = 1 << 20 // 1 MiB

// --- payloads ---

// OpenPayload announces an incoming public connection to dial back; streamID is the per-public-
// connection id, DISTINCT from the phone connection's route connID.
type OpenPayload struct {
	StreamID string `json:"stream_id"`
}

// ClosePayload tears down one dial-back stream.
type ClosePayload struct {
	StreamID string `json:"stream_id"`
	Reason   string `json:"reason,omitempty"`
}

// RenewNudgePayload prompts an early renewal (ARI-driven or migrate-to-LE).
type RenewNudgePayload struct {
	ARIWindow string `json:"ari_window,omitempty"`
}

// RenewChallengePayload carries the fresh attestation nonce for a renewal.
type RenewChallengePayload struct {
	Nonce string `json:"nonce"` // hex
}

// RenewSubmitPayload is the phone's renewal submission (fresh attestation + rotated keys).
type RenewSubmitPayload struct {
	AttestationChainPEM string `json:"attestation_chain"`
	IdentityCSR         string `json:"identity_csr"` // PEM
	TLSCSR              string `json:"tls_csr"`      // PEM
}

// CertPushPayload delivers the renewal/issuance result to the phone.
type CertPushPayload struct {
	IdentityCertPEM string `json:"identity_cert"`
	PublicCertPEM   string `json:"public_cert"`
}

// ErrorPayload is a structured control-stream error.
type ErrorPayload struct {
	Reason     string `json:"reason"`
	Retryable  bool   `json:"retryable"`
	RetryAfter int64  `json:"retry_after_seconds,omitempty"`
}

// StreamOpenHeader prefixes a mesh data stream: connID (the phone connection's route id, for owner
// verification) + streamID (the public connection).
type StreamOpenHeader struct {
	Tunnel   string `json:"tunnel"`
	ConnID   string `json:"conn_id"`
	StreamID string `json:"stream_id"`
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

// EncodeStreamOpen encodes the mesh StreamOpen header (length-prefixed JSON) prepended to a mesh data
// stream.
func EncodeStreamOpen(h StreamOpenHeader) ([]byte, error) {
	body, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out[0:4], uint32(len(body)))
	copy(out[4:], body)
	return out, nil
}

// DecodeStreamOpen parses a mesh StreamOpen header from the front of a stream, returning the header and
// the number of bytes consumed.
func DecodeStreamOpen(data []byte) (StreamOpenHeader, int, error) {
	if len(data) < 4 {
		return StreamOpenHeader{}, 0, ErrControlMalformed
	}
	n := binary.BigEndian.Uint32(data[0:4])
	if n > maxControlPayload || len(data) < 4+int(n) {
		return StreamOpenHeader{}, 0, ErrControlMalformed
	}
	var h StreamOpenHeader
	if err := json.Unmarshal(data[4:4+n], &h); err != nil {
		return StreamOpenHeader{}, 0, ErrControlMalformed
	}
	return h, 4 + int(n), nil
}
