package phoneconn

import (
	"encoding/binary"
	"io"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// readControlFrame reads one length-framed control frame from r: [type:1][len:4 BE][payload].
func readControlFrame(r io.Reader) ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:5])
	if n > 1<<20 {
		// An oversize length prefix is a wire-protocol violation, not a transport error: surface the
		// distinct sentinel so readPump records close_reason=protocol-error (not phone-close).
		return nil, wire.ErrControlTooLarge
	}
	frame := make([]byte, 5+int(n))
	copy(frame, hdr[:])
	if _, err := io.ReadFull(r, frame[5:]); err != nil {
		return nil, err
	}
	return frame, nil
}
