package limit

import (
	"crypto/rand"
	"encoding/hex"
)

// mintToken returns a random lock-holder token (best-effort release checks it).
func mintToken() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
