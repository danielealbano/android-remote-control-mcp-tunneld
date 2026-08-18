// Package edge is the raw TCP :443 public edge: it peeks the TLS ClientHello (SNI/ALPN/version + a
// stable JA4 fingerprint), applies accept-time checks (ban-first, per-IP connection rate,
// --max-clients), routes reserved SNIs to the local TLS terminators and tunnel SNIs to the bridge
// (local fast path or mesh), and enforces the frontend connection policy. See the Plan-3 record.
package edge

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ClientHelloInfo is the peeked, routing-relevant ClientHello data.
type ClientHelloInfo struct {
	SNI        string
	ALPN       string
	TLSVersion string
	JA4        string
}

var errBadClientHello = errors.New("edge: malformed ClientHello")

// isGREASE reports whether a 2-byte value is a GREASE value (0x?a?a) excluded from JA4.
func isGREASE(v uint16) bool { return (v&0x0f0f) == 0x0a0a && (v>>8) == (v&0xff) }

// isAlnum reports whether b is an ASCII alphanumeric byte (the JA4 ALPN-component character class).
func isAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}

// parseClientHello parses a full TLS record containing a ClientHello and returns the routing info +
// a JA4-style fingerprint (ciphers and extensions SORTED before hashing → stable under the
// extension-order randomization that killed JA3).
func parseClientHello(record []byte) (ClientHelloInfo, error) {
	// TLS record: type(1)=0x16, version(2), length(2), then the handshake.
	if len(record) < 5 || record[0] != 0x16 {
		return ClientHelloInfo{}, errBadClientHello
	}
	hs := record[5:]
	// Handshake: type(1)=0x01, length(3), then the ClientHello body.
	if len(hs) < 4 || hs[0] != 0x01 {
		return ClientHelloInfo{}, errBadClientHello
	}
	b := hs[4:]
	// legacy_version(2) + random(32).
	if len(b) < 34 {
		return ClientHelloInfo{}, errBadClientHello
	}
	legacyVer := uint16(b[0])<<8 | uint16(b[1])
	b = b[34:]
	// session_id.
	if len(b) < 1 {
		return ClientHelloInfo{}, errBadClientHello
	}
	sidLen := int(b[0])
	b = b[1:]
	if len(b) < sidLen {
		return ClientHelloInfo{}, errBadClientHello
	}
	b = b[sidLen:]
	// cipher_suites.
	if len(b) < 2 {
		return ClientHelloInfo{}, errBadClientHello
	}
	csLen := int(b[0])<<8 | int(b[1])
	b = b[2:]
	if len(b) < csLen || csLen%2 != 0 {
		return ClientHelloInfo{}, errBadClientHello
	}
	var ciphers []uint16
	for i := 0; i < csLen; i += 2 {
		v := uint16(b[i])<<8 | uint16(b[i+1])
		if !isGREASE(v) {
			ciphers = append(ciphers, v)
		}
	}
	b = b[csLen:]
	// compression_methods.
	if len(b) < 1 {
		return ClientHelloInfo{}, errBadClientHello
	}
	compLen := int(b[0])
	b = b[1:]
	if len(b) < compLen {
		return ClientHelloInfo{}, errBadClientHello
	}
	b = b[compLen:]
	// extensions.
	info := ClientHelloInfo{}
	var extIDs []uint16
	var sigAlgs []uint16
	var supportedVerMax uint16
	if len(b) >= 2 {
		extTotal := int(b[0])<<8 | int(b[1])
		b = b[2:]
		if len(b) < extTotal {
			return ClientHelloInfo{}, errBadClientHello
		}
		ext := b[:extTotal]
		for len(ext) >= 4 {
			etype := uint16(ext[0])<<8 | uint16(ext[1])
			elen := int(ext[2])<<8 | int(ext[3])
			ext = ext[4:]
			if len(ext) < elen {
				break
			}
			data := ext[:elen]
			ext = ext[elen:]
			if !isGREASE(etype) {
				extIDs = append(extIDs, etype)
			}
			switch etype {
			case 0x0000: // SNI
				info.SNI = parseSNI(data)
			case 0x0010: // ALPN
				info.ALPN = parseFirstALPN(data)
			case 0x000d: // signature_algorithms
				sigAlgs = parseUint16List(data)
			case 0x002b: // supported_versions
				supportedVerMax = parseSupportedVersionsMax(data)
			}
		}
	}
	info.TLSVersion = versionString(pickVersion(legacyVer, supportedVerMax))
	info.JA4 = computeJA4(info, ciphers, extIDs, sigAlgs)
	return info, nil
}

func parseSNI(data []byte) string {
	// server_name_list length(2), then entries: type(1), name_len(2), name.
	if len(data) < 2 {
		return ""
	}
	list := data[2:]
	for len(list) >= 3 {
		nlen := int(list[1])<<8 | int(list[2])
		if list[0] == 0x00 && len(list) >= 3+nlen {
			return string(list[3 : 3+nlen])
		}
		if len(list) < 3+nlen {
			break
		}
		list = list[3+nlen:]
	}
	return ""
}

func parseFirstALPN(data []byte) string {
	if len(data) < 3 {
		return ""
	}
	list := data[2:] // skip alpn_list_len(2)
	if len(list) < 1 {
		return ""
	}
	l := int(list[0])
	if len(list) < 1+l {
		return ""
	}
	return string(list[1 : 1+l])
}

func parseUint16List(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	l := int(data[0])<<8 | int(data[1])
	body := data[2:]
	if len(body) < l {
		return nil
	}
	var out []uint16
	for i := 0; i+1 < l; i += 2 {
		out = append(out, uint16(body[i])<<8|uint16(body[i+1]))
	}
	return out
}

func parseSupportedVersionsMax(data []byte) uint16 {
	if len(data) < 1 {
		return 0
	}
	l := int(data[0])
	body := data[1:]
	if len(body) < l {
		return 0
	}
	var maxv uint16
	for i := 0; i+1 < l; i += 2 {
		v := uint16(body[i])<<8 | uint16(body[i+1])
		if isGREASE(v) {
			continue
		}
		if v > maxv {
			maxv = v
		}
	}
	return maxv
}

func pickVersion(legacy, supported uint16) uint16 {
	if supported != 0 {
		return supported
	}
	return legacy
}

func versionString(v uint16) string {
	switch v {
	case 0x0304:
		return "1.3"
	case 0x0303:
		return "1.2"
	case 0x0302:
		return "1.1"
	case 0x0301:
		return "1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// computeJA4 builds a JA4-style fingerprint. Ciphers and extensions are SORTED before hashing (the
// property that makes JA4 stable under Chrome's extension-order randomization). SNI(0) and ALPN(16)
// are excluded from the sorted extension list per the JA4 spec.
func computeJA4(info ClientHelloInfo, ciphers, extIDs, sigAlgs []uint16) string {
	ver := "13"
	switch info.TLSVersion {
	case "1.2":
		ver = "12"
	case "1.1":
		ver = "11"
	case "1.0":
		ver = "10"
	}
	sniFlag := "i"
	if info.SNI != "" {
		sniFlag = "d"
	}
	// Per the JA4 spec, the ALPN component is the FIRST and LAST ASCII-alphanumeric characters of the
	// first ALPN value ("http/1.1" → "h1"); when either edge byte is non-alphanumeric, the first and
	// last characters of the hex representation are used instead; no ALPN → "00".
	alpn := "00"
	if info.ALPN != "" {
		first, last := info.ALPN[0], info.ALPN[len(info.ALPN)-1]
		if isAlnum(first) && isAlnum(last) {
			alpn = string(first) + string(last)
		} else {
			h := hex.EncodeToString([]byte(info.ALPN))
			alpn = string(h[0]) + string(h[len(h)-1])
		}
	}
	// JA4 counts are capped at 99.
	a := fmt.Sprintf("t%s%s%02d%02d%s", ver, sniFlag, min(len(ciphers), 99), minExt(extIDs), alpn)

	sortedC := sortedHex(ciphers)
	b := sha12(strings.Join(sortedC, ","))

	// Extension list for the hash EXCLUDES SNI(0) and ALPN(16); sig algs appended (unsorted) after '_'.
	var filtered []uint16
	for _, e := range extIDs {
		if e == 0x0000 || e == 0x0010 {
			continue
		}
		filtered = append(filtered, e)
	}
	sortedE := sortedHex(filtered)
	extPart := strings.Join(sortedE, ",")
	if len(sigAlgs) > 0 {
		extPart += "_" + strings.Join(hexList(sigAlgs), ",")
	}
	c := sha12(extPart)

	return a + "_" + b + "_" + c
}

func minExt(ext []uint16) int {
	// Extension count in the JA4_a part includes SNI/ALPN (they are only excluded from the hash).
	return min(len(ext), 99)
}

func sortedHex(vs []uint16) []string {
	out := hexList(vs)
	sort.Strings(out)
	return out
}

func hexList(vs []uint16) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = fmt.Sprintf("%04x", v)
	}
	return out
}

func sha12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
