package edge

import (
	"encoding/binary"
	"testing"
)

// buildClientHello assembles a minimal TLS ClientHello record with the given SNI, ciphers, ALPN, and
// extensions in the given order (each extension: id + raw data).
func buildClientHello(sni string, ciphers []uint16, exts []extension) []byte {
	var body []byte
	body = append(body, 0x03, 0x03)          // legacy_version 1.2
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id len 0
	cs := make([]byte, 2+len(ciphers)*2)     // cipher suites
	binary.BigEndian.PutUint16(cs[0:2], uint16(len(ciphers)*2))
	for i, c := range ciphers {
		binary.BigEndian.PutUint16(cs[2+i*2:], c)
	}
	body = append(body, cs...)
	body = append(body, 0x01, 0x00) // compression: 1 method, null

	var extBytes []byte
	for _, e := range exts {
		var eb [4]byte
		binary.BigEndian.PutUint16(eb[0:2], e.id)
		binary.BigEndian.PutUint16(eb[2:4], uint16(len(e.data)))
		extBytes = append(extBytes, eb[:]...)
		extBytes = append(extBytes, e.data...)
	}
	var extLen [2]byte
	binary.BigEndian.PutUint16(extLen[:], uint16(len(extBytes)))
	body = append(body, extLen[:]...)
	body = append(body, extBytes...)

	// handshake header
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	// record header
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)
	return rec
}

type extension struct {
	id   uint16
	data []byte
}

func sniExt(host string) extension {
	name := []byte(host)
	data := make([]byte, 5+len(name))
	binary.BigEndian.PutUint16(data[0:2], uint16(3+len(name))) // server_name_list len
	data[2] = 0x00                                             // host_name type
	binary.BigEndian.PutUint16(data[3:5], uint16(len(name)))
	copy(data[5:], name)
	return extension{id: 0x0000, data: data}
}

func alpnExt(proto string) extension {
	p := []byte(proto)
	data := make([]byte, 3+len(p))
	binary.BigEndian.PutUint16(data[0:2], uint16(1+len(p)))
	data[2] = byte(len(p))
	copy(data[3:], p)
	return extension{id: 0x0010, data: data}
}

func supportedVersionsExt() extension {
	// list len 2, then 0x0304 (TLS 1.3)
	return extension{id: 0x002b, data: []byte{0x02, 0x03, 0x04}}
}

func TestParseSNIALPNVersion(t *testing.T) {
	rec := buildClientHello("k7m2x9qwp4.example.test",
		[]uint16{0x1301, 0x1302},
		[]extension{sniExt("k7m2x9qwp4.example.test"), alpnExt("h2"), supportedVersionsExt(), {id: 0x000a, data: []byte{0, 2, 0, 23}}})
	info, err := parseClientHello(rec)
	if err != nil {
		t.Fatal(err)
	}
	if info.SNI != "k7m2x9qwp4.example.test" {
		t.Errorf("SNI = %q", info.SNI)
	}
	if info.ALPN != "h2" {
		t.Errorf("ALPN = %q", info.ALPN)
	}
	if info.TLSVersion != "1.3" {
		t.Errorf("version = %q", info.TLSVersion)
	}
	if info.JA4 == "" {
		t.Error("JA4 should be computed")
	}
}

func TestJA4StableUnderExtensionShuffle(t *testing.T) {
	ciphers := []uint16{0x1301, 0x1302, 0x1303}
	e1 := []extension{sniExt("x.example.test"), alpnExt("h2"), supportedVersionsExt(), {id: 0x000a, data: []byte{0, 2, 0, 23}}, {id: 0x000b, data: []byte{1, 0}}}
	// Same extensions, different ORDER.
	e2 := []extension{{id: 0x000b, data: []byte{1, 0}}, supportedVersionsExt(), sniExt("x.example.test"), {id: 0x000a, data: []byte{0, 2, 0, 23}}, alpnExt("h2")}

	i1, err := parseClientHello(buildClientHello("x.example.test", ciphers, e1))
	if err != nil {
		t.Fatal(err)
	}
	i2, err := parseClientHello(buildClientHello("x.example.test", ciphers, e2))
	if err != nil {
		t.Fatal(err)
	}
	if i1.JA4 != i2.JA4 {
		t.Errorf("JA4 must be stable under extension reordering:\n %s\n %s", i1.JA4, i2.JA4)
	}
}

func TestParseRejectsNonHandshake(t *testing.T) {
	if _, err := parseClientHello([]byte{0x17, 0x03, 0x03, 0, 1, 0}); err == nil {
		t.Error("non-handshake record should error")
	}
}
