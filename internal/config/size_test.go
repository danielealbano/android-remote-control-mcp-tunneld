package config

import "testing"

func TestParseByteSizeValidUnitsBinary(t *testing.T) {
	t.Parallel()
	cases := map[string]int64{
		"1mb":  1048576,
		"10mb": 10485760,
		"16kb": 16384,
		"8kb":  8192,
		"1gb":  1073741824,
		"512b": 512,
		"1024": 1024, // bare number = bytes
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			got, err := ParseByteSize(in)
			if err != nil {
				t.Fatalf("ParseByteSize(%q) unexpected error: %v", in, err)
			}
			if got != want {
				t.Errorf("ParseByteSize(%q) = %d, want %d", in, got, want)
			}
		})
	}
}

func TestParseByteSizeRejectsMalformed(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"", "  ", "abc", "1tb", "10mib", "-5mb", "mb", "1.5mb"} {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseByteSize(in); err == nil {
				t.Errorf("ParseByteSize(%q) expected error, got nil", in)
			}
		})
	}
}

func TestParseBitrateBitsNotBytesDecimal(t *testing.T) {
	t.Parallel()
	cases := map[string]int64{
		"1mbit":   125000, // 1e6 bits / 8
		"256kbit": 32000,  // 256e3 / 8
		"300kbit": 37500,
		"128kbit": 16000,
		"8bit":    1,
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			got, err := ParseBitrate(in)
			if err != nil {
				t.Fatalf("ParseBitrate(%q) unexpected error: %v", in, err)
			}
			if got != want {
				t.Errorf("ParseBitrate(%q) = %d bytes/s, want %d", in, got, want)
			}
		})
	}
}

func TestParseBitrateRejectsMalformed(t *testing.T) {
	t.Parallel()
	// A bare number (no bit suffix) and byte-size suffixes must be rejected — bitrate needs bits.
	for _, in := range []string{"", "1mb", "1000", "abc", "-1mbit", "mbit"} {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseBitrate(in); err == nil {
				t.Errorf("ParseBitrate(%q) expected error, got nil", in)
			}
		})
	}
}
