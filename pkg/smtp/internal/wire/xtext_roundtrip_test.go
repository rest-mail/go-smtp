package wire

import "testing"

// TestXtextRoundTrip verifies that EncodeXtext/DecodeXtext round-trip every
// octet value, including 0x80-0xFF which the previous decoder (ParseInt with
// bitSize 8) could not represent.
//
// checklist: SMTP-EXT-04
func TestXtextRoundTrip(t *testing.T) {
	for i := 0; i < 256; i++ {
		raw := string([]byte{byte(i)})
		enc := EncodeXtext(raw)
		dec, err := DecodeXtext(enc)
		if err != nil {
			t.Fatalf("byte %#02x: DecodeXtext(%q) error: %v", i, enc, err)
		}
		if dec != raw {
			t.Fatalf("byte %#02x: round-trip = %q (encoded %q), want %q", i, dec, enc, raw)
		}
	}
}
