package smtp

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// xtextGrammar is RFC 4954 section 8 (and RFC 3461 section 4):
//
//	xtext   = *(xchar / hexchar)  ;; non-US-ASCII is only allowed as hexchar
//	xchar   = %x21-2A / %x2C-3C / %x3E-7E
//	hexchar = "+" HEXDIG HEXDIG
//
// RFC 4954 section 8 makes HEXDIG case-insensitive, so a decoder accepts
// lower-case hex digits.
var xtextGrammar = regexp.MustCompile(`^(?:[\x21-\x2A\x2C-\x3C\x3E-\x7E]|\+[0-9A-Fa-f]{2})*$`)

// canonicalXtextGrammar is what an encoder emits: RFC 3461 section 4 writes
// hexchar with "two upper case hexadecimal digits".
var canonicalXtextGrammar = regexp.MustCompile(`^(?:[\x21-\x2A\x2C-\x3C\x3E-\x7E]|\+[0-9A-F]{2})*$`)

// hexcharRe finds each hexchar in a string that already matches xtextGrammar.
var hexcharRe = regexp.MustCompile(`\+[0-9A-Fa-f]{2}`)

// referenceDecodeXtext decodes val by the grammar alone, independently of
// decodeXtext: it reports false when val is not an xtext.
func referenceDecodeXtext(val string) (string, bool) {
	if !xtextGrammar.MatchString(val) {
		return "", false
	}
	return hexcharRe.ReplaceAllStringFunc(val, func(h string) string {
		b, err := hex.DecodeString(h[1:])
		if err != nil {
			panic(err)
		}
		return string(b)
	}), true
}

// referenceEncodeXtext encodes every octet independently of encodeXtext: an
// xchar as itself, any other octet as "+" and two upper-case hex digits.
func referenceEncodeXtext(raw string) string {
	var sb strings.Builder
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if strings.IndexByte("+=", b) < 0 && b >= 0x21 && b <= 0x7E {
			sb.WriteByte(b)
		} else {
			fmt.Fprintf(&sb, "+%02X", b)
		}
	}
	return sb.String()
}

func allOctets() string {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return string(b)
}

// checklist: SMTP-EXT-04
func FuzzDecodeXtext(f *testing.F) {
	for _, seed := range []string{
		"", "a", "e+3Dmc2", "hey+3Da@example.com", "+2B", "+2b", "+00+ff+FF+80",
		"+41+42", "<>", "+3C+3E", "+", "+A", "+AG", "+G0", "a+", "a+2", "++2B",
		// Literal octets outside xchar. decodeXtext used to accept each of
		// these as itself.
		"a=b", "e=mc2@example.com", "a b", "\t", "\x00", "a\x7f", "\xff",
		"élisa@example.org", "=", "+3D=",
		referenceEncodeXtext(allOctets()), strings.ToLower(referenceEncodeXtext(allOctets())),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, val string) {
		if len(val) > maxParserFuzzInput {
			t.Skip()
		}
		got, err := decodeXtext(val)
		want, ok := referenceDecodeXtext(val)
		if !ok {
			if err == nil {
				t.Fatalf("decodeXtext(%q) = %q, want an error: not an xtext", val, got)
			}
			return
		}
		if err != nil {
			t.Fatalf("decodeXtext(%q) error %v on a valid xtext", val, err)
		}
		if got != want {
			t.Fatalf("decodeXtext(%q) = %q, want %q", val, got, want)
		}
		// Each hexchar is three wire bytes for one octet; an xchar is one.
		if n := strings.Count(val, "+"); len(got) != len(val)-2*n {
			t.Fatalf("decodeXtext(%q) = %d octets, want %d", val, len(got), len(val)-2*n)
		}
		// Re-encoding gives the canonical spelling of the same octets.
		enc := encodeXtext(got)
		if enc != referenceEncodeXtext(got) {
			t.Fatalf("encodeXtext(%q) = %q, want %q", got, enc, referenceEncodeXtext(got))
		}
		if again, err := decodeXtext(enc); err != nil || again != got {
			t.Fatalf("decodeXtext(encodeXtext(%q)) = (%q, %v)", got, again, err)
		}
	})
}

// checklist: SMTP-EXT-04
func FuzzEncodeXtext(f *testing.F) {
	for _, seed := range []string{
		"", "a", "e=mc2", "hey=a@example.com", "+", "=", "+=", " ", "\x00", "\x7f",
		"\x80", "\xff", "élisa@example.org", "\xc3", "<>", "a b\tc\r\n", allOctets(),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > maxParserFuzzInput {
			t.Skip()
		}
		enc := encodeXtext(raw)
		if !canonicalXtextGrammar.MatchString(enc) {
			t.Fatalf("encodeXtext(%q) = %q, not an RFC 3461 xtext", raw, enc)
		}
		if want := referenceEncodeXtext(raw); enc != want {
			t.Fatalf("encodeXtext(%q) = %q, want %q", raw, enc, want)
		}
		dec, ok := referenceDecodeXtext(enc)
		if !ok || dec != raw {
			t.Fatalf("grammar decodes encodeXtext(%q) = %q to (%q, %v)", raw, enc, dec, ok)
		}
		if got, err := decodeXtext(enc); err != nil || got != raw {
			t.Fatalf("decodeXtext(encodeXtext(%q)) = (%q, %v)", raw, got, err)
		}
	})
}

// xclientValueGrammar is xtext as Postfix decodes XCLIENT values: a '+' must
// start a hexchar; every other octet stands for itself.
var xclientValueGrammar = regexp.MustCompile(`^(?:[^+]|\+[0-9A-Fa-f]{2})*$`)

// checklist: XC-SYNTAX-03
func FuzzDecodeXClientValue(f *testing.F) {
	for _, seed := range []string{
		"", "alice", "user+2Btag+3Dx@example.com", "IPV6+3A2001:db8::1", "+c3+a9",
		"+", "+A", "+AG", "+G0", "a+", "a+2", "++2B", "user+tag@example.com",
		"client\u0085example", "alice ", "a=b", "\x00", "\xff",
		referenceEncodeXtext(allOctets()), strings.ToLower(referenceEncodeXtext(allOctets())),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, val string) {
		if len(val) > maxParserFuzzInput {
			t.Skip()
		}
		got, ok := decodeXClientValue(val)
		if ok != xclientValueGrammar.MatchString(val) {
			t.Fatalf("decodeXClientValue(%q) ok = %v, want %v", val, ok, !ok)
		}
		if !ok {
			return
		}
		want := hexcharRe.ReplaceAllStringFunc(val, func(h string) string {
			b, err := hex.DecodeString(h[1:])
			if err != nil {
				panic(err)
			}
			return string(b)
		})
		if got != want {
			t.Fatalf("decodeXClientValue(%q) = %q, want %q", val, got, want)
		}
		// A valid xtext decodes exactly as the strict RFC 3461 decoder does.
		if strict, err := decodeXtext(val); err == nil && strict != got {
			t.Fatalf("decodeXClientValue(%q) = %q, decodeXtext = %q", val, got, strict)
		}
		// What a proxy encodes comes back unchanged.
		if again, ok := decodeXClientValue(referenceEncodeXtext(val)); !ok || again != val {
			t.Fatalf("decodeXClientValue(encode(%q)) = (%q, %v)", val, again, ok)
		}
	})
}
