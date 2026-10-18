package smtp

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// The oracle below is RFC 6533 section 3, written out independently of
// decodeUTF8AddrXtext, encodeUTF8AddrXtext and encodeUTF8AddrUnitext:
//
//	utf-8-addr-xtext    = 1*(QCHAR / EmbeddedUnicodeChar)
//	utf-8-addr-unitext  = 1*(QUCHAR / EmbeddedUnicodeChar)
//	QCHAR               = %x21-2a / %x2c-3c / %x3e-5b / %x5d-7e
//	QUCHAR              = QCHAR / UTF8-2 / UTF8-3 / UTF8-4
//	EmbeddedUnicodeChar = %x5C.78 "{" HEXPOINT "}"
//
// UTF8-2, UTF8-3 and UTF8-4 are RFC 3629 section 4. The decoder accepts
// either form, so it is checked against utf-8-addr-unitext; the "1*" is
// enforced by decodeTypedAddress, which refuses an empty address.

// hexpointGrammar is HEXPOINT. ABNF quoted strings, HEXDIG included, are
// case-insensitive (RFC 5234 section 2.3); "\x" is %x5C.78 and is not. The
// 6-digit form is written "10" 4*HEXDIG, but HEXPOINT "is 2 to 6 hexadecimal
// digits", so it is "10" and exactly four more.
var hexpointGrammar = regexp.MustCompile(`^(?i:` +
	`[01][1-9]|10|20|2B|3D|7F|` + // all xtext-specials
	`5C|[89A-F][0-9A-F]|` + // 2-digit forms
	`[1-9A-F][0-9A-F]{2}|` + // 3-digit forms
	`[1-9A-CE-F][0-9A-F]{3}|` + // 4-digit forms excluding
	`D[0-7][0-9A-F]{2}|` + // ... surrogate
	`[1-9A-F][0-9A-F]{4}|` + // 5-digit forms
	`10[0-9A-F]{4}` + // 6-digit forms
	`)$`)

func refQchar(b byte) bool {
	return b >= 0x21 && b <= 0x2A || b >= 0x2C && b <= 0x3C ||
		b >= 0x3E && b <= 0x5B || b >= 0x5D && b <= 0x7E
}

// refUTF8Char returns the length of the UTF8-2, UTF8-3 or UTF8-4 that s
// starts with, or 0. It is the RFC 3629 section 4 byte table, not utf8.
func refUTF8Char(s string) int {
	in := func(i int, lo, hi byte) bool { return i < len(s) && s[i] >= lo && s[i] <= hi }
	tail := func(i int) bool { return in(i, 0x80, 0xBF) }
	switch {
	case in(0, 0xC2, 0xDF) && tail(1):
		return 2
	case in(0, 0xE0, 0xE0) && in(1, 0xA0, 0xBF) && tail(2),
		in(0, 0xE1, 0xEC) && tail(1) && tail(2),
		in(0, 0xED, 0xED) && in(1, 0x80, 0x9F) && tail(2),
		in(0, 0xEE, 0xEF) && tail(1) && tail(2):
		return 3
	case in(0, 0xF0, 0xF0) && in(1, 0x90, 0xBF) && tail(2) && tail(3),
		in(0, 0xF1, 0xF3) && tail(1) && tail(2) && tail(3),
		in(0, 0xF4, 0xF4) && in(1, 0x80, 0x8F) && tail(2) && tail(3):
		return 4
	}
	return 0
}

// refUTF8 encodes a code point by the RFC 3629 section 3 bit layout.
func refUTF8(cp uint64) string {
	switch {
	case cp < 0x80:
		return string([]byte{byte(cp)})
	case cp < 0x800:
		return string([]byte{0xC0 | byte(cp>>6), 0x80 | byte(cp&0x3F)})
	case cp < 0x10000:
		return string([]byte{0xE0 | byte(cp>>12), 0x80 | byte(cp>>6&0x3F), 0x80 | byte(cp&0x3F)})
	}
	return string([]byte{0xF0 | byte(cp>>18), 0x80 | byte(cp>>12&0x3F), 0x80 | byte(cp>>6&0x3F), 0x80 | byte(cp&0x3F)})
}

// refCodePoint decodes one UTF8-2, UTF8-3 or UTF8-4 sequence.
func refCodePoint(seq string) uint64 {
	cp := uint64(seq[0]) & (0x7F >> len(seq))
	for i := 1; i < len(seq); i++ {
		cp = cp<<6 | uint64(seq[i]&0x3F)
	}
	return cp
}

// referenceDecodeUTF8Addr decodes *(QCHAR / EmbeddedUnicodeChar), or with
// unitext *(QUCHAR / EmbeddedUnicodeChar), by the grammar alone. It reports
// false when val is not in that language.
func referenceDecodeUTF8Addr(val string, unitext bool) (string, bool) {
	var sb strings.Builder
	for i := 0; i < len(val); {
		if refQchar(val[i]) {
			sb.WriteByte(val[i])
			i++
			continue
		}
		if strings.HasPrefix(val[i:], `\x{`) {
			end := strings.IndexByte(val[i+3:], '}')
			if end < 0 {
				return "", false
			}
			hexpoint := val[i+3 : i+3+end]
			if !hexpointGrammar.MatchString(hexpoint) {
				return "", false
			}
			cp, err := strconv.ParseUint(hexpoint, 16, 32)
			if err != nil {
				panic(err)
			}
			sb.WriteString(refUTF8(cp))
			i += 3 + end + 1
			continue
		}
		if n := refUTF8Char(val[i:]); unitext && n > 0 {
			sb.WriteString(val[i : i+n])
			i += n
			continue
		}
		return "", false
	}
	return sb.String(), true
}

// referenceEncodeUTF8Addr is the canonical encoding of raw: a QCHAR as
// itself, non-ASCII as itself in unitext, and anything else as an
// EmbeddedUnicodeChar with the shortest upper-case HEXPOINT. It reports false
// when raw is not UTF-8 or holds a character HEXPOINT cannot express.
func referenceEncodeUTF8Addr(raw string, unitext bool) (string, bool) {
	var sb strings.Builder
	for i := 0; i < len(raw); {
		var cp uint64
		n := 1
		switch {
		case refQchar(raw[i]):
			sb.WriteByte(raw[i])
			i++
			continue
		case raw[i] < 0x80:
			cp = uint64(raw[i])
		default:
			if n = refUTF8Char(raw[i:]); n == 0 {
				return "", false
			}
			if unitext {
				sb.WriteString(raw[i : i+n])
				i += n
				continue
			}
			cp = refCodePoint(raw[i : i+n])
		}
		hexpoint := strconv.FormatUint(cp, 16)
		if len(hexpoint) < 2 {
			hexpoint = "0" + hexpoint
		}
		hexpoint = strings.ToUpper(hexpoint)
		if !hexpointGrammar.MatchString(hexpoint) {
			return "", false
		}
		sb.WriteString(`\x{` + hexpoint + `}`)
		i += n
	}
	return sb.String(), true
}

// checkUTF8AddrDecode holds decode to the grammar for one input.
func checkUTF8AddrDecode(decode func(string) (string, error), val string) error {
	got, err := decode(val)
	want, ok := referenceDecodeUTF8Addr(val, true)
	if !ok {
		if err == nil {
			return fmt.Errorf("decode(%q) = %q, want an error: not RFC 6533 unitext", val, got)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("decode(%q) error %v on a valid RFC 6533 address", val, err)
	}
	if got != want {
		return fmt.Errorf("decode(%q) = %q, want %q", val, got, want)
	}
	if !utf8.ValidString(got) {
		return fmt.Errorf("decode(%q) = %q, not UTF-8", val, got)
	}
	return nil
}

// checkUTF8AddrEncode holds encode to the grammar and its canonical form.
func checkUTF8AddrEncode(encode func(string) (string, error), raw string, unitext bool) error {
	enc, err := encode(raw)
	want, ok := referenceEncodeUTF8Addr(raw, unitext)
	if !ok {
		if err == nil {
			return fmt.Errorf("encode(%q) = %q, want an error: no RFC 6533 encoding", raw, enc)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("encode(%q) error %v, want %q", raw, err, want)
	}
	if enc != want {
		return fmt.Errorf("encode(%q) = %q, want %q", raw, enc, want)
	}
	dec, ok := referenceDecodeUTF8Addr(enc, unitext)
	if !ok || dec != raw {
		return fmt.Errorf("grammar decodes encode(%q) = %q to (%q, %v)", raw, enc, dec, ok)
	}
	if raw != "" && enc == "" {
		return fmt.Errorf("encode(%q) is empty", raw)
	}
	return nil
}

func encodeUTF8AddrXtextChecked(raw string) error {
	return checkUTF8AddrEncode(encodeUTF8AddrXtext, raw, false)
}

func encodeUTF8AddrUnitextChecked(raw string) error {
	return checkUTF8AddrEncode(encodeUTF8AddrUnitext, raw, true)
}

// utf8AddrDecodeSeeds holds the RFC 6533 examples and each HEXPOINT,
// QCHAR and RFC 3629 boundary.
var utf8AddrDecodeSeeds = []string{
	"", "a", `e\x{3D}mc2@example.com`, `e\x{3D}mc2@ドメイン名例.jp`,
	`e\x{3D}mc2@\x{30C9}\x{30E1}\x{30A4}\x{30F3}\x{540D}\x{4F8B}.jp`,
	`\x{01}`, `\x{09}`, `\x{10}`, `\x{11}`, `\x{19}`, `\x{20}`, `\x{2B}`, `\x{3D}`,
	`\x{5C}`, `\x{7F}`, `\x{80}`, `\x{FF}`, `\x{100}`, `\x{FFF}`, `\x{1000}`,
	`\x{D7FF}`, `\x{E000}`, `\x{FFFF}`, `\x{10000}`, `\x{FFFFF}`, `\x{100000}`,
	`\x{10FFFF}`, `\x{e9}`, `\x{2b}`, `\x{d7ff}`, `\x{10ffff}`,
	// HEXPOINT has no form for these.
	`\x{00}`, `\x{0A}`, `\x{0D}`, `\x{0F}`, `\x{1A}`, `\x{1F}`, `\x{21}`, `\x{41}`,
	`\x{7E}`, `\x{0}`, `\x{1}`, `\x{A}`, `\x{0E9}`, `\x{00E9}`, `\x{0100}`,
	`\x{D800}`, `\x{DFFF}`, `\x{d800}`, `\x{0FFFF}`, `\x{110000}`, `\x{1000000}`,
	`\x{FFFFFFFFFFFFFFFFFFFF}`, `\x{}`, `\x{`, `\x{E9`, `\x`, `\`, `\X{E9}`,
	`\x(E9)`, `\x{G0}`, `\x{+E9}`, `\x{ E9}`, `\\x{E9}`,
	"a b", "a+b", "a=b", "a\\b", "\x00", "\t", "\r\n", "\x7f", "a@b c",
	// Literal UTF-8 boundaries, then malformed UTF-8: a stray tail,
	// overlong forms, surrogates, past U+10FFFF and truncated sequences.
	"\u0080", "߿", "ࠀ", "퟿", "", "￿", "\U00010000",
	"\U0010ffff", "élisa@example.org",
	"\x80", "\xbf", "\xc0\xaf", "\xc1\xbf", "\xe0\x80\xaf", "\xe0\x9f\xbf",
	"\xed\xa0\x80", "\xed\xbf\xbf", "\xf0\x80\x80\xaf", "\xf0\x8f\xbf\xbf",
	"\xf4\x90\x80\x80", "\xf5\x80\x80\x80", "\xff", "\xc3", "\xe3\x83", "a\xc3",
}

// utf8AddrEncodeSeeds holds every character class an encoder must place.
var utf8AddrEncodeSeeds = []string{
	"", "a", "e=mc2@example.com", "e=mc2@ドメイン名例.jp", `"a\b"@example.com`,
	`\`, "+", "=", " ", "\x01", "\x09", "\x10", "\x19", "\x20", "\x7f", "~!",
	"\x00", "\n", "\r", "\x0f", "\x1a", "\x1f", "a\r\nb",
	"é", "\u0080", "ÿ", "Ā", "࿿", "က", "퟿", "",
	"￿", "\U00010000", "\U000fffff", "\U00100000", "\U0010ffff",
	"\xff", "\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80", "a\xc3",
	string(utf8.RuneError),
}

func FuzzDecodeUTF8AddrXtext(f *testing.F) {
	for _, seed := range utf8AddrDecodeSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, val string) {
		if len(val) > maxParserFuzzInput {
			t.Skip()
		}
		if err := checkUTF8AddrDecode(decodeUTF8AddrXtext, val); err != nil {
			t.Fatal(err)
		}
		got, err := decodeUTF8AddrXtext(val)
		if err != nil {
			return
		}
		// The ORCPT parameter takes the same address behind "utf-8;", in
		// any case, and refuses an empty one (RFC 6533 "1*").
		aType, aAddr, terr := decodeTypedAddress("uTF-8;" + val)
		if val == "" {
			if terr == nil {
				t.Fatalf("decodeTypedAddress accepts an empty utf-8 address as %q", aAddr)
			}
			return
		}
		if terr != nil || aType != DSNAddressTypeUTF8 || aAddr != got {
			t.Fatalf("decodeTypedAddress(utf-8;%q) = (%q, %q, %v), want %q", val, aType, aAddr, terr, got)
		}
		// What decodes re-encodes, canonically, in both forms.
		if err := encodeUTF8AddrXtextChecked(got); err != nil {
			t.Fatal(err)
		}
		if err := encodeUTF8AddrUnitextChecked(got); err != nil {
			t.Fatal(err)
		}
	})
}

func FuzzEncodeUTF8AddrXtext(f *testing.F) {
	for _, seed := range utf8AddrEncodeSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > maxParserFuzzInput {
			t.Skip()
		}
		if err := encodeUTF8AddrXtextChecked(raw); err != nil {
			t.Fatal(err)
		}
		enc, err := encodeUTF8AddrXtext(raw)
		if err != nil {
			return
		}
		for i := 0; i < len(enc); i++ {
			if enc[i] >= utf8.RuneSelf {
				t.Fatalf("encodeUTF8AddrXtext(%q) = %q, not 7-bit", raw, enc)
			}
		}
		if got, err := decodeUTF8AddrXtext(enc); err != nil || got != raw {
			t.Fatalf("decodeUTF8AddrXtext(%q) = (%q, %v), want %q", enc, got, err, raw)
		}
	})
}

func FuzzEncodeUTF8AddrUnitext(f *testing.F) {
	for _, seed := range utf8AddrEncodeSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > maxParserFuzzInput {
			t.Skip()
		}
		if err := encodeUTF8AddrUnitextChecked(raw); err != nil {
			t.Fatal(err)
		}
		enc, err := encodeUTF8AddrUnitext(raw)
		if err != nil {
			return
		}
		if got, err := decodeUTF8AddrXtext(enc); err != nil || got != raw {
			t.Fatalf("decodeUTF8AddrXtext(%q) = (%q, %v), want %q", enc, got, err, raw)
		}
	})
}

// Each mutant is a plausible weakening of the decoder or an encoder; the
// oracle must catch every one of them on the seed corpus alone. The first
// encoder mutants are the encoders as they were before RFC 6533 checking.
func TestUTF8AddrOracleCatchesMutants(t *testing.T) {
	legacyEncode := func(raw string, unitext bool) (string, error) {
		var out strings.Builder
		for _, ch := range raw {
			switch {
			case ch >= '!' && ch <= '~' && ch != '+' && ch != '=':
				out.WriteRune(ch)
			case unitext && ch > '\x7F':
				out.WriteRune(ch)
			default:
				out.WriteString(`\x{` + strings.ToUpper(strconv.FormatInt(int64(ch), 16)) + `}`)
			}
		}
		return out.String(), nil
	}
	decoders := map[string]func(string) (string, error){
		"accepts malformed UTF-8": func(val string) (string, error) {
			if !utf8.ValidString(val) {
				return val, nil
			}
			return decodeUTF8AddrXtext(val)
		},
		"refuses lower-case HEXDIG": func(val string) (string, error) {
			if regexp.MustCompile(`\\x\{[^}]*[a-f]`).MatchString(val) {
				return "", errors.New("lower case")
			}
			return decodeUTF8AddrXtext(val)
		},
		"accepts a leading zero": func(val string) (string, error) {
			return decodeUTF8AddrXtext(strings.ReplaceAll(val, `\x{0E9}`, `\x{E9}`))
		},
		"accepts a surrogate": func(val string) (string, error) {
			if val == `\x{D800}` {
				return "�", nil
			}
			return decodeUTF8AddrXtext(val)
		},
		"decodes an escaped QCHAR": func(val string) (string, error) {
			return decodeUTF8AddrXtext(strings.ReplaceAll(val, `\x{41}`, "A"))
		},
		"accepts a literal backslash": func(val string) (string, error) {
			return decodeUTF8AddrXtext(strings.ReplaceAll(val, `a\b`, `a\x{5C}b`))
		},
		"leaves escapes undecoded": func(val string) (string, error) {
			if _, err := decodeUTF8AddrXtext(val); err != nil {
				return "", err
			}
			return val, nil
		},
	}
	for name, decode := range decoders {
		caught := false
		for _, seed := range utf8AddrDecodeSeeds {
			if checkUTF8AddrDecode(decode, seed) != nil {
				caught = true
				break
			}
		}
		if !caught {
			t.Errorf("decoder mutant %q passes the oracle", name)
		}
	}

	encoders := map[string]struct {
		encode  func(string) (string, error)
		unitext bool
	}{
		"legacy xtext":   {func(raw string) (string, error) { return legacyEncode(raw, false) }, false},
		"legacy unitext": {func(raw string) (string, error) { return legacyEncode(raw, true) }, true},
		"lower-case HEXPOINT": {func(raw string) (string, error) {
			enc, err := encodeUTF8AddrXtext(raw)
			return strings.ToLower(enc), err
		}, false},
		"escapes unitext non-ASCII":  {encodeUTF8AddrXtext, true},
		"literal non-ASCII in xtext": {encodeUTF8AddrUnitext, false},
		"drops malformed UTF-8": {func(raw string) (string, error) {
			return encodeUTF8AddrXtext(strings.ToValidUTF8(raw, ""))
		}, false},
		"pads HEXPOINT": {func(raw string) (string, error) {
			enc, err := encodeUTF8AddrXtext(raw)
			return strings.ReplaceAll(enc, `\x{E9}`, `\x{0E9}`), err
		}, false},
	}
	for name, m := range encoders {
		caught := false
		for _, seed := range utf8AddrEncodeSeeds {
			if checkUTF8AddrEncode(m.encode, seed, m.unitext) != nil {
				caught = true
				break
			}
		}
		if !caught {
			t.Errorf("encoder mutant %q passes the oracle", name)
		}
	}
}

// Minimized cases from the oracle, each a defect before RFC 6533 checking.
func TestUTF8AddrRFC6533Regressions(t *testing.T) {
	for _, val := range []string{"\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\x80", "a\xc3"} {
		if got, err := decodeUTF8AddrXtext(val); err == nil {
			t.Errorf("decodeUTF8AddrXtext(%q) = %q, want an error: not UTF-8", val, got)
		}
	}
	for val, want := range map[string]string{`\x{e9}`: "é", `\x{d7ff}`: "퟿", `a\x{2b}b`: "a+b"} {
		if got, err := decodeUTF8AddrXtext(val); err != nil || got != want {
			t.Errorf("decodeUTF8AddrXtext(%q) = (%q, %v), want %q", val, got, err, want)
		}
	}
	for _, tc := range []struct{ raw, xtext, unitext string }{
		{`"a\b"@example.com`, `"a\x{5C}b"@example.com`, `"a\x{5C}b"@example.com`},
		{"\x01é", `\x{01}\x{E9}`, `\x{01}é`},
	} {
		if got, err := encodeUTF8AddrXtext(tc.raw); err != nil || got != tc.xtext {
			t.Errorf("encodeUTF8AddrXtext(%q) = (%q, %v), want %q", tc.raw, got, err, tc.xtext)
		}
		if got, err := encodeUTF8AddrUnitext(tc.raw); err != nil || got != tc.unitext {
			t.Errorf("encodeUTF8AddrUnitext(%q) = (%q, %v), want %q", tc.raw, got, err, tc.unitext)
		}
	}
	for _, raw := range []string{"\x00", "a\nb", "\x0f", "\x1f", "\xff"} {
		if got, err := encodeUTF8AddrXtext(raw); err == nil {
			t.Errorf("encodeUTF8AddrXtext(%q) = %q, want an error", raw, got)
		}
		if got, err := encodeUTF8AddrUnitext(raw); err == nil {
			t.Errorf("encodeUTF8AddrUnitext(%q) = %q, want an error", raw, got)
		}
	}
}

// The client puts the fixed encodings on the wire and refuses an
// original recipient that has no RFC 6533 encoding.
func TestClientORCPTUTF8Encoding(t *testing.T) {
	c := &Client{ext: map[string]string{"DSN": ""}}
	opts := &RcptOptions{OriginalRecipientType: DSNAddressTypeUTF8, OriginalRecipient: `"a\b"@example.com`}
	want := `RCPT TO:<x@example.com> ORCPT=UTF-8;"a\x{5C}b"@example.com`
	if got, err := c.buildRcptCmd("x@example.com", opts); err != nil || got != want {
		t.Errorf("buildRcptCmd = (%q, %v), want %q", got, err, want)
	}
	c.ext["SMTPUTF8"] = ""
	if got, err := c.buildRcptCmd("x@example.com", opts); err != nil || got != want {
		t.Errorf("buildRcptCmd with SMTPUTF8 = (%q, %v), want %q", got, err, want)
	}
	for _, orcpt := range []string{"a\x00b@example.com", "a\xffb@example.com"} {
		opts.OriginalRecipient = orcpt
		if got, err := c.buildRcptCmd("x@example.com", opts); err == nil {
			t.Errorf("buildRcptCmd with ORCPT %q = %q, want an error", orcpt, got)
		}
	}
}
