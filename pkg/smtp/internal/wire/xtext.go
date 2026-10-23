package wire

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rest-mail/go-smtp/pkg/smtp"
)

func FromHexDigit(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	}
	return 0, false
}

// isXchar reports whether ch is an xchar (RFC 3461 section 4, RFC 4954 section
// 8): printable non-space US-ASCII except '+' and '='.
func isXchar(ch byte) bool {
	return ch >= '!' && ch <= '~' && ch != '+' && ch != '='
}

// DecodeXtext decodes the xtext form defined in RFC 3461 section 4 / RFC 4954
// section 8, where each octet outside the safe range is encoded as "+HH" with
// two hex digits. It operates on octets, so all byte values (including
// 0x80-0xFF) round-trip. Hex digits are accepted in either case (RFC 4954
// section 8), but any other octet must be an xchar: a literal space, control,
// '=' or non-ASCII byte is not xtext.
func DecodeXtext(val string) (string, error) {
	var out strings.Builder
	out.Grow(len(val))
	for i := 0; i < len(val); i++ {
		ch := val[i]
		if ch != '+' {
			if !isXchar(ch) {
				return "", errors.New("smtp: invalid xtext character")
			}
			out.WriteByte(ch)
			continue
		}
		if i+2 >= len(val) {
			return "", errors.New("smtp: incomplete xtext hexchar")
		}
		hi, ok1 := FromHexDigit(val[i+1])
		lo, ok2 := FromHexDigit(val[i+2])
		if !ok1 || !ok2 {
			return "", errors.New("smtp: invalid xtext hexchar")
		}
		out.WriteByte(hi<<4 | lo)
		i += 2
	}

	return out.String(), nil
}

// This regexp matches 'EmbeddedUnicodeChar' token defined in
// https://datatracker.ietf.org/doc/html/rfc6533.html#section-3
// however it is intentionally relaxed by requiring only '\x{HEX}' to be
// present.  It also matches disallowed characters in QCHAR and QUCHAR defined
// in above.
// So it allows us to detect malformed values and report them appropriately.
// HEXDIG is case-insensitive, like every ABNF quoted string (RFC 5234 section
// 2.3), so "\x{e9}" is as valid as "\x{E9}".
var eUOrDCharRe = regexp.MustCompile(`\\x[{][0-9A-Fa-f]+[}]|[[:cntrl:] \\+=]`)

// Decodes the utf-8-addr-xtext or the utf-8-addr-unitext form.
func DecodeUTF8AddrXtext(val string) (string, error) {
	// A literal non-ASCII QUCHAR is UTF8-2, UTF8-3 or UTF8-4 (RFC 3629
	// section 4): never an overlong form, a surrogate, a code point above
	// U+10FFFF or a stray octet.
	if !utf8.ValidString(val) {
		return "", errors.New("smtp: invalid UTF-8 in utf-8 address")
	}

	var replaceErr error
	decoded := eUOrDCharRe.ReplaceAllStringFunc(val, func(match string) string {
		if len(match) == 1 {
			replaceErr = errors.New("disallowed character:" + match)
			return ""
		}

		hexpoint := match[3 : len(match)-1]
		char, err := strconv.ParseUint(hexpoint, 16, 21)
		if err != nil {
			replaceErr = err
			return ""
		}
		switch len(hexpoint) {
		case 2:
			switch {
			// all xtext-specials
			case 0x01 <= char && char <= 0x09 ||
				0x11 <= char && char <= 0x19 ||
				char == 0x10 || char == 0x20 ||
				char == 0x2B || char == 0x3D || char == 0x7F:
			// 2-digit forms
			case char == 0x5C || 0x80 <= char && char <= 0xFF:
				// This space is intentionally left blank
			default:
				replaceErr = errors.New("illegal hexpoint:" + hexpoint)
				return ""
			}
		// 3-digit forms
		case 3:
			switch {
			case 0x100 <= char && char <= 0xFFF:
				// This space is intentionally left blank
			default:
				replaceErr = errors.New("illegal hexpoint:" + hexpoint)
				return ""
			}
		// 4-digit forms excluding surrogate
		case 4:
			switch {
			case 0x1000 <= char && char <= 0xD7FF:
			case 0xE000 <= char && char <= 0xFFFF:
				// This space is intentionally left blank
			default:
				replaceErr = errors.New("illegal hexpoint:" + hexpoint)
				return ""
			}
		// 5-digit forms
		case 5:
			switch {
			case 0x1_0000 <= char && char <= 0xF_FFFF:
				// This space is intentionally left blank
			default:
				replaceErr = errors.New("illegal hexpoint:" + hexpoint)
				return ""
			}
		// 6-digit forms
		case 6:
			switch {
			case 0x10_0000 <= char && char <= 0x10_FFFF:
				// This space is intentionally left blank
			default:
				replaceErr = errors.New("illegal hexpoint:" + hexpoint)
				return ""
			}
		// the other invalid forms
		default:
			replaceErr = errors.New("illegal hexpoint:" + hexpoint)
			return ""
		}

		return string(rune(char))
	})
	if replaceErr != nil {
		return "", replaceErr
	}

	return decoded, nil
}

func EncodeXtext(raw string) string {
	const hex = "0123456789ABCDEF"

	var out strings.Builder
	out.Grow(len(raw))

	// xtext is defined over octets, so iterate bytes and emit each unsafe octet
	// as "+HH" with two upper-case hex digits.
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if isXchar(ch) {
			out.WriteByte(ch)
		} else {
			out.WriteByte('+')
			out.WriteByte(hex[ch>>4])
			out.WriteByte(hex[ch&0x0F])
		}
	}
	return out.String()
}

// isQchar reports whether ch is a QCHAR (RFC 6533 section 3): printable
// non-space US-ASCII except '\', '+' and '='.
func isQchar(ch rune) bool {
	return ch < utf8.RuneSelf && isXchar(byte(ch)) && ch != '\\'
}

// writeEmbeddedUnicodeChar writes ch as an RFC 6533 EmbeddedUnicodeChar,
// "\x{HEXPOINT}" with upper-case digits. An ASCII HEXPOINT is always two
// digits, and HEXPOINT has no form at all for NUL, %x0A-0F or %x1A-1F, so
// those are refused.
func writeEmbeddedUnicodeChar(out *strings.Builder, ch rune) error {
	if ch < utf8.RuneSelf && (ch == 0 || ch&0x0F >= 0x0A && ch <= 0x1F) {
		return fmt.Errorf("smtp: %U cannot be encoded in a utf-8 address", ch)
	}
	fmt.Fprintf(out, "\\x{%02X}", ch)
	return nil
}

// Encodes raw string to the utf-8-addr-xtext form in RFC 6533.
func EncodeUTF8AddrXtext(raw string) (string, error) {
	if !utf8.ValidString(raw) {
		return "", errors.New("smtp: invalid UTF-8 in utf-8 address")
	}

	var out strings.Builder
	out.Grow(len(raw))

	for _, ch := range raw {
		if isQchar(ch) {
			out.WriteRune(ch)
		} else if err := writeEmbeddedUnicodeChar(&out, ch); err != nil {
			return "", err
		}
	}
	return out.String(), nil
}

// Encodes raw string to the utf-8-addr-unitext form in RFC 6533.
func EncodeUTF8AddrUnitext(raw string) (string, error) {
	if !utf8.ValidString(raw) {
		return "", errors.New("smtp: invalid UTF-8 in utf-8 address")
	}

	var out strings.Builder
	out.Grow(len(raw))

	for _, ch := range raw {
		switch {
		case isQchar(ch), ch >= utf8.RuneSelf:
			// QCHAR, or UTF-8 non-ASCII
			out.WriteRune(ch)
		default:
			// other ASCII: CTLs, space, '\', '+' and '='
			if err := writeEmbeddedUnicodeChar(&out, ch); err != nil {
				return "", err
			}
		}
	}
	return out.String(), nil
}

func IsPrintableASCII(val string) bool {
	for _, ch := range val {
		if ch < ' ' || '~' < ch {
			return false
		}
	}
	return true
}

func CheckNotifySet(values []smtp.DSNNotify) error {
	if len(values) == 0 {
		return errors.New("Malformed NOTIFY parameter value")
	}
	for _, val := range values {
		switch val {
		case smtp.DSNNotifyNever:
			if len(values) != 1 {
				return errors.New("Malformed NOTIFY parameter value")
			}
		case smtp.DSNNotifyDelayed, smtp.DSNNotifyFailure, smtp.DSNNotifySuccess:
			// RFC 3461 does not prohibit repeated list elements.
		default:
			return errors.New("Malformed NOTIFY parameter value")
		}
	}
	return nil
}
