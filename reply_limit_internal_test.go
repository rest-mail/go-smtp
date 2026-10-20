package smtp

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"net/textproto"
	"strings"
	"testing"
	"unicode/utf8"
)

// RFC 5321 §4.5.3.1.5 counts octets, including the status prefix and CRLF.
// Truncation must keep the status, multiline framing and complete UTF-8 runes.
//
// checklist: SMTP-LIM-06
func TestRFC5321_ReplyLine512(t *testing.T) {
	for _, tc := range []struct {
		name   string
		code   int
		enh    EnhancedCode
		prefix string
	}{
		{"plain", 220, NoEnhancedCode, "220 "},
		{"enhanced", 550, EnhancedCode{5, 1, 1}, "550 5.1.1 "},
		{"long enhanced", 550, EnhancedCode{5, 123, 456}, "550 5.123.456 "},
		{"default success", 250, EnhancedCodeNotSet, "250 2.0.0 "},
		{"default temporary", 450, EnhancedCodeNotSet, "450 4.0.0 "},
		{"default permanent", 550, EnhancedCodeNotSet, "550 5.0.0 "},
		{"default intermediate", 354, EnhancedCodeNotSet, "354 "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			budget := 512 - len(tc.prefix) - 2
			for _, n := range []int{0, budget - 1, budget, budget + 1, 4096} {
				text := strings.Repeat("x", n)
				wantText := text
				if n > budget {
					wantText = text[:budget]
				}
				got := renderLimitReply(t, tc.code, tc.enh, text)
				if want := tc.prefix + wantText + "\r\n"; got != want {
					t.Fatalf("%d text octets: got %q, want %q", n, got, want)
				}
			}
			for _, runeText := range []string{"é", "€", "😀"} {
				// Each possible split inside a multibyte character must back up
				// to the last complete character, rather than emit invalid UTF-8.
				for spare := 0; spare < len(runeText); spare++ {
					text := strings.Repeat("x", budget-spare) + runeText
					got := renderLimitReply(t, tc.code, tc.enh, text)
					want := tc.prefix + strings.Repeat("x", budget-spare) + "\r\n"
					if got != want || !utf8.ValidString(got) {
						t.Fatalf("UTF-8 boundary: got %q, want %q", got, want)
					}
				}
				text := strings.Repeat("x", budget-len(runeText)) + runeText
				if got, want := renderLimitReply(t, tc.code, tc.enh, text), tc.prefix+text+"\r\n"; got != want {
					t.Fatalf("complete UTF-8 boundary: got %q, want %q", got, want)
				}
			}
		})
	}
}

// Each logical line, including lines introduced by a backend's newline, has
// its own budget; the enhanced status stays on the final line as before.
//
// checklist: SMTP-LIM-06
func TestRFC5321_MultilineReplyLine512(t *testing.T) {
	long := strings.Repeat("x", 4096)
	got := renderLimitReply(t, 550, EnhancedCode{5, 1, 1}, long+"\nshort", long)
	want := "550-" + strings.Repeat("x", 506) + "\r\n550-short\r\n550 5.1.1 " + strings.Repeat("x", 500) + "\r\n"
	if got != want {
		t.Fatalf("multiline reply = %q, want %q", got, want)
	}
	if got := renderLimitReply(t, 250, NoEnhancedCode); got != "250 \r\n" {
		t.Fatalf("empty reply = %q", got)
	}
}

// RFC 4954 §4 explicitly makes SASL challenge sizes independent of ordinary
// SMTP line limits. Truncating this Base64 would corrupt the authentication.
//
// checklist: SMTP-LIM-06 SMTP-EXT-08
func TestRFC4954_LongChallengeNotTruncated(t *testing.T) {
	challenge := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("challenge"), 100))
	if got, want := renderLimitReply(t, 334, NoEnhancedCode, challenge), "334 "+challenge+"\r\n"; got != want {
		t.Fatalf("challenge changed: got %q, want %q", got, want)
	}
}

func renderLimitReply(t *testing.T, code int, enh EnhancedCode, text ...string) string {
	t.Helper()
	var out bytes.Buffer
	c := &Conn{
		server: NewServer(nopBackend{}),
		text:   &textproto.Conn{Writer: textproto.Writer{W: bufio.NewWriter(&out)}},
	}
	c.writeResponse(code, enh, text...)
	c.flush()
	if c.writeErr != nil {
		t.Fatal(c.writeErr)
	}
	return out.String()
}
