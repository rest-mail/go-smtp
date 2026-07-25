package smtp

import (
	"testing"
)

func TestParser(t *testing.T) {
	validReversePaths := []struct {
		raw, path, after string
	}{
		{"<>", "", ""},
		{"<root@nsa.gov>", "root@nsa.gov", ""},
		{"root@nsa.gov", "root@nsa.gov", ""},
		{"<root@nsa.gov> AUTH=asdf@example.org", "root@nsa.gov", " AUTH=asdf@example.org"},
		{"root@nsa.gov AUTH=asdf@example.org", "root@nsa.gov", " AUTH=asdf@example.org"},
	}
	for _, tc := range validReversePaths {
		p := parser{tc.raw}
		path, err := p.parseReversePath()
		if err != nil {
			t.Errorf("parser.parseReversePath(%q) = %v", tc.raw, err)
		} else if path != tc.path {
			t.Errorf("parser.parseReversePath(%q) = %q, want %q", tc.raw, path, tc.path)
		} else if p.s != tc.after {
			t.Errorf("parser.parseReversePath(%q): got after = %q, want %q", tc.raw, p.s, tc.after)
		}
	}

	invalidReversePaths := []string{
		"",
		" ",
		"asdf",
		"<Foo Bar <root@nsa.gov>>",
		" BODY=8BITMIME SIZE=12345",
		"a:b:c@example.org",
		"<root@nsa.gov",
	}
	for _, tc := range invalidReversePaths {
		p := parser{tc}
		if path, err := p.parseReversePath(); err == nil {
			t.Errorf("parser.parseReversePath(%q) = %q, want error", tc, path)
		}
	}
}

// TestParserRejectsControlBytes verifies that control bytes (< 0x20 and 0x7F)
// are rejected in both the domain and the local-part (dot-string and
// quoted-string, including quoted-pairs). RFC 5321 §4.1.2 excludes control
// characters from Let-dig and qtextSMTP; accepting them enables the tainted
// address to be echoed into status lines (command/response injection).
func TestParserRejectsControlBytes(t *testing.T) {
	rejected := []struct {
		name, raw string
	}{
		{"CR in domain", "<alice@ex\rample.com>"},
		{"LF in domain", "<alice@ex\nample.com>"},
		{"NUL in domain", "<alice@ex\x00ample.com>"},
		{"DEL in domain", "<alice@example.com\x7f>"},
		{"CR in dot-string local-part", "<al\rice@example.com>"},
		{"NUL in dot-string local-part", "<al\x00ice@example.com>"},
		{"CR in quoted local-part", "<\"al\rice\"@example.com>"},
		{"NUL in quoted local-part", "<\"al\x00ice\"@example.com>"},
		{"DEL in quoted local-part", "<\"al\x7fice\"@example.com>"},
		{"escaped CR in quoted local-part", "<\"al\\\rice\"@example.com>"},
	}
	for _, tc := range rejected {
		p := parser{tc.raw}
		if path, err := p.parseReversePath(); err == nil {
			t.Errorf("%s: parseReversePath(%q) = %q, want error", tc.name, tc.raw, path)
		}
	}

	// SMTPUTF8 bytes (> 0x7F) must remain permitted in both domain and
	// local-part; only the C0/DEL control range is forbidden.
	allowed := []string{
		"<\xc3\xa9lisa@ex\xc3\xa9mple.com>",
		"<\"\xc3\xa9lisa\"@example.com>",
	}
	for _, tc := range allowed {
		p := parser{tc}
		if _, err := p.parseReversePath(); err != nil {
			t.Errorf("parseReversePath(%q) = %v, want no error (SMTPUTF8 high bytes must be allowed)", tc, err)
		}
	}
}

func TestParseArgsEqualsInValue(t *testing.T) {
	args, err := parseArgs(" X=a=b SIMPLE=1 FLAG")
	if err != nil {
		t.Fatalf("parseArgs returned error: %v", err)
	}
	if got := args["X"]; got != "a=b" {
		t.Errorf("args[X] = %q, want %q", got, "a=b")
	}
	if got := args["SIMPLE"]; got != "1" {
		t.Errorf("args[SIMPLE] = %q, want %q", got, "1")
	}
	if got, ok := args["FLAG"]; !ok || got != "" {
		t.Errorf("args[FLAG] = %q (present=%v), want empty and present", got, ok)
	}
}

func TestParseCmdSTARTTLSExact(t *testing.T) {
	if cmd, _, err := parseCmd("STARTTLS\r\n"); err != nil || cmd != "STARTTLS" {
		t.Fatalf("parseCmd(STARTTLS) = (%q, err=%v); want (STARTTLS, nil)", cmd, err)
	}
	// STARTTLSx must not be dispatched as STARTTLS; it is an unknown command.
	if cmd, _, err := parseCmd("STARTTLSx\r\n"); err == nil && cmd == "STARTTLS" {
		t.Fatalf("parseCmd(STARTTLSx) dispatched as STARTTLS; want it treated as an unknown command")
	}
}
