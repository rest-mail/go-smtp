package smtp

import (
	"reflect"
	"testing"
	"time"
)

// checklist: SMTP-SYN-01 SMTP-SYN-02
func TestParser(t *testing.T) {
	validReversePaths := []struct {
		raw, path, after string
	}{
		{"<>", "", ""},
		{"<root@nsa.gov>", "root@nsa.gov", ""},
		{"root@nsa.gov", "root@nsa.gov", ""},
		{"<root@nsa.gov> AUTH=asdf@example.org", "root@nsa.gov", " AUTH=asdf@example.org"},
		{"root@nsa.gov AUTH=asdf@example.org", "root@nsa.gov", " AUTH=asdf@example.org"},
		{"<@r1.example,@r2.example:u@example.org> SIZE=1", "u@example.org", " SIZE=1"},
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
		// The source route must end inside the path (found by fuzzing).
		"<@r> X=:u@x>",
		"<@r\x00:u@x>",
		"<@r\t:u@x>",
		"<@r<x:u@x>",
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
//
// checklist: SMTP-SYN-02
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

// TestParsePostmasterPath covers the domainless "<Postmaster>" forward-path
// form (RFC 5321 §4.1.1.3): it is matched case-insensitively, the local-part is
// returned with its original casing, the token is consumed leaving any trailing
// ESMTP parameters in p.s, and non-delimited or non-matching input is left
// untouched with ok == false so the caller falls back to normal path parsing.
//
// checklist: SMTP-SYN-03
func TestParsePostmasterPath(t *testing.T) {
	matched := []struct {
		raw, mbox, after string
	}{
		{"<Postmaster>", "Postmaster", ""},
		{"<postmaster>", "postmaster", ""},
		{"<POSTMASTER>", "POSTMASTER", ""},
		{"<PostMaster> NOTIFY=NEVER", "PostMaster", " NOTIFY=NEVER"},
		{"<Postmaster>\tORCPT=rfc822;x", "Postmaster", "\tORCPT=rfc822;x"},
	}
	for _, tc := range matched {
		p := parser{tc.raw}
		mbox, ok := p.parsePostmasterPath()
		if !ok {
			t.Errorf("parsePostmasterPath(%q): ok = false, want true", tc.raw)
		} else if mbox != tc.mbox {
			t.Errorf("parsePostmasterPath(%q) = %q, want %q", tc.raw, mbox, tc.mbox)
		} else if p.s != tc.after {
			t.Errorf("parsePostmasterPath(%q): after = %q, want %q", tc.raw, p.s, tc.after)
		}
	}

	// These must NOT be taken as the postmaster special form; p.s must be left
	// intact so the caller can fall back to parsePath.
	notMatched := []string{
		"<Postmaster@example.com>", // domain-qualified: normal path parsing
		"<Postmasterx>",            // not delimited by '>' at the token boundary
		"<Postmaster>x",            // trailing non-whitespace after '>'
		"Postmaster",               // missing angle brackets
		"<root@nsa.gov>",           // ordinary mailbox
		"<>",                       // empty path
	}
	for _, tc := range notMatched {
		p := parser{tc}
		if mbox, ok := p.parsePostmasterPath(); ok {
			t.Errorf("parsePostmasterPath(%q) = (%q, true), want ok=false", tc, mbox)
		} else if p.s != tc {
			t.Errorf("parsePostmasterPath(%q): p.s mutated to %q, want unchanged", tc, p.s)
		}
	}
}

// checklist: SMTP-SYN-06
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

// checklist: SMTP-EXT-07
func TestParseCmdSTARTTLSExact(t *testing.T) {
	if cmd, _, err := parseCmd("STARTTLS\r\n"); err != nil || cmd != "STARTTLS" {
		t.Fatalf("parseCmd(STARTTLS) = (%q, err=%v); want (STARTTLS, nil)", cmd, err)
	}
	// STARTTLSx must not be dispatched as STARTTLS; it is an unknown command.
	if cmd, _, err := parseCmd("STARTTLSx\r\n"); err == nil && cmd == "STARTTLS" {
		t.Fatalf("parseCmd(STARTTLSx) dispatched as STARTTLS; want it treated as an unknown command")
	}
}

// SMTP verbs are ASCII and case-insensitive (RFC 5321 section 2.4).
// Unicode case folding must not turn a different wire verb into STARTTLS.
//
// checklist: SMTP-SYN-05
func TestParseCmdASCII(t *testing.T) {
	for _, line := range []string{
		"ſTARTTLS", "STARTTLſ", "ſtarttls ignored", "ſET x", "KUIT", "ＭAIL FROM:<a@example.org>",
	} {
		t.Run(line, func(t *testing.T) {
			if cmd, _, err := parseCmd(line); err == nil {
				t.Fatalf("parseCmd(%q) = %q without error; want non-ASCII verb rejected", line, cmd)
			}
		})
	}
	for _, tc := range []struct{ line, cmd, arg string }{
		{"sTaRtTlS\r\n", "STARTTLS", ""},
		{"starttls ignored", "STARTTLS", ""},
		{"eHlO café.example\r\n", "EHLO", "café.example"},
		{"mAiL FROM:<élisa@example.org> SMTPUTF8", "MAIL", "FROM:<élisa@example.org> SMTPUTF8"},
		{"xClIeNt NAME=café ADDR=127.0.0.1", "XCLIENT", "NAME=café ADDR=127.0.0.1"},
		{"NOOP \xff=ſ", "NOOP", "\xff=ſ"},
		{"noop", "NOOP", ""},
	} {
		cmd, arg, err := parseCmd(tc.line)
		if err != nil || cmd != tc.cmd || arg != tc.arg {
			t.Errorf("parseCmd(%q) = (%q, %q, %v), want (%q, %q, nil)", tc.line, cmd, arg, err, tc.cmd, tc.arg)
		}
	}
}

// checklist: SMTP-SYN-06
func TestParseArgsBoundaries(t *testing.T) {
	for _, input := range []string{" SIZE=1 size=2", " SMTPUTF8 smtputf8", " AUTH=a=b AuTh=c==", " X= x"} {
		if args, err := parseArgs(input); err == nil || args != nil {
			t.Errorf("parseArgs(%q) = (%v, %v), want nil map and duplicate error", input, args, err)
		}
	}
	args, err := parseArgs(" auth=élisa=a== EMPTY= FLAG x==")
	want := map[string]string{"AUTH": "élisa=a==", "EMPTY": "", "FLAG": "", "X": "="}
	if err != nil || !reflect.DeepEqual(args, want) {
		t.Fatalf("parseArgs = (%v, %v), want (%v, nil)", args, err, want)
	}
}

// RFC 2852 section 4: optional sign, one to nine digits, N/R mode,
// optional T trace, and strictly positive time in return mode.
//
// checklist: SMTP-EXT-11
func TestParseDeliverByBoundaries(t *testing.T) {
	for _, tc := range []struct {
		input   string
		seconds int
		mode    DeliverByMode
		trace   bool
	}{
		{"0;N", 0, DeliverByNotify, false},
		{"-0;NT", 0, DeliverByNotify, true},
		{"+1;RT", 1, DeliverByReturn, true},
		{"000000001;R", 1, DeliverByReturn, false},
		{"999999999;N", 999999999, DeliverByNotify, false},
		{"+999999999;RT", 999999999, DeliverByReturn, true},
		{"-999999999;NT", -999999999, DeliverByNotify, true},
	} {
		got := parseDeliverByArgument(tc.input)
		if got == nil || got.Time != time.Duration(tc.seconds)*time.Second || got.Mode != tc.mode || got.Trace != tc.trace {
			t.Errorf("parseDeliverByArgument(%q) = %+v, want (%d seconds, %q, trace=%v)", tc.input, got, tc.seconds, tc.mode, tc.trace)
		}
	}
	for _, input := range []string{
		"", ";N", "+;N", "-;N", "1", "1;", "1;X", "1;NN", "1;NTT", "1;N;T", "1;TN",
		"0;R", "-0;RT", "-1;R", "1000000000;N", "-1000000000;N",
		"0000000001;N", "+0000000001;R", "-0000000000;N",
		"9223372036854775807;N", "-9223372036854775808;N",
		"1.0;N", " 1;N", "1 ;N", "1;N\r\n", "１;N", "1;Ｎ", "1;NＴ",
	} {
		if got := parseDeliverByArgument(input); got != nil {
			t.Errorf("parseDeliverByArgument(%q) = %+v, want nil", input, got)
		}
	}
}
