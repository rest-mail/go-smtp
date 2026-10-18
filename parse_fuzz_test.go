package smtp

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Bound work and allocations even when the fuzzer generates oversized inputs.
const maxParserFuzzInput = 4096

func FuzzParseCmd(f *testing.F) {
	for _, seed := range []string{
		"", "\r\n", "A", "NOOP", "noop\r\n", "HELOx", "EHLO café.example\r\n",
		"MAIL FROM:<élisa@example.org> SMTPUTF8", "NOOP \xff=ſ", "DATA\x00",
		"sTaRtTlS", "STARTTLS ignored", "STARTTLSx", "ſTARTTLS", "STARTTLſ", "ſtarttls ignored",
		"xClIeNt NAME=café", "XCLIENTx", "KUIT", "ſET x", "ＭAIL x", "\xffOOO x", "0 00",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		if len(line) > maxParserFuzzInput {
			t.Skip()
		}
		cmd, arg, err := parseCmd(line)
		if err != nil {
			return
		}
		wire := strings.TrimRight(line, "\r\n")
		verb, rest, hasArgs := strings.Cut(wire, " ")
		for i := 0; i < len(verb); i++ {
			if verb[i] >= 0x80 {
				t.Fatalf("non-ASCII wire verb %q parsed as %q", verb, cmd)
			}
		}
		// Unknown commands are left to dispatch to reject. Only recognized
		// SMTP verbs must correspond exactly to the ASCII wire token.
		switch cmd {
		case "", "HELO", "EHLO", "LHLO", "MAIL", "RCPT", "VRFY", "NOOP", "RSET",
			"BDAT", "DATA", "QUIT", "AUTH", "STARTTLS", "XCLIENT",
			"SEND", "SOML", "SAML", "EXPN", "HELP", "TURN":
		default:
			return
		}
		if cmd != strings.ToUpper(verb) {
			t.Fatalf("wire verb %q synthesized command %q", verb, cmd)
		}
		wantArg := ""
		if hasArgs && cmd != "STARTTLS" {
			wantArg = strings.TrimSpace(rest)
		}
		if arg != wantArg {
			t.Fatalf("argument bytes changed: got %q, want %q", arg, wantArg)
		}
		// ASCII case changes must preserve both dispatch and argument bytes.
		lower := strings.ToLower(verb)
		if hasArgs {
			lower += " " + rest
		}
		lowerCmd, lowerArg, lowerErr := parseCmd(lower)
		if lowerErr != nil || lowerCmd != cmd || lowerArg != arg {
			t.Fatalf("ASCII case changed parsing: (%q, %q, %v)", lowerCmd, lowerArg, lowerErr)
		}
	})
}

func FuzzParseArgs(f *testing.F) {
	for _, seed := range []string{
		"", " ", " BODY=8BITMIME SIZE=1024 SMTPUTF8", " SIZE=1 size=2",
		" SMTPUTF8 smtputf8", " AUTH=a=b== AuTh=x", " X=a=b== EMPTY= FLAG",
		" AUTH=élisa=a==", " X=\xff", "=", " X=1\tY=2\r\n", " X=1\x00",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxParserFuzzInput {
			t.Skip()
		}
		args, err := parseArgs(input)
		seen := make(map[string]bool)
		duplicate := false
		for _, field := range strings.Fields(input) {
			end := strings.IndexByte(field, '=')
			if end < 0 {
				end = len(field)
			}
			key := strings.ToUpper(field[:end])
			duplicate = duplicate || seen[key]
			seen[key] = true
			if err == nil {
				value := ""
				if end < len(field) {
					value = field[end+1:]
				}
				if got, ok := args[key]; !ok || got != value {
					t.Fatalf("field %q lost key/value bytes: %v", field, args)
				}
			}
		}
		if duplicate {
			if err == nil || args != nil {
				t.Fatalf("duplicate keys accepted: %q => %v", input, args)
			}
		} else if err != nil || len(args) != len(seen) {
			t.Fatalf("unique options failed: %q => (%v, %v)", input, args, err)
		}
		// Any value made of one field, including embedded '=', must survive;
		// changing the ASCII casing of the key must still count as a repeat.
		value := strings.Join(strings.Fields(input), "")
		one, oneErr := parseArgs(" AuTh=" + value)
		if oneErr != nil || one["AUTH"] != value {
			t.Fatalf("AUTH value changed: %q => (%v, %v)", value, one, oneErr)
		}
		if _, dupErr := parseArgs(" AuTh=" + value + " aUtH=x"); dupErr == nil {
			t.Fatal("case-insensitive duplicate AUTH accepted")
		}
	})
}

func FuzzParseDeliverByArgument(f *testing.F) {
	for _, seed := range []string{
		"", "1", ";N", "+;N", "0;N", "-0;NT", "1;R", "+1;RT", "-1;N", "0;R", "-1;R",
		"999999999;RT", "-999999999;NT", "1000000000;N", "-1000000000;N",
		"000000001;R", "0000000001;N", "+0000000001;R", "-0000000000;N",
		"9223372036854775807;N", "-9223372036854775808;N", "1;X", "1;NTT", "1;N;T",
		"1;TN", "1;n", "1;rt", "１;N", "1;Ｎ", "1;NＴ", "1;N\r\n", "\x00;N",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxParserFuzzInput {
			t.Skip()
		}
		if got := parseDeliverByArgument(input); got != nil {
			number, suffix, ok := strings.Cut(input, ";")
			digits := strings.TrimPrefix(strings.TrimPrefix(number, "+"), "-")
			if !ok || len(digits) < 1 || len(digits) > 9 || strings.Trim(digits, "0123456789") != "" {
				t.Fatalf("invalid BY time accepted: %q", input)
			}
			if suffix != "N" && suffix != "NT" && suffix != "R" && suffix != "RT" {
				t.Fatalf("invalid BY mode/trace accepted: %q", input)
			}
			seconds, err := strconv.ParseInt(number, 10, 64)
			if err != nil || seconds < -999999999 || seconds > 999999999 ||
				got.Time != time.Duration(seconds)*time.Second ||
				string(got.Mode) != suffix[:1] || got.Trace != (len(suffix) == 2) ||
				(got.Mode == DeliverByReturn && seconds <= 0) {
				t.Fatalf("invalid BY result: %q => %+v", input, got)
			}
		}
		// Generate valid bounded deadlines as well as mutating raw syntax,
		// so rejecting every input cannot satisfy the fuzz invariants.
		seconds := int64(len(input)) * 123457 % 1000000000
		for _, suffix := range []string{"N", "NT", "R", "RT"} {
			if seconds == 0 && suffix[0] == 'R' {
				continue
			}
			valid := fmt.Sprintf("+%09d;%s", seconds, suffix)
			got := parseDeliverByArgument(valid)
			if got == nil || got.Time != time.Duration(seconds)*time.Second ||
				string(got.Mode) != suffix[:1] || got.Trace != (len(suffix) == 2) {
				t.Fatalf("valid BY failed: %q => %+v", valid, got)
			}
		}
	})
}
