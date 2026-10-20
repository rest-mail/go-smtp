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

// wireFields is the oracle's token split: SMTP separates tokens with SP
// (RFC 5321 §4.1.2), and the server also tolerates HTAB. Every other byte,
// including those of a UTF-8 space such as U+0085, belongs to a token.
func wireFields(s string) []string {
	var fields []string
	start := -1
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ' ' || s[i] == '\t' {
			if start >= 0 {
				fields = append(fields, s[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	return fields
}

// wireTrim strips the SP and HTAB around s, and nothing else.
func wireTrim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// checklist: SMTP-SYN-05
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
		if hasArgs {
			wantArg = wireTrim(rest)
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

// checklist: SMTP-SYN-06
func FuzzParseArgs(f *testing.F) {
	for _, seed := range []string{
		"", " ", " BODY=8BITMIME SIZE=1024 SMTPUTF8", " SIZE=1 size=2",
		" SMTPUTF8 smtputf8", " AUTH=a=b== AuTh=x", " X=a=b== EMPTY= FLAG",
		" AUTH=élisa=a==", " X=\xff", "=", " X=1\tY=2\r\n", " X=1\x00",
		// CI found strings.Fields splitting a value at U+0085 NEL.
		"0000000000000000000000000000000000000000000000000\u0085",
		" X=a\u00a0b Y=\u0085", " \u2028X=1",
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
		for _, field := range wireFields(input) {
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
		value := strings.Join(wireFields(input), "")
		one, oneErr := parseArgs(" AuTh=" + value)
		if oneErr != nil || one["AUTH"] != value {
			t.Fatalf("AUTH value changed: %q => (%v, %v)", value, one, oneErr)
		}
		if _, dupErr := parseArgs(" AuTh=" + value + " aUtH=x"); dupErr == nil {
			t.Fatal("case-insensitive duplicate AUTH accepted")
		}
	})
}

// checklist: SMTP-EXT-11
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
	// Check valid bounded deadlines once, so rejecting every input cannot
	// satisfy the fuzz invariants. This must stay out of the fuzz body: when
	// the body derived a deadline from len(input), every byte the minimizer
	// removed changed fmt's and strconv's coverage, so no byte could go and
	// minimizing one interesting input walked O(n²) candidates for the whole
	// -fuzzminimizetime, which reads as 0 execs/sec.
	for _, seconds := range []int64{0, 1, 123457, 99999999, 999999999} {
		for _, suffix := range []string{"N", "NT", "R", "RT"} {
			if seconds == 0 && suffix[0] == 'R' {
				continue
			}
			for _, valid := range []string{
				fmt.Sprintf("%d;%s", seconds, suffix),
				fmt.Sprintf("+%09d;%s", seconds, suffix),
			} {
				got := parseDeliverByArgument(valid)
				if got == nil || got.Time != time.Duration(seconds)*time.Second ||
					string(got.Mode) != suffix[:1] || got.Trace != (len(suffix) == 2) {
					f.Fatalf("valid BY failed: %q => %+v", valid, got)
				}
			}
		}
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
	})
}

// pathSeeds cover the null reverse-path, dot-string and quoted local-parts,
// SMTPUTF8, source routes, the domainless Postmaster form and the boundaries
// of each (trailing parameters, missing brackets, control bytes).
var pathSeeds = []string{
	"", "<>", "<> SIZE=10", "<>x", "<root@nsa.gov>", "root@nsa.gov",
	"<root@nsa.gov> AUTH=asdf@example.org", "root@nsa.gov\tSIZE=1", "<root@nsa.gov",
	"<élisa@exämple.org> SMTPUTF8", "<\xff@\xfe>", `<"a b\"c\\d"@example.org>`,
	`"a>b"@example.org`, `<"\a"@x>`, `<"\`, `<""@x>`, "<a\x00b@x>", "<a@x\x7f>",
	`<"a\` + "\x01" + `"@x>`, "<@r1.example,@r2.example:u@example.org>",
	"@r.example:u@example.org", "<@:u@x>", "<@r.example>", "<@r> X=:u@x>",
	"<@r\x00:u@x>", "<@r\t:u@x>", "<Postmaster>", "<postMASTER> NOTIFY=NEVER",
	"<Postmaster>\tX=1", "<Postmaster>x", "<Postmaster", "<Postmaster@example.org>",
	"Postmaster", "<Poſtmaster>", "<Foo Bar <root@nsa.gov>>", "a:b:c@example.org",
	"<a@b@c>", "<a@[192.0.2.1]>", "<a@b>c", "a@b>",
}

// isASCIIPrefixFold reports whether s starts with prefix, ignoring ASCII case
// only: SMTP keywords such as Postmaster are ASCII (RFC 5321 §2.4).
func isASCIIPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		a, b := s[i], prefix[i]
		if 'A' <= a && a <= 'Z' {
			a += 'a' - 'A'
		}
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}

// checkAcceptedPath checks a non-null path parsePath accepted from input
// against RFC 5321 §4.1.2, independently of how the parser reached it.
func checkAcceptedPath(t *testing.T, input, mbox, rest string) {
	t.Helper()
	if !strings.HasSuffix(input, rest) {
		t.Fatalf("%q: parser left %q, not a suffix of its input", input, rest)
	}
	consumed := input[:len(input)-len(rest)]
	for i := 0; i < len(mbox); i++ {
		if mbox[i] < 0x20 || mbox[i] == 0x7F {
			t.Fatalf("%q: control byte leaked into mailbox %q", input, mbox)
		}
	}
	// Path = "<" [ A-d-l ":" ] Mailbox ">"; the closing bracket is consumed
	// exactly when the opening one was.
	bracketed := strings.HasPrefix(consumed, "<")
	if bracketed != strings.HasSuffix(consumed, ">") {
		t.Fatalf("%q: unbalanced path %q", input, consumed)
	}
	body := consumed
	if bracketed {
		body = body[1 : len(body)-1]
	} else if rest != "" && rest[0] != ' ' && rest[0] != '\t' && rest[0] != '>' {
		t.Fatalf("%q: unbracketed path ended inside a token, left %q", input, rest)
	}
	if strings.HasPrefix(body, "@") {
		// A-d-l = At-domain *( "," At-domain ): domains only, so the route
		// can neither run past the path's end nor hide whitespace or controls.
		route, after, ok := strings.Cut(body, ":")
		if !ok {
			t.Fatalf("%q: source route without ':' accepted", input)
		}
		for i := 0; i < len(route); i++ {
			if c := route[i]; c <= ' ' || c == 0x7F || c == '<' || c == '>' {
				t.Fatalf("%q: source route %q crosses the path boundary", input, route)
			}
		}
		body = after
	}
	local, domain := body, ""
	if strings.HasPrefix(body, `"`) {
		// Quoted-string = DQUOTE *QcontentSMTP DQUOTE; the mailbox carries
		// the content with each quoted-pair reduced to its character.
		var sb strings.Builder
		i := 1
		for ; i < len(body) && body[i] != '"'; i++ {
			if body[i] == '\\' {
				i++
			}
			if i < len(body) {
				sb.WriteByte(body[i])
			}
		}
		if i >= len(body) {
			t.Fatalf("%q: unterminated quoted-string accepted", input)
		}
		local, domain = sb.String(), body[i+1:]
		if !strings.HasPrefix(domain, "@") {
			t.Fatalf("%q: quoted local-part not followed by '@'", input)
		}
	} else {
		at := strings.IndexByte(body, '@')
		if at < 0 {
			t.Fatalf("%q: mailbox without '@' accepted", input)
		}
		local, domain = body[:at], body[at:]
	}
	if local == "" || len(domain) < 2 {
		t.Fatalf("%q: empty local-part or domain accepted: %q", input, mbox)
	}
	if strings.ContainsAny(domain, " \t>") {
		t.Fatalf("%q: domain %q runs past the path", input, domain)
	}
	if mbox != local+domain {
		t.Fatalf("%q: mailbox %q, want %q", input, mbox, local+domain)
	}
}

// validPathParts derives a dot-string local-part, a domain and a quoted
// local-part from arbitrary fuzz input, so the targets also check acceptance:
// rejecting every input must not satisfy them.
func validPathParts(input string) (local, domain, quoted string) {
	var l, d, q strings.Builder
	for i := 0; i < len(input) && i < 64; i++ {
		c := input[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
			l.WriteByte(c)
			d.WriteByte(c)
		case c >= 0x80 || strings.IndexByte("!#$%&'*+-/=?^_`{|}~", c) >= 0:
			l.WriteByte(c) // atext, plus UTF-8 for SMTPUTF8
		}
		if c >= ' ' && c != 0x7F {
			q.WriteByte(c)
		}
	}
	return "u" + l.String(), "d" + d.String() + ".example", q.String()
}

// checklist: SMTP-SYN-01 SMTP-SYN-02
func FuzzParseReversePath(f *testing.F) {
	for _, seed := range pathSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxParserFuzzInput {
			t.Skip()
		}
		// conn.handleMail trims the argument after "FROM:".
		s := strings.TrimSpace(input)
		p := parser{s: s}
		mbox, err := p.parseReversePath()
		if strings.HasPrefix(s, "<>") {
			// Reverse-path = Path / "<>" (RFC 5321 §4.1.2).
			if err != nil || mbox != "" || p.s != s[2:] {
				t.Fatalf("null reverse-path %q => (%q, %v, rest %q)", s, mbox, err, p.s)
			}
		} else if err == nil {
			checkAcceptedPath(t, s, mbox, p.s)
		}
		if isASCIIPrefixFold(s, "<postmaster>") && err == nil {
			// The domainless Postmaster form is a forward-path only (§4.1.1.3).
			t.Fatalf("MAIL accepted domainless %q", s)
		}

		local, domain, quoted := validPathParts(input)
		addr := local + "@" + domain
		for _, tc := range []struct{ raw, mbox, rest string }{
			{"<>", "", ""},
			{"<> SIZE=1", "", " SIZE=1"},
			{"<" + addr + ">", addr, ""},
			{"<" + addr + "> BODY=8BITMIME", addr, " BODY=8BITMIME"},
			{addr + "\tSIZE=1", addr, "\tSIZE=1"},
			{"<@a.example,@b.example:" + addr + ">", addr, ""},
		} {
			p := parser{s: tc.raw}
			got, err := p.parseReversePath()
			if err != nil || got != tc.mbox || p.s != tc.rest {
				t.Fatalf("valid %q => (%q, %v, rest %q)", tc.raw, got, err, p.s)
			}
		}
		if quoted != "" {
			raw := `<"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(quoted) + `"@` + domain + ">"
			p := parser{s: raw}
			if got, err := p.parseReversePath(); err != nil || got != quoted+"@"+domain || p.s != "" {
				t.Fatalf("valid quoted %q => (%q, %v, rest %q)", raw, got, err, p.s)
			}
		}
	})
}

// checklist: SMTP-SYN-02 SMTP-SYN-03 SMTP-SYN-04
func FuzzParseForwardPath(f *testing.F) {
	for _, seed := range pathSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxParserFuzzInput {
			t.Skip()
		}
		// conn.handleRcpt trims the argument after "TO:", tries the
		// domainless Postmaster form, then falls back to an ordinary path.
		s := strings.TrimSpace(input)
		p := parser{s: s}
		mbox, ok := p.parsePostmasterPath()
		wantPostmaster := isASCIIPrefixFold(s, "<postmaster>") &&
			(len(s) == 12 || s[12] == ' ' || s[12] == '\t')
		if ok != wantPostmaster {
			t.Fatalf("Postmaster form %q: ok = %v, want %v", s, ok, wantPostmaster)
		}
		if ok {
			// Postmaster is case-insensitive; keep the client's spelling.
			if mbox != s[1:11] || p.s != s[12:] {
				t.Fatalf("Postmaster form %q => (%q, rest %q)", s, mbox, p.s)
			}
		} else {
			if p.s != s {
				t.Fatalf("Postmaster fallback consumed input: %q => rest %q", s, p.s)
			}
			mbox, err := p.parsePath()
			if err == nil {
				checkAcceptedPath(t, s, mbox, p.s)
			}
			if strings.HasPrefix(s, "<>") && err == nil {
				// A forward-path is never null (§4.1.1.3).
				t.Fatalf("RCPT accepted null path %q", s)
			}
		}

		// Spell Postmaster with the case pattern of the input's bytes.
		pm := []byte("postmaster")
		for i := range pm {
			if i < len(input) && input[i]&1 == 1 {
				pm[i] -= 'a' - 'A'
			}
		}
		local, domain, _ := validPathParts(input)
		for _, tc := range []struct{ raw, mbox, rest string }{
			{"<" + string(pm) + ">", string(pm), ""},
			{"<" + string(pm) + "> NOTIFY=NEVER", string(pm), " NOTIFY=NEVER"},
			{"<" + string(pm) + ">\tX=1", string(pm), "\tX=1"},
		} {
			p := parser{s: tc.raw}
			if got, ok := p.parsePostmasterPath(); !ok || got != tc.mbox || p.s != tc.rest {
				t.Fatalf("valid %q => (%q, %v, rest %q)", tc.raw, got, ok, p.s)
			}
		}
		for _, tc := range []struct{ raw, mbox string }{
			{"<" + string(pm) + "@" + domain + ">", string(pm) + "@" + domain},
			{"<" + local + "@" + domain + ">", local + "@" + domain},
			{"<@r.example:" + local + "@" + domain + ">", local + "@" + domain},
		} {
			p := parser{s: tc.raw}
			if _, ok := p.parsePostmasterPath(); ok {
				t.Fatalf("%q taken as the domainless Postmaster form", tc.raw)
			}
			if got, err := p.parsePath(); err != nil || got != tc.mbox || p.s != "" {
				t.Fatalf("valid %q => (%q, %v, rest %q)", tc.raw, got, err, p.s)
			}
		}
		for _, raw := range []string{"<>", "<" + string(pm) + ">x", "<" + string(pm)} {
			p := parser{s: raw}
			if _, ok := p.parsePostmasterPath(); ok {
				t.Fatalf("%q taken as the domainless Postmaster form", raw)
			}
			if got, err := p.parsePath(); err == nil {
				t.Fatalf("RCPT accepted %q as %q", raw, got)
			}
		}
	})
}
