package smtp

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// cutPrefixFold is a version of strings.CutPrefix which is case-insensitive.
func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return "", false
	}
	return s[len(prefix):], true
}

// isWSP reports whether ch separates SMTP tokens: SP, which RFC 5321 §4.1.2
// requires, or HTAB, which the server also tolerates (RFC 5234 WSP). Any
// other byte, including the bytes of a UTF-8 space such as U+0085 NEL or
// U+00A0 NBSP, is token content: an SMTPUTF8 esmtp-value may carry UTF-8
// (RFC 6531 §3.3).
func isWSP(ch byte) bool {
	return ch == ' ' || ch == '\t'
}

// trimWSP removes leading and trailing SP and HTAB from s. Unlike
// strings.TrimSpace it leaves Unicode whitespace in place.
func trimWSP(s string) string {
	return strings.Trim(s, " \t")
}

// splitWSP splits s into the tokens separated by runs of SP and HTAB. Unlike
// strings.Fields it does not split on Unicode whitespace.
func splitWSP(s string) []string {
	var fields []string
	for {
		for len(s) > 0 && isWSP(s[0]) {
			s = s[1:]
		}
		if s == "" {
			return fields
		}
		i := 0
		for i < len(s) && !isWSP(s[i]) {
			i++
		}
		fields = append(fields, s[:i])
		s = s[i:]
	}
}

func parseCmd(line string) (cmd string, arg string, err error) {
	line = strings.TrimRight(line, "\r\n")
	// SMTP verbs are ASCII (RFC 5321 section 2.4). Unicode case folding
	// would otherwise turn e.g. long-s into S in STARTTLS. Arguments may
	// contain UTF-8, so check only the verb before normalizing its case.
	for i := 0; i < len(line) && line[i] != ' '; i++ {
		if line[i] >= 0x80 {
			return "", "", fmt.Errorf("non-ASCII command verb")
		}
	}

	l := len(line)
	switch {
	case strings.EqualFold(line, "STARTTLS") || strings.HasPrefix(strings.ToUpper(line), "STARTTLS "):
		// Preserve parameters so the handler can reject them with 501
		// (RFC 3207 §4), rather than silently starting a TLS handshake.
		if i := strings.IndexByte(line, ' '); i >= 0 {
			return "STARTTLS", trimWSP(line[i+1:]), nil
		}
		return "STARTTLS", "", nil
	case strings.EqualFold(line, "XCLIENT") || strings.HasPrefix(strings.ToUpper(line), "XCLIENT "):
		// XCLIENT is a 7-letter verb (not the 4-letter form the logic below
		// assumes) and carries attribute arguments.
		if i := strings.IndexByte(line, ' '); i >= 0 {
			return "XCLIENT", trimWSP(line[i+1:]), nil
		}
		return "XCLIENT", "", nil
	case l == 0:
		return "", "", nil
	case l < 4:
		return "", "", fmt.Errorf("command too short: %q", line)
	case l == 4:
		return strings.ToUpper(line), "", nil
	case l == 5:
		// Too long to be only command, too short to have args
		return "", "", fmt.Errorf("mangled command: %q", line)
	}

	// If we made it here, command is long enough to have args
	if line[4] != ' ' {
		// There wasn't a space after the command?
		return "", "", fmt.Errorf("mangled command: %q", line)
	}

	return strings.ToUpper(line[0:4]), trimWSP(line[5:]), nil
}

// Takes the arguments proceeding a command and files them
// into a map[string]string after uppercasing each key.  Sample arg
// string:
//
//	" BODY=8BITMIME SIZE=1024 SMTPUTF8"
//
// The leading space is mandatory. Parameters are separated by SP or HTAB
// only (see isWSP).
func parseArgs(s string) (map[string]string, error) {
	argMap := map[string]string{}
	for _, arg := range splitWSP(s) {
		// Split on the first '=' only: a parameter value may itself contain
		// '=' (e.g. base64-ish or AUTH values).
		key, value, _ := strings.Cut(arg, "=")
		key = strings.ToUpper(key)
		// RFC 5321 §4.1.1.11: an esmtp-keyword must not appear more than once in
		// a single command. Reject a repeat rather than silently collapsing it in
		// the map (which would keep only the last value).
		if _, dup := argMap[key]; dup {
			return nil, fmt.Errorf("duplicate ESMTP parameter %q", key)
		}
		argMap[key] = value
	}
	return argMap, nil
}

func parseHelloArgument(arg string) (string, error) {
	domain := arg
	if idx := strings.IndexAny(arg, " \t"); idx >= 0 {
		domain = arg[:idx]
	}
	if domain == "" {
		return "", fmt.Errorf("invalid domain")
	}
	return domain, nil
}

// maxDeliverBySeconds is the largest by-time RFC 2852 section 4 can express:
// its grammar allows at most nine digits.
const maxDeliverBySeconds = 999999999

// Parses the BY argument defined in RFC2852 section 4.
// Returns pointer to options or nil if invalid.
func parseDeliverByArgument(arg string) *DeliverByOptions {
	secondsStr, modeStr, ok := strings.Cut(arg, ";")
	if !ok {
		return nil
	}
	// Count wire digits, including leading zeros, rather than just bounding
	// the numeric value: RFC 2852 section 4 permits ["-" / "+"]1*9DIGIT.
	digits := secondsStr
	if strings.HasPrefix(digits, "+") || strings.HasPrefix(digits, "-") {
		digits = digits[1:]
	}
	if len(digits) < 1 || len(digits) > 9 {
		return nil
	}
	modeStr, traceValue := strings.CutSuffix(modeStr, "T")
	if modeStr != string(DeliverByNotify) && modeStr != string(DeliverByReturn) {
		return nil
	}
	modeValue := DeliverByMode(modeStr)
	secondsValue, err := strconv.Atoi(secondsStr)
	if err != nil || (modeValue == DeliverByReturn && secondsValue < 1) {
		return nil
	}
	// A by-time outside the nine digits the grammar allows is malformed, not
	// merely large. Rejecting it here keeps an absurd deadline (and, on a
	// 64-bit platform, one that overflows the resulting Duration) out of the
	// backend.
	if secondsValue > maxDeliverBySeconds || secondsValue < -maxDeliverBySeconds {
		return nil
	}
	return &DeliverByOptions{
		Time:  time.Duration(secondsValue) * time.Second,
		Mode:  modeValue,
		Trace: traceValue,
	}
}

// parser parses command arguments defined in RFC 5321 section 4.1.2.
type parser struct {
	s string
}

// isCTL reports whether ch is an ASCII control byte: the C0 range (< 0x20,
// which includes NUL, TAB, CR and LF) or DEL (0x7F). RFC 5321 §4.1.2 excludes
// these from Let-dig and qtextSMTP. Bytes > 0x7F are intentionally not treated
// as control bytes so that SMTPUTF8 addresses remain permitted.
func isCTL(ch byte) bool {
	return ch < 0x20 || ch == 0x7F
}

func (p *parser) peekByte() (byte, bool) {
	if len(p.s) == 0 {
		return 0, false
	}
	return p.s[0], true
}

func (p *parser) readByte() (byte, bool) {
	ch, ok := p.peekByte()
	if ok {
		p.s = p.s[1:]
	}
	return ch, ok
}

func (p *parser) acceptByte(ch byte) bool {
	got, ok := p.peekByte()
	if !ok || got != ch {
		return false
	}
	p.readByte()
	return true
}

func (p *parser) expectByte(ch byte) error {
	if !p.acceptByte(ch) {
		if len(p.s) == 0 {
			return fmt.Errorf("expected '%v', got EOF", string(ch))
		} else {
			return fmt.Errorf("expected '%v', got '%v'", string(ch), string(p.s[0]))
		}
	}
	return nil
}

func (p *parser) parseReversePath() (string, error) {
	if strings.HasPrefix(p.s, "<>") {
		p.s = strings.TrimPrefix(p.s, "<>")
		return "", nil
	}
	return p.parsePath()
}

func (p *parser) parsePath() (string, error) {
	hasBracket := p.acceptByte('<')
	if p.acceptByte('@') {
		i := strings.IndexByte(p.s, ':')
		if i < 0 {
			return "", fmt.Errorf("malformed a-d-l")
		}
		// The source route (A-d-l, RFC 5321 §4.1.2) is a list of domains and
		// is skipped, not returned. Bound the skip to the path: a ':' found
		// past whitespace, an angle bracket or a control byte belongs to the
		// parameters or another token, e.g. "<@r> X=:u@x>".
		for j := 0; j < i; j++ {
			if ch := p.s[j]; ch == ' ' || ch == '<' || ch == '>' || isCTL(ch) {
				return "", fmt.Errorf("malformed a-d-l")
			}
		}
		p.s = p.s[i+1:]
	}
	mbox, err := p.parseMailbox()
	if err != nil {
		return "", fmt.Errorf("in mailbox: %v", err)
	}
	if hasBracket {
		if err := p.expectByte('>'); err != nil {
			return "", err
		}
	}
	return mbox, nil
}

// parsePostmasterPath handles the domainless "<Postmaster>" forward-path form
// defined in RFC 5321 §4.1.1.3. Because it has no "@domain", parseMailbox
// rejects it; yet §4.5.1 requires every receiver to accept it, so RCPT must
// special-case it. This form is valid only for the forward-path (RCPT TO), not
// for the reverse-path (MAIL FROM), so the handling lives here rather than in
// parsePath/parseReversePath.
//
// When p.s begins with a case-insensitive "<Postmaster>" delimited by
// end-of-input or whitespace (so ESMTP parameters may follow), it consumes the
// token and returns the local-part as typed (preserving the client's casing)
// with ok == true. Otherwise it leaves p.s untouched and returns ok == false so
// the caller can fall back to ordinary path parsing.
func (p *parser) parsePostmasterPath() (mbox string, ok bool) {
	const token = "<Postmaster>"
	rest, matched := cutPrefixFold(p.s, token)
	if !matched {
		return "", false
	}
	// Guard against swallowing e.g. "<Postmaster>x" (not a valid delimiter) as
	// the postmaster form; only end-of-input or whitespace may follow.
	if len(rest) > 0 && rest[0] != ' ' && rest[0] != '\t' {
		return "", false
	}
	mbox = p.s[1 : len(token)-1] // strip the angle brackets, keep original case
	p.s = rest
	return mbox, true
}

func (p *parser) parseMailbox() (string, error) {
	localPart, err := p.parseLocalPart()
	if err != nil {
		return "", fmt.Errorf("in local-part: %v", err)
	} else if localPart == "" {
		return "", fmt.Errorf("local-part is empty")
	}

	if err := p.expectByte('@'); err != nil {
		return "", err
	}

	var sb strings.Builder
	sb.WriteString(localPart)
	sb.WriteByte('@')

	for {
		ch, ok := p.peekByte()
		if !ok {
			break
		}
		if ch == ' ' || ch == '\t' || ch == '>' {
			break
		}
		if isCTL(ch) {
			return "", fmt.Errorf("control byte in domain")
		}
		p.readByte()
		sb.WriteByte(ch)
	}

	if strings.HasSuffix(sb.String(), "@") {
		return "", fmt.Errorf("domain is empty")
	}

	return sb.String(), nil
}

func (p *parser) parseLocalPart() (string, error) {
	var sb strings.Builder

	if p.acceptByte('"') { // quoted-string
		for {
			ch, ok := p.readByte()
			switch ch {
			case '\\':
				ch, ok = p.readByte()
			case '"':
				return sb.String(), nil
			}
			if !ok {
				return "", fmt.Errorf("malformed quoted-string")
			}
			// Reject control bytes in both qtextSMTP and quoted-pairSMTP
			// (RFC 5321 §4.1.2); ch here is either the literal quoted char
			// or the byte following a backslash escape.
			if isCTL(ch) {
				return "", fmt.Errorf("control byte in quoted-string")
			}
			sb.WriteByte(ch)
		}
	} else { // dot-string
		for {
			ch, ok := p.peekByte()
			if !ok {
				return sb.String(), nil
			}
			switch ch {
			case '@':
				return sb.String(), nil
			case '(', ')', '<', '>', '[', ']', ':', ';', '\\', ',', '"', ' ', '\t':
				return "", fmt.Errorf("malformed dot-string")
			}
			if isCTL(ch) {
				return "", fmt.Errorf("control byte in dot-string")
			}
			p.readByte()
			sb.WriteByte(ch)
		}
	}
}

// isDecimal reports whether s contains one or more ASCII decimal digits.
// strconv's integer parsers alone also accept a leading sign.
func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// parseBdatArgs parses RFC 3030's byte count and optional ASCII LAST marker.
// The current per-chunk implementation limit is 2^32-1 octets; larger messages
// can be split into multiple chunks. See CHUNK-LIMIT-01 in CHECKLIST.md.
func parseBdatArgs(arg string) (uint64, bool, error) {
	args := splitWSP(arg)
	if len(args) == 0 {
		return 0, false, errors.New("Missing chunk size argument")
	}
	if len(args) > 2 {
		return 0, false, errors.New("Too many arguments")
	}
	last := len(args) == 2
	if last && (len(args[1]) != 4 || !strings.EqualFold(args[1], "LAST")) {
		return 0, false, errors.New("Unknown BDAT argument")
	}
	size, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return 0, false, errors.New("Malformed size argument")
	}
	return size, last, nil
}
