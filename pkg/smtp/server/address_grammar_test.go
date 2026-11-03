package server

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/rest-mail/go-smtp/pkg/smtp"
)

// expectAddress sends addr as the reverse-path and then as a forward-path,
// and checks the reply to each. want is the full status ("250", or
// "501 5.1.x" for a refusal, which picks 5.1.7 for MAIL and 5.1.3 for RCPT).
func expectAddress(t *testing.T, configure func(*Server), addr, mailParams string, accept bool) {
	t.Helper()
	_, raw, br, _ := newFlushTestConn(t, configure)
	xclientCommand(t, raw, br, "EHLO client.example", "250")
	mailWant, rcptWant := "250", "250"
	if !accept {
		mailWant, rcptWant = "501 5.1.7", "501 5.1.3"
	}
	xclientCommand(t, raw, br, "MAIL FROM:<"+addr+">"+mailParams, mailWant)
	if !accept {
		xclientCommand(t, raw, br, "MAIL FROM:<s@example.org>"+mailParams, "250")
	}
	xclientCommand(t, raw, br, "RCPT TO:<"+addr+">", rcptWant)
}

// RFC 5321 §4.1.2 and §4.1.3: a Domain is LDH labels separated by dots, an
// address literal is an IPv4 address or "IPv6:" and an IPv6 address; a
// General-address-literal needs an IANA-registered tag, and "IPv6" is the
// only one. Anything else is refused with 501: 5.1.7 for the
// sender, 5.1.3 for a recipient (RFC 3463). A 63-octet label and a
// 255-octet domain are accepted (RFC 5321 §4.5.3.1.2); one more octet is not.
//
// checklist: SMTP-AUDIT-39
func TestRFC5321_DomainGrammar(t *testing.T) {
	label63 := strings.Repeat("d", 63)
	domain255 := strings.Join([]string{label63, label63, label63, label63}, ".")
	for _, tc := range []struct {
		domain string
		accept bool
	}{
		{"example.com", true},
		{"EXAMPLE.com", true},
		{"x-1.example", true},
		{"1example.com", true},
		{"localhost", true},
		{label63 + ".example", true},
		{domain255, true},
		{"[192.0.2.1]", true},
		{"[001.002.003.004]", true},
		{"[IPv6:2001:db8::1]", true},
		{"[ipv6:2001:DB8::1]", true},
		{"[IPv6:::ffff:192.0.2.1]", true},

		{"ex_ample.com", false},
		{"-example.com", false},
		{"example-.com", false},
		{"ex..com", false},
		{".example.com", false},
		{"example.com.", false},
		{"exa!mple.com", false},
		{strings.Repeat("d", 64) + ".example", false},
		{domain255 + "d", false},
		{"[]", false},
		{"[192.0.2]", false},
		{"[192.0.2.256]", false},
		{"[192.0.2.1.5]", false},
		{"[1922.0.2.1]", false},
		{"[IPv6:2001:db8::g]", false},
		{"[IPv6:192.0.2.1]", false},
		{"[IPv6:fe80::1%eth0]", false},
		{"[2001:db8::1]", false},
		{"[x-tag:content]", false},
		{"[IPv7:content]", false},
		{"[192.0.2.1", false},
	} {
		t.Run(tc.domain, func(t *testing.T) {
			expectAddress(t, nil, "user@"+tc.domain, "", tc.accept)
		})
	}
}

// RFC 5321 §4.1.2: an unquoted local-part is a Dot-string, Atom *("." Atom)
// with every Atom non-empty, so it does not start or end with a dot or hold
// two in a row. A Quoted-string may hold any of those. A 64-octet
// local-part is accepted (RFC 5321 §4.5.3.1.1); the server sets no limit of
// its own on longer ones, as §4.5.3.1 asks.
//
// checklist: SMTP-AUDIT-105
func TestRFC5321_LocalPartGrammar(t *testing.T) {
	for _, tc := range []struct {
		local  string
		accept bool
	}{
		{"user", true},
		{"first.last", true},
		{"a.b.c", true},
		{"!#$%&'*+-/=?^_`{|}~", true},
		{strings.Repeat("l", 64), true},
		{strings.Repeat("l", 65), true},
		{`"first last"`, true},
		{`".leading..double.trailing."`, true},
		{`"quote\"inside"`, true},
		{`"back\\slash"`, true},

		{".user", false},
		{"user.", false},
		{"first..last", false},
		{".", false},
		{"a.b.", false},
	} {
		t.Run(tc.local, func(t *testing.T) {
			expectAddress(t, nil, tc.local+"@example.com", "", tc.accept)
		})
	}
}

// RFC 6531 §3.3 adds U-labels to sub-domain and UTF-8 to atext, so a UTF-8
// address that is otherwise well formed is accepted with SMTPUTF8, while the
// RFC 5321 dot and hyphen rules still apply to it.
//
// checklist: SMTP-AUDIT-39 SMTP-AUDIT-105
func TestRFC6531_AddressGrammarKeepsUTF8(t *testing.T) {
	utf8 := func(s *Server) { s.EnableSMTPUTF8 = true }
	for _, tc := range []struct {
		addr   string
		accept bool
	}{
		{"用户@例子.广告", true},
		{"jörg.müller@bücher.example", true},
		{"jörg..müller@bücher.example", false},
		{"jörg@bü_cher.example", false},
		{"jörg@-bücher.example", false},
		{"jörg@bücher..example", false},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			expectAddress(t, utf8, tc.addr, " SMTPUTF8", tc.accept)
		})
	}
}

// replyCodeSession answers MAIL with err.
type replyCodeSession struct {
	nopSession
	err error
}

func (s replyCodeSession) Mail(string, *smtp.MailOptions) error { return s.err }

// captureLog is a Logger that keeps what it is given.
type captureLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *captureLog) Printf(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, v...))
}

func (l *captureLog) Println(v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintln(v...))
}

func (l *captureLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// RFC 5321 §4.2.1 and §4.3.2: a reply code is three digits, the first 2, 3,
// 4 or 5. A backend's invalid code is replaced by 451 4.3.0 and logged. RFC
// 3463 §2 / RFC 2034 §3: an enhanced code whose class differs from the reply
// code's first digit, or whose subject or detail is out of range, becomes
// X.0.0; a 3xx reply carries none. A valid backend reply passes unchanged.
//
// checklist: SMTP-AUDIT-43
func TestRFC5321_BackendReplyCodeIsChecked(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    *smtp.SMTPError
		want   string
		logged bool
	}{
		{"valid", &smtp.SMTPError{Code: 553, EnhancedCode: smtp.EnhancedCode{5, 1, 3}, Message: "No"}, "553 5.1.3 No", false},
		{"valid no enhanced", &smtp.SMTPError{Code: 550, EnhancedCode: smtp.NoEnhancedCode, Message: "No"}, "550 No", false},
		{"valid enhanced not set", &smtp.SMTPError{Code: 450, Message: "Later"}, "450 4.0.0 Later", false},
		{"zero", &smtp.SMTPError{Code: 0, Message: "x"}, "451 4.3.0 Internal server error", true},
		{"two digits", &smtp.SMTPError{Code: 55, Message: "x"}, "451 4.3.0 Internal server error", true},
		{"1yz", &smtp.SMTPError{Code: 199, Message: "x"}, "451 4.3.0 Internal server error", true},
		{"6yz", &smtp.SMTPError{Code: 600, Message: "x"}, "451 4.3.0 Internal server error", true},
		{"four digits", &smtp.SMTPError{Code: 5500, Message: "x"}, "451 4.3.0 Internal server error", true},
		{"negative", &smtp.SMTPError{Code: -550, Message: "x"}, "451 4.3.0 Internal server error", true},
		{"class mismatch", &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{4, 1, 1}, Message: "No"}, "550 5.0.0 No", true},
		{"bad class", &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{3, 1, 1}, Message: "No"}, "550 5.0.0 No", true},
		{"subject too large", &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1000, 1}, Message: "No"}, "550 5.0.0 No", true},
		{"negative detail", &smtp.SMTPError{Code: 450, EnhancedCode: smtp.EnhancedCode{4, 1, -2}, Message: "No"}, "450 4.0.0 No", true},
		{"3yz enhanced", &smtp.SMTPError{Code: 354, EnhancedCode: smtp.EnhancedCode{2, 0, 0}, Message: "Go"}, "354 Go", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &captureLog{}
			_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
				s.ErrorLog = log
				s.Backend = BackendFunc(func(*Conn) (Session, error) {
					return replyCodeSession{err: tc.err}, nil
				})
			})
			xclientCommand(t, raw, br, "EHLO client.example", "250")
			writeFlushBatch(t, raw, "MAIL FROM:<a@example.com>\r\n")
			reply := readFlushReply(t, br)
			if len(reply) != 1 || reply[0] != tc.want {
				t.Fatalf("reply = %q, want %q", reply, tc.want)
			}
			if got := log.String() != ""; got != tc.logged {
				t.Fatalf("logged = %v, want %v: %q", got, tc.logged, log.String())
			}
		})
	}
}
