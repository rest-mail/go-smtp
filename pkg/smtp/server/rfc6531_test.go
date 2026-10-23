package server

import (
	"strings"
	"testing"

	"github.com/rest-mail/go-smtp/pkg/smtp"
	"github.com/rest-mail/go-smtp/pkg/smtp/internal/wire"
)

type rfc6531Session struct {
	nopSession
	got chan string
}

func (s rfc6531Session) Mail(from string, opts *smtp.MailOptions) error {
	if opts.UTF8 {
		from += " +SMTPUTF8"
	}
	s.got <- "MAIL " + from
	return nil
}

func (s rfc6531Session) Rcpt(to string, _ *smtp.RcptOptions) error {
	s.got <- "RCPT " + to
	return nil
}

// rfc6531Conn returns a greeted connection after EHLO, with its capabilities.
func rfc6531Conn(t *testing.T, enable bool) (command func(string, string) []string, caps []string, got chan string) {
	t.Helper()
	got = make(chan string, 16)
	_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
		s.EnableSMTPUTF8 = enable
		s.Backend = BackendFunc(func(*Conn) (Session, error) { return rfc6531Session{got: got}, nil })
	})
	command = func(command, want string) []string {
		t.Helper()
		writeFlushBatch(t, raw, command+"\r\n")
		reply := readFlushReply(t, br)
		if !strings.HasPrefix(reply[0], want) {
			t.Fatalf("%q reply = %q, want %s", command, reply, want)
		}
		return reply
	}
	caps = command("EHLO client.example", "250")
	return command, caps, got
}

// checklist: UTF8-EHLO-01 UTF8-EHLO-02
func TestRFC6531Advertisement(t *testing.T) {
	for _, enable := range []bool{true, false} {
		_, caps, _ := rfc6531Conn(t, enable)
		var utf8, eightBit int
		for _, cap := range caps {
			switch {
			case strings.HasPrefix(cap[4:], "SMTPUTF8"):
				utf8++
				if cap[4:] != "SMTPUTF8" {
					t.Fatalf("parameter on SMTPUTF8 advertisement: %q", cap)
				}
			case cap[4:] == "8BITMIME":
				eightBit++
			}
		}
		if want := map[bool]int{true: 1, false: 0}[enable]; utf8 != want {
			t.Fatalf("enable=%v: SMTPUTF8 advertisements = %d, want %d", enable, utf8, want)
		}
		if enable && eightBit != 1 {
			t.Fatalf("SMTPUTF8 advertised without 8BITMIME: %q", caps)
		}
	}
}

// checklist: UTF8-MAIL-01 UTF8-MAIL-02 UTF8-ADDR-01 UTF8-ADDR-02 UTF8-ADDR-03 UTF8-STATE-01
func TestRFC6531ServerEnvelope(t *testing.T) {
	command, _, got := rfc6531Conn(t, true)
	expect := func(want string) {
		t.Helper()
		if g := <-got; g != want {
			t.Fatalf("session saw %q, want %q", g, want)
		}
	}

	// §3.1 item 4: the MAIL parameter does not accept a value.
	command("MAIL FROM:<élisa@exämple.org> SMTPUTF8=yes", "501 5.5.4")

	// §3.2: a UTF-8 string in every mailbox position, unchanged.
	command("MAIL FROM:<élisa@exämple.org> smtputf8", "250 ")
	expect("MAIL élisa@exämple.org +SMTPUTF8")
	command("RCPT TO:<用户@例子.广告>", "250 ")
	expect("RCPT 用户@例子.广告")
	command("RCPT TO:<ascii@example.org>", "250 ")
	expect("RCPT ascii@example.org")
	// RFC 3629 UTF-8 only; invalid octets are not a mailbox.
	command("RCPT TO:<\xff@example.org>", "501 5.5.2")

	// §3.5: without SMTPUTF8 on MAIL, a non-ASCII address is refused with
	// 550 (sender) or 553 (recipient) and X.6.7.
	command("RSET", "250 ")
	command("MAIL FROM:<élisa@exämple.org>", "550 5.6.7")
	command("MAIL FROM:<a@example.org> BODY=8BITMIME", "250 ")
	expect("MAIL a@example.org")
	command("RCPT TO:<用户@例子.广告>", "553 5.6.7")
	// The flag belongs to the transaction: a later SMTPUTF8 MAIL needs RSET first,
	// and a new MAIL without it does not inherit the previous one.
	command("RSET", "250 ")
	command("MAIL FROM:<a@example.org> SMTPUTF8", "250 ")
	expect("MAIL a@example.org +SMTPUTF8")
	command("RSET", "250 ")
	command("MAIL FROM:<a@example.org>", "250 ")
	expect("MAIL a@example.org")
	command("RCPT TO:<用户@例子.广告>", "553 5.6.7")
	command("RCPT TO:<b@example.org>", "250 ")
	expect("RCPT b@example.org")
}

// checklist: UTF8-MAIL-01 UTF8-MAIL-02 UTF8-MAIL-03 UTF8-STATE-01
func TestRFC6531ServerParameterValue(t *testing.T) {
	command, _, got := rfc6531Conn(t, true)
	for _, parameter := range []string{
		"SMTPUTF8=", "sMtPuTf8=", "SMTPUTF8=yes", "SMTPUTF8==",
		"SIZE=0 SMTPUTF8=", "SMTPUTF8= BODY=8BITMIME",
		"SMTPUTF8=\tSIZE=0", "SMTPUTF8= SMTPUTF8",
	} {
		command("MAIL FROM:<a@example.org> "+parameter, "501 5.5.4")
		select {
		case call := <-got:
			t.Fatalf("refused parameter %q reached backend: %q", parameter, call)
		default:
		}
		// A refused parameter must not begin a transaction or enable UTF-8.
		command("RCPT TO:<b@example.org>", "503 ")
		command("MAIL FROM:<élisa@example.org>", "550 5.6.7")
	}

	// Both bare spellings remain valid and start a usable UTF-8 transaction.
	for _, parameter := range []string{"SMTPUTF8", "sMtPuTf8"} {
		command("MAIL FROM:<élisa@example.org> "+parameter, "250 ")
		if call := <-got; call != "MAIL élisa@example.org +SMTPUTF8" {
			t.Fatalf("bare parameter reached backend as %q", call)
		}
		command("RCPT TO:<用户@example.org>", "250 ")
		if call := <-got; call != "RCPT 用户@example.org" {
			t.Fatalf("UTF-8 recipient reached backend as %q", call)
		}
		command("RSET", "250 ")
	}
}

// checklist: UTF8-ADDR-02 UTF8-MAIL-02
func TestRFC6531ServerDisabled(t *testing.T) {
	command, _, _ := rfc6531Conn(t, false)
	command("MAIL FROM:<a@example.org> SMTPUTF8", "504 ")
	command("MAIL FROM:<élisa@exämple.org>", "550 5.6.7")
}

// checklist: UTF8-VRFY-01
func TestRFC6531VrfyRepliesStayASCII(t *testing.T) {
	command, _, _ := rfc6531Conn(t, true)
	for line, want := range map[string]string{
		"VRFY élisa SMTPUTF8": "252 ", "VRFY élisa": "252 ",
		"EXPN listé SMTPUTF8": "502 ", "EXPN listé": "502 ",
	} {
		for _, reply := range command(line, want) {
			if !wire.IsASCII(reply) {
				t.Fatalf("%q reply %q is not ASCII", line, reply)
			}
		}
	}
}
