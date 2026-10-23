package rfctest

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/rest-mail/go-smtp/pkg/smtp/client"
)

// expectReply sends cmd and checks that the first reply line starts with want.
func expectReply(t *testing.T, w io.Writer, next func() string, cmd, want string) {
	t.Helper()
	io.WriteString(w, cmd)
	if got := next(); !strings.HasPrefix(got, want) {
		t.Fatalf("%q: got reply %q, want it to start with %q", strings.TrimSpace(cmd), got, want)
	}
}

// RFC 5321 §4.1.4 and §4.1.1: MAIL, RCPT and DATA are refused out of order, and
// a refused command leaves the session usable.
//
// checklist: SMTP-ORD-01 SMTP-ORD-02 SMTP-ORD-03
func TestRFC5321_CommandOrder(t *testing.T) {
	_, s, c, scanner := testServerGreeted(t)
	defer s.Close()
	defer c.Close()
	next := func() string { scanner.Scan(); return scanner.Text() }

	expectReply(t, c, next, "MAIL FROM:<a@example.org>\r\n", "5")
	expectReply(t, c, next, "HELO client.example.org\r\n", "250 ")
	expectReply(t, c, next, "RCPT TO:<b@example.org>\r\n", "5")
	expectReply(t, c, next, "DATA\r\n", "5")
	expectReply(t, c, next, "MAIL FROM:<a@example.org>\r\n", "250 ")
	expectReply(t, c, next, "DATA\r\n", "5") // no recipient yet
	expectReply(t, c, next, "RCPT TO:<b@example.org>\r\n", "250 ")
	expectReply(t, c, next, "DATA\r\n", "354 ")
}

// RFC 5321 §4.1.1.5: RSET clears the sender, the recipients and the message
// data; it is the same after a second EHLO (§4.1.4, "exactly as if a RSET").
//
// checklist: SMTP-RSET-01 SMTP-RSET-02
func TestRFC5321_RsetAndSecondEhloClearTransaction(t *testing.T) {
	for _, clear := range []string{"RSET\r\n", "EHLO again.example.org\r\n"} {
		_, s, c, scanner := testServerGreeted(t)
		next := func() string { scanner.Scan(); return scanner.Text() }
		expectReply(t, c, next, "EHLO client.example.org\r\n", "250")
		for scanner.Text() != "" && !strings.HasPrefix(scanner.Text(), "250 ") {
			next()
		}
		expectReply(t, c, next, "MAIL FROM:<a@example.org>\r\n", "250 ")
		expectReply(t, c, next, "RCPT TO:<b@example.org>\r\n", "250 ")
		io.WriteString(c, clear)
		for {
			line := next()
			if strings.HasPrefix(line, "250 ") {
				break
			}
			if !strings.HasPrefix(line, "250-") {
				t.Fatalf("%q: got %q", strings.TrimSpace(clear), line)
			}
		}
		expectReply(t, c, next, "RCPT TO:<c@example.org>\r\n", "5") // the sender is gone
		expectReply(t, c, next, "MAIL FROM:<a@example.org>\r\n", "250 ")
		c.Close()
		s.Close()
	}
}

// RFC 5321 §2.4: command verbs and the FROM:/TO: keywords are case-insensitive.
//
// checklist: SMTP-SYN-05 SMTP-CMD-02
func TestRFC5321_CommandsCaseInsensitive(t *testing.T) {
	_, s, c, scanner := testServerGreeted(t)
	defer s.Close()
	defer c.Close()
	next := func() string { scanner.Scan(); return scanner.Text() }

	expectReply(t, c, next, "helo client.example.org\r\n", "250 ")
	expectReply(t, c, next, "Mail From:<a@example.org>\r\n", "250 ")
	expectReply(t, c, next, "rCpT tO:<b@example.org>\r\n", "250 ")
	expectReply(t, c, next, "noop\r\n", "250 ")
	expectReply(t, c, next, "quit\r\n", "221 ")
}

// RFC 5321 §3.3 and §4.5.3.1.8: a transaction may have several recipients, and
// a server that limits them answers 452 for the ones over the limit while the
// accepted recipients stay in the transaction.
//
// checklist: SMTP-RCPT-01 SMTP-RCPT-02
func TestRFC5321_RecipientLimit(t *testing.T) {
	be, s, c, scanner := testServerGreeted(t)
	defer s.Close()
	defer c.Close()
	s.MaxRecipients = 2
	next := func() string { scanner.Scan(); return scanner.Text() }

	expectReply(t, c, next, "HELO client.example.org\r\n", "250 ")
	expectReply(t, c, next, "MAIL FROM:<a@example.org>\r\n", "250 ")
	expectReply(t, c, next, "RCPT TO:<b1@example.org>\r\n", "250 ")
	expectReply(t, c, next, "RCPT TO:<b2@example.org>\r\n", "250 ")
	expectReply(t, c, next, "RCPT TO:<b3@example.org>\r\n", "452 4.5.3 ")
	expectReply(t, c, next, "DATA\r\n", "354 ")
	expectReply(t, c, next, "Subject: x\r\n\r\nbody\r\n.\r\n", "250 ")
	if len(be.anonmsgs) != 1 || len(be.anonmsgs[0].To) != 2 {
		t.Fatalf("recipients delivered: %+v", be.anonmsgs)
	}
}

// RFC 5321 §4.5.2: the sender prefixes a leading "." of a line with another; the
// receiver removes one. A lone "." line ends the data, and a line of two dots
// is one dot of content.
//
// checklist: SMTP-DATA-02 SMTP-DATA-03
func TestRFC5321_DotUnstuffing(t *testing.T) {
	be, s, c, scanner := testServerGreeted(t)
	defer s.Close()
	defer c.Close()
	next := func() string { scanner.Scan(); return scanner.Text() }

	expectReply(t, c, next, "HELO client.example.org\r\n", "250 ")
	expectReply(t, c, next, "MAIL FROM:<a@example.org>\r\n", "250 ")
	expectReply(t, c, next, "RCPT TO:<b@example.org>\r\n", "250 ")
	expectReply(t, c, next, "DATA\r\n", "354 ")
	expectReply(t, c, next, "one\r\n..two\r\n...\r\nthree.\r\n..\r\n.\r\n", "250 ")
	if len(be.anonmsgs) != 1 {
		t.Fatalf("got %d messages", len(be.anonmsgs))
	}
	if got, want := string(be.anonmsgs[0].Data), "one\r\n.two\r\n..\r\nthree.\r\n.\r\n"; got != want {
		t.Fatalf("data = %q, want %q", got, want)
	}
}

// RFC 5321 §4.5.3.1.4: a server accepts a command line of 512 octets, the
// terminating CRLF included, and answers a line longer than it supports with a
// 5xx rather than guessing. (The default limit here is 2000.)
//
// checklist: SMTP-LIM-01
func TestRFC5321_CommandLine512(t *testing.T) {
	_, s, c, scanner := testServerGreeted(t)
	defer s.Close()
	defer c.Close()
	next := func() string { scanner.Scan(); return scanner.Text() }

	line := "NOOP " + strings.Repeat("x", 512-len("NOOP \r\n")) + "\r\n"
	if len(line) != 512 {
		t.Fatalf("test line is %d octets", len(line))
	}
	expectReply(t, c, next, line, "250 ")
}

// RFC 5321 §3.8 and §4.2.2: an unknown verb is 500, and the server then still
// answers the next command; VRFY does not need to confirm anything (252); an
// argument that is not allowed (DATA, QUIT) is a 501 where the RFC says so.
//
// checklist: SMTP-CMD-08 SMTP-SYN-09 SMTP-SYN-10
func TestRFC5321_UnknownAndArgumentErrors(t *testing.T) {
	_, s, c, scanner := testServerGreeted(t)
	defer s.Close()
	defer c.Close()
	next := func() string { scanner.Scan(); return scanner.Text() }

	expectReply(t, c, next, "HELO\r\n", "501 ")
	expectReply(t, c, next, "HELO client.example.org\r\n", "250 ")
	expectReply(t, c, next, "FROB\r\n", "500 ")
	expectReply(t, c, next, "NOOP\r\n", "250 ")
	expectReply(t, c, next, "MAIL FROM:<a@example.org>\r\n", "250 ")
	expectReply(t, c, next, "RCPT TO:<b@example.org>\r\n", "250 ")
	expectReply(t, c, next, "DATA junk\r\n", "501 ")
	expectReply(t, c, next, "DATA\r\n", "354 ")
}

// RFC 5321 §4.5.3.1.7 and §4.5.3.1.10: a server accepts at least 100 recipients
// in one transaction.
//
// checklist: SMTP-LIM-04 SMTP-RCPT-01
func TestRFC5321_HundredRecipients(t *testing.T) {
	be, s, c, scanner := testServerGreeted(t)
	defer s.Close()
	defer c.Close()
	next := func() string { scanner.Scan(); return scanner.Text() }

	expectReply(t, c, next, "HELO client.example.org\r\n", "250 ")
	expectReply(t, c, next, "MAIL FROM:<a@example.org>\r\n", "250 ")
	for i := 0; i < 100; i++ {
		expectReply(t, c, next, fmt.Sprintf("RCPT TO:<r%d@example.org>\r\n", i), "250 ")
	}
	expectReply(t, c, next, "DATA\r\n", "354 ")
	expectReply(t, c, next, "x\r\n.\r\n", "250 ")
	if len(be.anonmsgs) != 1 || len(be.anonmsgs[0].To) != 100 {
		t.Fatalf("delivered %+v", be.anonmsgs)
	}
}

// RFC 5321 §4.5.3.1.1–3: a server accepts a local-part of 64 octets, a domain of
// 255 octets and a path of 256 octets.
//
// checklist: SMTP-LIM-03
func TestRFC5321_MinimumAddressSizes(t *testing.T) {
	_, s, c, scanner := testServerGreeted(t)
	defer s.Close()
	defer c.Close()
	next := func() string { scanner.Scan(); return scanner.Text() }

	label := strings.Repeat("d", 63)
	domain := strings.Join([]string{label, label, label, label}, ".") // 255 octets
	local := strings.Repeat("l", 64)
	if len(domain) != 255 {
		t.Fatalf("domain is %d octets", len(domain))
	}
	expectReply(t, c, next, "HELO client.example.org\r\n", "250 ")
	expectReply(t, c, next, "MAIL FROM:<"+local+"@"+domain+">\r\n", "250 ")
	expectReply(t, c, next, "RCPT TO:<"+local+"@"+domain+">\r\n", "250 ")
}

// RFC 5321 §4.5.2: a client doubles a leading "." of every line it sends in
// DATA, and ends the data with a line holding one "."; the server sees the
// original text.
//
// checklist: SMTP-CLI-04
func TestRFC5321_ClientDotStuffing(t *testing.T) {
	be, s, c, _ := testServer(t)
	defer s.Close()
	cl := client.New(c)
	if err := cl.Hello("client.example.org"); err != nil {
		t.Fatal(err)
	}
	if err := cl.Mail("a@example.org", nil); err != nil {
		t.Fatal(err)
	}
	if err := cl.Rcpt("b@example.org", nil); err != nil {
		t.Fatal(err)
	}
	w, err := cl.Data()
	if err != nil {
		t.Fatal(err)
	}
	const body = "one\r\n.two\r\n..\r\n.\r\nthree\r\n"
	if _, err := io.WriteString(w, body); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if len(be.anonmsgs) != 1 || string(be.anonmsgs[0].Data) != body {
		t.Fatalf("server saw %+v, want %q", be.anonmsgs, body)
	}
}
