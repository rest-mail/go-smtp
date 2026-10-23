package rfctest

import (
	"io"
	"strings"
	"testing"

	"github.com/rest-mail/go-smtp/pkg/smtp"
)

// RFC 5321 §3.6.1 and §4.1.1.3: a server MUST be prepared for a source route
// in the forward-path and SHOULD ignore it. The backend receives only the
// mailbox; the route's hosts are not relayed through.
//
// checklist: SMTP-RCPT-03
func TestRFC5321_SourceRouteIgnored(t *testing.T) {
	be, s, c, scanner := testServerGreeted(t)
	defer s.Close()
	defer c.Close()
	next := func() string { scanner.Scan(); return scanner.Text() }

	expectReply(t, c, next, "HELO client.example.org\r\n", "250 ")
	expectReply(t, c, next, "MAIL FROM:<@relay.example.org:a@example.org>\r\n", "250 ")
	expectReply(t, c, next, "RCPT TO:<@hosta.example.org,@hostb.example.org:b@example.org>\r\n", "250 ")
	expectReply(t, c, next, "RCPT TO:<@[192.0.2.1]:c@example.org>\r\n", "250 ")
	expectReply(t, c, next, "DATA\r\n", "354 ")
	expectReply(t, c, next, "Subject: x\r\n\r\nhi\r\n.\r\n", "250 ")

	if len(be.anonmsgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(be.anonmsgs))
	}
	msg := be.anonmsgs[0]
	if msg.From != "a@example.org" {
		t.Errorf("From = %q, want the mailbox without its route", msg.From)
	}
	if len(msg.To) != 2 || msg.To[0] != "b@example.org" || msg.To[1] != "c@example.org" {
		t.Errorf("To = %q, want the mailboxes without their routes", msg.To)
	}
}

// RFC 5321 §3.3: when every RCPT was rejected, DATA gets 503 or 554, and the
// message data that follows is not taken as the message (it is read as
// commands, each refused).
//
// checklist: SMTP-DATA-08
func TestRFC5321_DataAfterAllRecipientsRejected(t *testing.T) {
	be, s, c, scanner := testServerGreeted(t)
	defer s.Close()
	defer c.Close()
	be.rcptErr = &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "no such user"}
	next := func() string { scanner.Scan(); return scanner.Text() }

	expectReply(t, c, next, "HELO client.example.org\r\n", "250 ")
	expectReply(t, c, next, "MAIL FROM:<a@example.org>\r\n", "250 ")
	expectReply(t, c, next, "RCPT TO:<b@example.org>\r\n", "550 ")
	expectReply(t, c, next, "RCPT TO:<c@example.org>\r\n", "550 ")
	io.WriteString(c, "DATA\r\n")
	if got := next(); !strings.HasPrefix(got, "503 ") && !strings.HasPrefix(got, "554 ") {
		t.Fatalf("DATA with no accepted recipient: got %q, want 503 or 554", got)
	}
	expectReply(t, c, next, "hi\r\n", "5")
	expectReply(t, c, next, "NOOP\r\n", "250 ")
	if len(be.anonmsgs) != 0 {
		t.Errorf("backend got %d messages, want none", len(be.anonmsgs))
	}
}
