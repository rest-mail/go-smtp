package client

import (
	"errors"
	"io"
	"testing"

	"github.com/rest-mail/go-smtp/pkg/smtp"
)

// RFC 5321 §4.2 reply grammar: the text of a reply line is optional, so a line
// may be a bare code ("250"), a bare continuation ("250-") or a code and a space
// ("250 "). §4.2.1: a client must accept a reply with no text at all. Bare codes
// are accepted as single-line replies and as the last line of a multiline one,
// for success and for failure, synchronously and pipelined.
//
// checklist: SMTP-CLI-11
func TestRFC5321_ClientAcceptsBareCodes(t *testing.T) {
	c, wrote := newScriptedClient("220\r\n" + // greeting
		"250-\r\n250-PIPELINING\r\n250-8BITMIME\r\n250\r\n" + // EHLO, bare first and last lines
		"250\r\n" + // MAIL
		"550\r\n" + // RCPT, bare failure
		"250 \r\n" + // RCPT, code and space
		"354\r\n" + // DATA
		"250\r\n" + // end of data
		"250\r\n" + // pipelined RSET
		"250-\r\n250\r\n" + // pipelined MAIL, multiline of bare lines
		"451-try\r\n451\r\n" + // pipelined RCPT, multiline failure ending bare
		"250\r\n" + // NOOP
		"221\r\n") // QUIT

	if ok, _ := c.Extension("PIPELINING"); !ok {
		t.Fatal("PIPELINING not parsed from an EHLO reply with bare lines")
	}
	if ok, _ := c.Extension("8BITMIME"); !ok {
		t.Fatal("8BITMIME not parsed from an EHLO reply with bare lines")
	}
	if err := c.Mail("a@example.org", nil); err != nil {
		t.Fatalf("MAIL 250: %v", err)
	}
	var smtpErr *smtp.SMTPError
	if err := c.Rcpt("bad@example.org", nil); !errors.As(err, &smtpErr) || smtpErr.Code != 550 || smtpErr.Message != "" {
		t.Fatalf("RCPT bare 550: %v, want an SMTPError 550 with no text", err)
	}
	if err := c.Rcpt("b@example.org", nil); err != nil {
		t.Fatalf("RCPT \"250 \": %v", err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatalf("DATA bare 354: %v", err)
	}
	io.WriteString(w, "hi\r\n")
	if err := w.Close(); err != nil {
		t.Fatalf("end of data bare 250: %v", err)
	}

	p, err := c.Pipeline()
	if err != nil {
		t.Fatal(err)
	}
	p.Reset()
	p.Mail("a@example.org", nil)
	p.Rcpt("c@example.org", nil)
	errs := p.Wait()
	if len(errs) != 3 || errs[0] != nil || errs[1] != nil {
		t.Fatalf("pipelined results %v, want RSET and MAIL accepted", errs)
	}
	if !errors.As(errs[2], &smtpErr) || smtpErr.Code != 451 || smtpErr.Message != "try\n" {
		t.Fatalf("pipelined RCPT: %#v, want 451 with both lines' text", errs[2])
	}

	if err := c.Noop(); err != nil {
		t.Fatalf("NOOP bare 250: %v", err)
	}
	if err := c.Quit(); err != nil {
		t.Fatalf("QUIT bare 221: %v", err)
	}
	if got := wrote.String(); got[len(got)-6:] != "QUIT\r\n" {
		t.Fatalf("session did not end with QUIT: %q", got)
	}
}

// The grammar still has a shape: a code must be three digits, and anything
// after them other than nothing, a space or a hyphen is not a reply line.
//
// checklist: SMTP-CLI-11
func TestRFC5321_ClientRejectsMalformedReplyLines(t *testing.T) {
	for _, line := range []string{"25", "2500", "25a", "abc", "250x text", "099 low", ""} {
		c, _ := newScriptedClient(line + "\r\n")
		err := c.Noop()
		var smtpErr *smtp.SMTPError
		if err == nil || errors.As(err, &smtpErr) {
			t.Errorf("greeting %q: %v, want a protocol error", line, err)
		}
	}
}

// Every optional-text form of a reply line parses to its code, text and
// whether more lines follow.
//
// checklist: SMTP-CLI-11
func TestParseReplyLine(t *testing.T) {
	for _, tc := range []struct {
		line      string
		code      int
		continued bool
		message   string
	}{
		{"250", 250, false, ""},
		{"250 ", 250, false, ""},
		{"250-", 250, true, ""},
		{"250-mx", 250, true, "mx"},
		{"250 2.0.0 OK", 250, false, "2.0.0 OK"},
	} {
		code, continued, message, err := parseReplyLine(tc.line, 2)
		if err != nil || code != tc.code || continued != tc.continued || message != tc.message {
			t.Errorf("parseReplyLine(%q) = %d, %v, %q, %v; want %d, %v, %q", tc.line,
				code, continued, message, err, tc.code, tc.continued, tc.message)
		}
	}
}
