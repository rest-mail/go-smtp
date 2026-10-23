package client

import (
	"strings"
	"testing"

	"github.com/rest-mail/go-smtp/pkg/smtp"
)

// checklist: UTF8-CLIENT-01 UTF8-CLIENT-02 UTF8-CLIENT-03 UTF8-STATE-01
func TestRFC6531Client(t *testing.T) {
	const intl = "用户@例子.广告"

	c, wrote := newMailParamClient("SMTPUTF8", "8BITMIME")
	if err := c.Mail(intl, nil); err == nil || !strings.Contains(err.Error(), "SMTPUTF8") {
		t.Fatalf("Mail without SMTPUTF8 = %v", err)
	}
	if err := c.Mail(intl, &smtp.MailOptions{}); err == nil {
		t.Fatal("Mail with empty options sent a non-ASCII sender")
	}
	if wrote.Len() != 0 {
		t.Fatalf("refused MAIL wrote %q", wrote.String())
	}
	c.Close()

	c, wrote = newMailParamClient("SMTPUTF8", "8BITMIME")
	if err := c.Mail("a@example.org", nil); err != nil {
		t.Fatal(err)
	}
	wrote.Reset()
	if err := c.Rcpt(intl, nil); err == nil || !strings.Contains(err.Error(), "SMTPUTF8") {
		t.Fatalf("Rcpt without SMTPUTF8 MAIL = %v", err)
	}
	if wrote.Len() != 0 {
		t.Fatalf("refused RCPT wrote %q", wrote.String())
	}
	c.Close()

	// §3.1 item 3: the client ignores parameters on the keyword.
	c, wrote = newMailParamClient("8BITMIME")
	c.ext["SMTPUTF8"] = "FUTURE"
	c.text.R.Reset(strings.NewReader("250 ok\r\n250 ok\r\n250 ok\r\n"))
	if err := c.Mail(intl, &smtp.MailOptions{UTF8: true}); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt(intl, nil); err != nil {
		t.Fatal(err)
	}
	if got, want := wrote.String(), "MAIL FROM:<"+intl+"> BODY=8BITMIME SMTPUTF8\r\nRCPT TO:<"+intl+">\r\n"; got != want {
		t.Fatalf("wire = %q, want %q", got, want)
	}
	// RSET ends the transaction; the next one starts without SMTPUTF8.
	if err := c.Reset(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.buildRcptCmd(intl, nil); err == nil {
		t.Fatal("SMTPUTF8 survived RSET")
	}
	c.Close()
}
