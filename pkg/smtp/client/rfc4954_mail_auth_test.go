package client

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/rest-mail/go-smtp/pkg/smtp"
)

// RFC 4954 §5: the client sends the submitter as xtext, an unknown submitter
// as AUTH=<> (never an empty value), and drops the parameter when the server
// did not advertise AUTH.
// checklist: SMTP-AUTH-30
func TestRFC4954_ClientMailAuthParameter(t *testing.T) {
	cases := []struct {
		auth      string
		advertise bool
		want      string
	}{
		{"", true, "MAIL FROM:<a@example.org> AUTH=<>\r\n"},
		{"e=mc2@example.com", true, "MAIL FROM:<a@example.org> AUTH=e+3Dmc2@example.com\r\n"},
		{"user+tag@example.com", true, "MAIL FROM:<a@example.org> AUTH=user+2Btag@example.com\r\n"},
		{"\"john doe\"@example.com", true, "MAIL FROM:<a@example.org> AUTH=\"john+20doe\"@example.com\r\n"},
		{"", false, "MAIL FROM:<a@example.org>\r\n"},
		{"e=mc2@example.com", false, "MAIL FROM:<a@example.org>\r\n"},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%t/%q", tc.advertise, tc.auth), func(t *testing.T) {
			var wrote bytes.Buffer
			c := New(faker{ReadWriter: struct {
				io.Reader
				io.Writer
			}{strings.NewReader("220 ready\r\n250 ok\r\n"), &wrote}})
			if err := c.greet(); err != nil {
				t.Fatal(err)
			}
			c.didHello = true
			c.ext = map[string]string{}
			if tc.advertise {
				c.ext["AUTH"] = "PLAIN"
			}
			auth := tc.auth
			if err := c.Mail("a@example.org", &smtp.MailOptions{Auth: &auth}); err != nil {
				t.Fatal(err)
			}
			if got := wrote.String(); got != tc.want {
				t.Fatalf("wrote %q, want %q", got, tc.want)
			}
		})
	}
}
