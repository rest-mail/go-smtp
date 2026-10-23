package client

import (
	"testing"

	"github.com/rest-mail/go-smtp/pkg/smtp"
)

// checklist: MIME-CLIENT-01 MIME-CLIENT-02 MIME-CLIENT-03 MIME-SYNTAX-02
func TestRFC6152ClientBodyOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		exts []string
		opts *smtp.MailOptions
		want string
	}{
		{"automatic extended", []string{"8BITMIME"}, nil, " BODY=8BITMIME"},
		{"automatic basic", nil, nil, ""},
		{"empty options", []string{"8BITMIME"}, &smtp.MailOptions{}, " BODY=8BITMIME"},
		{"explicit seven bit", []string{"8BITMIME"}, &smtp.MailOptions{Body: smtp.Body7Bit}, " BODY=7BIT"},
		{"basic seven bit", nil, &smtp.MailOptions{Body: smtp.Body7Bit}, ""},
		{"explicit eight bit", []string{"8BITMIME"}, &smtp.MailOptions{Body: smtp.Body8BitMIME}, " BODY=8BITMIME"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, wrote := newMailParamClient(tc.exts...)
			defer c.Close()
			if err := c.Mail("a@example.org", tc.opts); err != nil {
				t.Fatal(err)
			}
			if got, want := wrote.String(), "MAIL FROM:<a@example.org>"+tc.want+"\r\n"; got != want {
				t.Fatalf("wire = %q, want %q", got, want)
			}
		})
	}
	for _, tc := range []struct {
		name string
		exts []string
		body smtp.BodyType
	}{
		{"unadvertised eight bit", nil, smtp.Body8BitMIME},
		{"binary needs BDAT", []string{"8BITMIME", "BINARYMIME", "CHUNKING"}, smtp.BodyBinaryMIME},
		{"unknown", []string{"8BITMIME"}, "8BIT"},
		{"injection", []string{"8BITMIME"}, "7BIT\r\nQUIT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, wrote := newMailParamClient(tc.exts...)
			defer c.Close()
			if err := c.Mail("a@example.org", &smtp.MailOptions{Body: tc.body}); err == nil {
				t.Fatal("unsupported BODY accepted")
			}
			if wrote.Len() != 0 {
				t.Fatalf("invalid BODY wrote %q", wrote.String())
			}
		})
	}
}
