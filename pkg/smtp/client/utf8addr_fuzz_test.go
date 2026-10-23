package client

import (
	"testing"

	"github.com/rest-mail/go-smtp/pkg/smtp"
)

// The client puts the fixed encodings on the wire and refuses an
// original recipient that has no RFC 6533 encoding.
//
// checklist: SMTP-EXT-06 UTF8-DSN-01
func TestClientORCPTUTF8Encoding(t *testing.T) {
	c := &Client{ext: map[string]string{"DSN": ""}}
	opts := &smtp.RcptOptions{OriginalRecipientType: smtp.DSNAddressTypeUTF8, OriginalRecipient: `"a\b"@example.com`}
	want := `RCPT TO:<x@example.com> ORCPT=UTF-8;"a\x{5C}b"@example.com`
	if got, err := c.buildRcptCmd("x@example.com", opts); err != nil || got != want {
		t.Errorf("buildRcptCmd = (%q, %v), want %q", got, err, want)
	}
	c.ext["SMTPUTF8"] = ""
	if got, err := c.buildRcptCmd("x@example.com", opts); err != nil || got != want {
		t.Errorf("buildRcptCmd with SMTPUTF8 = (%q, %v), want %q", got, err, want)
	}
	for _, orcpt := range []string{"a\x00b@example.com", "a\xffb@example.com"} {
		opts.OriginalRecipient = orcpt
		if got, err := c.buildRcptCmd("x@example.com", opts); err == nil {
			t.Errorf("buildRcptCmd with ORCPT %q = %q, want an error", orcpt, got)
		}
	}
}
