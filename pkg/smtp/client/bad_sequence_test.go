package client

import (
	"errors"
	"testing"

	"github.com/rest-mail/go-smtp/pkg/smtp"
)

// checklist: SMTP-ORD-05
func TestClientBadSequenceError(t *testing.T) {
	for _, code := range []string{"502", "503"} {
		for _, command := range []string{"MAIL", "RCPT", "DATA"} {
			t.Run(command+"/"+code, func(t *testing.T) {
				c := scriptedClient(code + " 5.5.1 Bad sequence of commands\r\n250 2.0.0 Reset\r\n")
				var err error
				switch command {
				case "MAIL":
					err = c.Mail("a@example.org", nil)
				case "RCPT":
					err = c.Rcpt("b@example.org", nil)
				case "DATA":
					_, err = c.Data()
				}
				var smtpErr *smtp.SMTPError
				wantCode := 503
				if code == "502" {
					wantCode = 502
				}
				if !errors.As(err, &smtpErr) || smtpErr.Code != wantCode || smtpErr.EnhancedCode != (smtp.EnhancedCode{5, 5, 1}) {
					t.Fatalf("got %v, want %s 5.5.1", err, code)
				}
				if err := c.Reset(); err != nil {
					t.Fatalf("reset after refusal: %v", err)
				}
			})
		}
	}
}
