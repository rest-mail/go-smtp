package smtp

import (
	"bufio"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"
)

// Each subtest exercises a distinct refusal on the wire, including both missing
// prerequisites for DATA/BDAT and commands interleaved with non-LAST chunks.
func TestServerBadSequence(t *testing.T) {
	const mail = "MAIL FROM:<a@example.org>"
	const rcpt = "RCPT TO:<b@example.org>"
	tests := []struct {
		name    string
		setup   []string
		command string
		message string
	}{
		{"MAIL before greeting", nil, mail, "Please introduce yourself first."},
		{"AUTH before greeting", nil, "AUTH PLAIN =", "Please introduce yourself first."},
		{"RCPT before MAIL", []string{"HELO localhost"}, rcpt, "Missing MAIL FROM command."},
		{"DATA before MAIL", []string{"HELO localhost"}, "DATA", "Missing RCPT TO command."},
		{"DATA before RCPT", []string{"HELO localhost", mail}, "DATA", "Missing RCPT TO command."},
		{"BDAT before MAIL", []string{"HELO localhost"}, "BDAT 0 LAST", "Missing RCPT TO command."},
		{"BDAT before RCPT", []string{"HELO localhost", mail}, "BDAT 0 LAST", "Missing RCPT TO command."},
		{"MAIL during BDAT", []string{"HELO localhost", mail, rcpt, "BDAT 0"}, mail, "MAIL not allowed during message transfer"},
		{"RCPT during BDAT", []string{"HELO localhost", mail, rcpt, "BDAT 0"}, rcpt, "RCPT not allowed during message transfer"},
		{"DATA during BDAT", []string{"HELO localhost", mail, rcpt, "BDAT 0"}, "DATA", "DATA not allowed during message transfer"},
		{"XCLIENT during BDAT", []string{"HELO localhost", mail, rcpt, "BDAT 0"}, "XCLIENT ADDR=203.0.113.1", "XCLIENT not allowed during message transfer"},
		{"DATA after BINARYMIME", []string{"HELO localhost", mail + " BODY=BINARYMIME", rcpt}, "DATA", "DATA not allowed for BINARYMIME messages"},
		{"AUTH after MAIL", []string{"HELO localhost", mail}, "AUTH PLAIN =", "AUTH not allowed during mail transaction"},
		{"AUTH during BDAT", []string{"HELO localhost", mail, rcpt, "BDAT 0"}, "AUTH PLAIN =", "AUTH not allowed during mail transaction"},
		{"STARTTLS after MAIL", []string{"HELO localhost", mail}, "STARTTLS", "STARTTLS not allowed during mail transaction"},
		{"STARTTLS during BDAT", []string{"HELO localhost", mail, rcpt, "BDAT 0"}, "STARTTLS", "STARTTLS not allowed during mail transaction"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c, br := newConformanceServer(t, func(s *Server) {
				s.EnableBINARYMIME = true
				s.EnableXCLIENT = true
				s.TrustXCLIENT = func(*Conn) bool { return true }
				s.TLSConfig = &tls.Config{}
			})
			if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			for _, command := range tt.setup {
				writeCmd(t, c, command+"\r\n")
				if line := readSMTPLine(t, br); !strings.HasPrefix(line, "250 ") {
					t.Fatalf("setup %s: got %q, want 250", command, line)
				}
			}
			writeCmd(t, c, tt.command+"\r\n")
			if line := readSMTPLine(t, br); line != "503 5.5.1 "+tt.message {
				t.Fatalf("%s: got %q, want %q", tt.command, line, "503 5.5.1 "+tt.message)
			}

			// A refusal must preserve the current transaction and chunk stream.
			if len(tt.setup) >= 2 {
				if len(tt.setup) == 2 {
					writeCmd(t, c, rcpt+"\r\n")
					if line := readSMTPLine(t, br); !strings.HasPrefix(line, "250 ") {
						t.Fatalf("RCPT after refusal: %q", line)
					}
				}
				writeCmd(t, c, "BDAT 0 LAST\r\n")
				if line := readSMTPLine(t, br); !strings.HasPrefix(line, "250 ") {
					t.Fatalf("complete transaction after refusal: %q", line)
				}
			}
		})
	}
}

func TestServerSTARTTLSAlreadyTLSBadSequence(t *testing.T) {
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatal(err)
	}
	_, raw, br := newConformanceServer(t, func(s *Server) {
		s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	})
	if err := raw.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	drainEHLO(t, raw, br)
	writeCmd(t, raw, "STARTTLS\r\n")
	if line := readSMTPLine(t, br); !strings.HasPrefix(line, "220 ") {
		t.Fatalf("STARTTLS: %q", line)
	}
	c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	br = bufio.NewReader(c)
	drainEHLO(t, c, br)
	writeCmd(t, c, "STARTTLS\r\n")
	if line := readSMTPLine(t, br); line != "503 5.5.1 Already running in TLS" {
		t.Fatalf("repeated STARTTLS: got %q, want 503 5.5.1", line)
	}
}

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
				var smtpErr *SMTPError
				wantCode := 503
				if code == "502" {
					wantCode = 502
				}
				if !errors.As(err, &smtpErr) || smtpErr.Code != wantCode || smtpErr.EnhancedCode != (EnhancedCode{5, 5, 1}) {
					t.Fatalf("got %v, want %s 5.5.1", err, code)
				}
				if err := c.Reset(); err != nil {
					t.Fatalf("reset after refusal: %v", err)
				}
			})
		}
	}
}
