package server

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/rest-mail/go-smtp/pkg/smtp"
	"github.com/rest-mail/go-smtp/pkg/smtp/internal/testcert"
)

type rfc8689Session struct {
	nopSession
	mail chan smtp.MailOptions
	data chan string
}

func (s rfc8689Session) Mail(_ string, opts *smtp.MailOptions) error {
	s.mail <- *opts
	return nil
}
func (s rfc8689Session) Data(r io.Reader) error {
	b, err := io.ReadAll(r)
	s.data <- string(b)
	return err
}

type rfc8689Wire struct {
	raw  net.Conn
	br   *bufio.Reader
	mail chan smtp.MailOptions
	data chan string
}

func newRFC8689Wire(t *testing.T, enabled, encrypted bool) *rfc8689Wire {
	t.Helper()
	w := &rfc8689Wire{mail: make(chan smtp.MailOptions, 16), data: make(chan string, 16)}
	_, w.raw, w.br, _ = newFlushTestConn(t, func(s *Server) {
		s.EnableREQUIRETLS = enabled
		s.TLSConfig = rfc3207TLSConfig(t)
		s.Backend = BackendFunc(func(*Conn) (Session, error) {
			return rfc8689Session{mail: w.mail, data: w.data}, nil
		})
	})
	w.command(t, "EHLO client.example", "250")
	if encrypted {
		w.command(t, "STARTTLS", "220")
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(testcert.LocalhostCert) {
			t.Fatal("invalid test certificate")
		}
		// Use the fixture CA and its actual DNS name; no verification bypass.
		tc := tls.Client(w.raw, &tls.Config{RootCAs: roots, ServerName: "example.com"})
		if err := tc.Handshake(); err != nil {
			t.Fatal(err)
		}
		w.raw, w.br = tc, bufio.NewReader(tc)
		w.command(t, "EHLO client.example", "250")
	}
	return w
}
func (w *rfc8689Wire) command(t *testing.T, cmd, want string) []string {
	t.Helper()
	writeFlushBatch(t, w.raw, cmd+"\r\n")
	reply := readFlushReply(t, w.br)
	if !strings.HasPrefix(reply[0], want+" ") && !strings.HasPrefix(reply[0], want+"-") {
		t.Fatalf("%q = %q, want %s", cmd, reply, want)
	}
	return reply
}
func (w *rfc8689Wire) requireMail(t *testing.T, want bool) {
	t.Helper()
	select {
	case opts := <-w.mail:
		if opts.RequireTLS != want {
			t.Fatalf("RequireTLS = %v, want %v", opts.RequireTLS, want)
		}
	default:
		t.Fatal("MAIL did not reach backend")
	}
}
func (w *rfc8689Wire) deliver(t *testing.T, body string) {
	t.Helper()
	w.command(t, "RCPT TO:<recipient@example.net>", "250")
	w.command(t, "DATA", "354")
	writeFlushBatch(t, w.raw, body+".\r\n")
	if reply := readFlushReply(t, w.br); !strings.HasPrefix(reply[0], "250 ") {
		t.Fatal(reply)
	}
	select {
	case got := <-w.data:
		if got != body {
			t.Fatalf("body = %q, want %q", got, body)
		}
	default:
		t.Fatal("DATA did not reach backend")
	}
	w.command(t, "NOOP", "250")
}

// checklist: REQTLS-EHLO-01
func TestRFC8689Advertisement(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, encrypted := range []bool{false, true} {
			t.Run(fmt.Sprintf("enabled=%v/TLS=%v", enabled, encrypted), func(t *testing.T) {
				w := newRFC8689Wire(t, enabled, encrypted)
				count := 0
				for _, line := range w.command(t, "EHLO client.example", "250") {
					if strings.HasPrefix(line[4:], "REQUIRETLS") {
						count++
						if line[4:] != "REQUIRETLS" {
							t.Fatalf("parameterized capability: %q", line)
						}
					}
				}
				want := 0
				if enabled && encrypted {
					want = 1
				}
				if count != want {
					t.Fatalf("REQUIRETLS count = %d, want %d", count, want)
				}
				if !enabled {
					w.command(t, "MAIL FROM:<a@example.org> REQUIRETLS", "504 5.5.4")
				}
			})
		}
	}
}

// checklist: REQTLS-SYN-01
func TestRFC8689ParameterGrammar(t *testing.T) {
	w := newRFC8689Wire(t, true, true)
	for _, arg := range []string{"REQUIRETLS=", "REQUIRETLS=yes", "REQUIRETLS=No", "REQUIRETLS REQUIRETLS"} {
		w.command(t, "MAIL FROM:<a@example.org> "+arg, "501 5.5.4")
		if len(w.mail) != 0 {
			t.Fatal("invalid parameter reached backend")
		}
		w.command(t, "NOOP", "250")
	}
	w.command(t, "MAIL FROM:<a@example.org> rEqUiReTlS", "250")
	w.requireMail(t, true)
	w.command(t, "RCPT TO:<b@example.org> REQUIRETLS", "500 5.5.4")
	w.deliver(t, "Subject: grammar\r\n\r\nbody\r\n")
}

// checklist: REQTLS-TLS-01
func TestRFC8689ServerRefusesPlaintext(t *testing.T) {
	w := newRFC8689Wire(t, true, false)
	w.command(t, "MAIL FROM:<a@example.org> REQUIRETLS", "530 5.7.0")
	if len(w.mail) != 0 {
		t.Fatal("plaintext REQUIRETLS reached backend")
	}
	w.command(t, "RCPT TO:<b@example.org>", "503")
	w.command(t, "MAIL FROM:<a@example.org>", "250")
	w.requireMail(t, false)
	w.deliver(t, "Subject: ordinary\r\n\r\nallowed plaintext\r\n")
}

// checklist: REQTLS-RECEIVE-01
func TestRFC8689ReceiptAndReset(t *testing.T) {
	w := newRFC8689Wire(t, true, true)
	for _, reset := range []string{"RSET", "EHLO client.example", "DATA"} {
		w.command(t, "MAIL FROM:<a@example.org> REQUIRETLS", "250")
		w.requireMail(t, true)
		if reset == "DATA" {
			// Header interpretation belongs to the host; the explicit envelope bit
			// survives even if the opaque content requests TLS-Required: No.
			w.deliver(t, "TLS-Required: No\r\nSubject: protected\r\n\r\nbody\r\n")
		} else {
			w.command(t, reset, "250")
		}
		w.command(t, "MAIL FROM:<a@example.org>", "250")
		w.requireMail(t, false)
		w.deliver(t, "Subject: next\r\n\r\nno inherited requirement\r\n")
	}
}

// checklist: REQTLS-LEN-01
func TestRFC8689MailLength(t *testing.T) {
	w := newRFC8689Wire(t, true, true)
	prefix, suffix := "MAIL FROM:<", "> REQUIRETLS\r\n"
	from := strings.Repeat("a", 523-len(prefix)-len(suffix)-len("@example.org")) + "@example.org"
	cmd := prefix + from + suffix
	if len(cmd) != 523 {
		t.Fatal(len(cmd))
	}
	w.command(t, strings.TrimSuffix(cmd, "\r\n"), "250")
	w.requireMail(t, true)
	w.deliver(t, "Subject: extended length\r\n\r\nbody\r\n")
}
