package server

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp/pkg/smtp"
	"github.com/rest-mail/go-smtp/pkg/smtp/client"
	"github.com/rest-mail/go-smtp/pkg/smtp/internal/testcert"
)

func rfc3207TLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	cert, err := tls.X509KeyPair(testcert.LocalhostCert, testcert.LocalhostKey)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

// checklist: TLS-SYNTAX-02
func TestRFC3207RejectsParameters(t *testing.T) {
	for _, command := range []string{"STARTTLS ignored", "sTaRtTlS extra", "STARTTLS  x=y", "STARTTLS \u0085"} {
		t.Run(command, func(t *testing.T) {
			_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
				s.TLSConfig = rfc3207TLSConfig(t)
			})
			writeFlushBatch(t, raw, command+"\r\n")
			if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, "501 ") {
				t.Fatalf("%q: got %q, want 501", command, got)
			}
			writeFlushBatch(t, raw, "NOOP\r\n")
			if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, "250 ") {
				t.Fatalf("session after syntax error: %q", got)
			}
		})
	}
}

type rfc3207Session struct {
	flushAuthSession
	loggedOut chan struct{}
}

func (s rfc3207Session) Logout() error {
	close(s.loggedOut)
	return nil
}

// checklist: TLS-SYNTAX-01 TLS-STATE-01 TLS-STATE-04 TLS-STATE-05 TLS-EXAMPLE-01
func TestRFC3207ServerDiscardsKnowledge(t *testing.T) {
	type snapshot struct {
		host  string
		tls   bool
		proxy *XClientAttrs
	}
	snapshots := make(chan snapshot, 2)
	logouts := make(chan chan struct{}, 2)
	_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
		s.TLSConfig = rfc3207TLSConfig(t)
		s.EnableXCLIENT = true
		s.TrustXCLIENT = func(*Conn) bool { return true }
		s.Backend = BackendFunc(func(c *Conn) (Session, error) {
			state, ok := c.TLSConnectionState()
			snapshots <- snapshot{c.Hostname(), ok && state.HandshakeComplete, c.XClient()}
			logout := make(chan struct{})
			logouts <- logout
			return rfc3207Session{loggedOut: logout}, nil
		})
	})
	command := func(line string, code string) []string {
		t.Helper()
		writeFlushBatch(t, raw, line+"\r\n")
		reply := readFlushReply(t, br)
		if !strings.HasPrefix(reply[0], code+" ") && !strings.HasPrefix(reply[0], code+"-") {
			t.Fatalf("%s: %q, want %s", line, reply, code)
		}
		return reply
	}
	command("XCLIENT ADDR=203.0.113.1 LOGIN=old", "220")
	caps := command("EHLO before.example", "250")
	if !containsLine(caps, "250-STARTTLS") && !containsLine(caps, "250 STARTTLS") {
		t.Fatalf("missing bare STARTTLS keyword: %q", caps)
	}
	before := <-snapshots
	oldLogout := <-logouts
	if before.host != "before.example" || before.tls || before.proxy == nil {
		t.Fatalf("pre-TLS session: %+v", before)
	}
	command("AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk", "235")
	command("STARTTLS", "220")
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed test certificate
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	br = bufio.NewReader(tc)
	writeFlushBatch(t, tc, "MAIL FROM:<a@example.org>\r\n")
	if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, "503 ") {
		t.Fatalf("MAIL before fresh EHLO: %q", got)
	}
	select {
	case <-oldLogout:
	default:
		t.Fatal("old session was not logged out")
	}
	writeFlushBatch(t, tc, "EHLO after.example\r\n")
	caps = readFlushReply(t, br)
	if strings.Contains(strings.Join(caps, "\n"), "STARTTLS") {
		t.Fatalf("STARTTLS advertised over TLS: %q", caps)
	}
	after := <-snapshots
	if after.host != "after.example" || !after.tls || after.proxy != nil {
		t.Fatalf("post-TLS session: %+v", after)
	}
	writeFlushBatch(t, tc, "AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk\r\n")
	if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, "235 ") {
		t.Fatalf("pre-TLS authentication survived: %q", got)
	}
}

// checklist: TLS-POLICY-01
func TestRFC3207PlaintextDelivery(t *testing.T) {
	_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
		s.TLSConfig = rfc3207TLSConfig(t)
	})
	// Advertising STARTTLS must not by itself require TLS for local delivery.
	for _, step := range []struct{ command, code string }{
		{"HELO client.example", "250"},
		{"MAIL FROM:<a@example.org>", "250"},
		{"RCPT TO:<b@example.org>", "250"},
		{"DATA", "354"},
		{"Subject: example\r\n\r\nbody\r\n.", "250"},
	} {
		writeFlushBatch(t, raw, step.command+"\r\n")
		if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, step.code+" ") {
			t.Fatalf("%s: %q, want %s", step.command, got, step.code)
		}
	}
}

// checklist: TLS-REPLY-02
func TestRFC3207ClientTemporaryRefusal(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() { clientSide.Close(); serverSide.Close() })
	done := make(chan error, 1)
	go func() {
		defer serverSide.Close()
		br := bufio.NewReader(serverSide)
		for _, step := range []struct{ command, reply string }{
			{"", "220 localhost\r\n"},
			{"EHLO localhost\r\n", "250-localhost\r\n250 STARTTLS\r\n"},
			{"STARTTLS\r\n", "454 TLS temporarily unavailable\r\n"},
		} {
			if step.command != "" {
				line, err := br.ReadString('\n')
				if err != nil {
					done <- err
					return
				}
				if line != step.command {
					done <- fmt.Errorf("command = %q, want %q", line, step.command)
					return
				}
			}
			if _, err := io.WriteString(serverSide, step.reply); err != nil {
				done <- err
				return
			}
		}
		// A TLS-required constructor must close, never send mail in plaintext.
		extra, err := io.ReadAll(br)
		if len(extra) != 0 {
			err = fmt.Errorf("plaintext after TLS refusal: %q", extra)
		}
		done <- err
	}()
	if err := clientSide.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	client, err := client.NewStartTLS(clientSide, nil)
	var smtpErr *smtp.SMTPError
	if client != nil {
		client.Close()
	}
	if client != nil || !errors.As(err, &smtpErr) || smtpErr.Code != 454 {
		t.Fatalf("constructor returned (%v, %v), want nil client and SMTP error 454", client, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("constructor did not close after TLS refusal")
	}
}

func containsLine(lines []string, want string) bool {
	for _, line := range lines {
		if line == want {
			return true
		}
	}
	return false
}
