package server

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp/pkg/smtp/client"
)

// checklist: TLS-POLICY-05
func TestRFC3207ClientQuitsAfterRejectedTLS(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() { clientSide.Close(); serverSide.Close() })
	cfg := rfc3207TLSConfig(t)
	done := make(chan error, 1)
	go func() {
		defer serverSide.Close()
		br := bufio.NewReader(serverSide)
		for _, step := range []struct{ command, reply string }{
			{"", "220 localhost\r\n"},
			{"EHLO localhost\r\n", "250-localhost\r\n250 STARTTLS\r\n"},
			{"STARTTLS\r\n", "220 ready\r\n"},
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
		tc := tls.Server(serverSide, cfg)
		if err := tc.Handshake(); err != nil {
			done <- err
			return
		}
		// RFC 3207 §4.1: the first command after a negotiation the client
		// rejects is QUIT, not another EHLO.
		line, err := bufio.NewReader(tc).ReadString('\n')
		if err != nil {
			done <- err
			return
		}
		if line != "QUIT\r\n" {
			done <- fmt.Errorf("first command over TLS = %q, want QUIT", line)
			return
		}
		if _, err := io.WriteString(tc, "221 bye\r\n"); err != nil {
			done <- err
			return
		}
		// Read until the client closes, absorbing its close_notify.
		_, err = io.Copy(io.Discard, tc)
		done <- err
	}()
	if err := clientSide.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	c, err := client.NewStartTLS(clientSide, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed test certificate
	if err != nil {
		t.Fatal(err)
	}
	// The host inspects the completed negotiation and finds it too weak.
	if state, ok := c.TLSConnectionState(); !ok || !state.HandshakeComplete {
		t.Fatalf("TLS state = %v, %+v", ok, state)
	}
	if err := c.Quit(); err != nil {
		t.Fatalf("QUIT after rejected TLS: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server never saw QUIT")
	}
}

// checklist: TLS-STATE-06
func TestRFC3207CapabilitiesChangeAfterTLS(t *testing.T) {
	_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
		s.TLSConfig = rfc3207TLSConfig(t)
		s.AllowInsecureAuth = false
	})
	ehlo := func(conn net.Conn, br *bufio.Reader) []string {
		t.Helper()
		writeFlushBatch(t, conn, "EHLO client.example\r\n")
		return readFlushReply(t, br)
	}
	before := strings.Join(ehlo(raw, br), "\n")
	if strings.Contains(before, "AUTH") || !strings.Contains(before, "STARTTLS") {
		t.Fatalf("plaintext capabilities: %q", before)
	}
	writeFlushBatch(t, raw, "STARTTLS\r\n")
	if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, "220 ") {
		t.Fatalf("STARTTLS: %q", got)
	}
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed test certificate
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	tbr := bufio.NewReader(tc)
	after := ehlo(tc, tbr)
	if !containsLine(after, "250-AUTH PLAIN") && !containsLine(after, "250 AUTH PLAIN") {
		t.Fatalf("AUTH not offered over TLS: %q", after)
	}
	if strings.Contains(strings.Join(after, "\n"), "STARTTLS") {
		t.Fatalf("STARTTLS offered over TLS: %q", after)
	}
	writeFlushBatch(t, tc, "AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk\r\n")
	if got := readFlushReply(t, tbr)[0]; !strings.HasPrefix(got, "235 ") {
		t.Fatalf("AUTH over TLS: %q", got)
	}
}
