package smtp

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// nopBackend is a minimal Backend used by internal robustness tests.
type nopBackend struct{}

func (nopBackend) NewSession(*Conn) (Session, error) { return nopSession{}, nil }

type nopSession struct{}

func (nopSession) Reset()                          {}
func (nopSession) Logout() error                   { return nil }
func (nopSession) Mail(string, *MailOptions) error { return nil }
func (nopSession) Rcpt(string, *RcptOptions) error { return nil }
func (nopSession) Data(io.Reader) error            { return nil }

// TestStartTLSClosesOnHandshakeFailure verifies that a failed STARTTLS
// handshake closes the connection instead of leaving the command loop running
// on a half-upgraded connection. ReadTimeout is intentionally left at 0 so that
// no idle timeout can mask the behaviour: only the close-on-failure fix can end
// the connection.
func TestStartTLSClosesOnHandshakeFailure(t *testing.T) {
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	s := NewServer(nopBackend{})
	s.Domain = "localhost"
	s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	go s.Serve(ln)
	defer s.Close()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	br := bufio.NewReader(c)

	readLine := func() string {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		return line
	}

	_ = readLine() // greeting
	io.WriteString(c, "EHLO localhost\r\n")
	for !strings.HasPrefix(readLine(), "250 ") {
	}

	io.WriteString(c, "STARTTLS\r\n")
	if line := readLine(); !strings.HasPrefix(line, "220 ") {
		t.Fatalf("expected 220 ready to start TLS, got %q", line)
	}

	// Send a fatal TLS alert record instead of a ClientHello: the server's
	// handshake fails fast (rather than blocking on more handshake bytes)
	// while the client keeps its write side open.
	// Record: type=alert(0x15) version=TLS1.2(0x0303) len=2 {fatal(2), handshake_failure(40)}.
	io.WriteString(c, "\x15\x03\x03\x00\x02\x02\x28")

	// After the failed handshake the server must close the connection. Reading
	// to EOF should therefore complete promptly. Without the fix the server
	// returns to its command loop and (with no ReadTimeout) this read blocks.
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, br)
		done <- err
	}()

	select {
	case <-done:
		// Reached EOF: the connection was closed.
	case <-time.After(3 * time.Second):
		t.Fatal("server did not close the connection after STARTTLS handshake failure")
	}
}

// TestXtextRoundTrip verifies that encodeXtext/decodeXtext round-trip every
// octet value, including 0x80-0xFF which the previous decoder (ParseInt with
// bitSize 8) could not represent.
func TestXtextRoundTrip(t *testing.T) {
	for i := 0; i < 256; i++ {
		raw := string([]byte{byte(i)})
		enc := encodeXtext(raw)
		dec, err := decodeXtext(enc)
		if err != nil {
			t.Fatalf("byte %#02x: decodeXtext(%q) error: %v", i, enc, err)
		}
		if dec != raw {
			t.Fatalf("byte %#02x: round-trip = %q (encoded %q), want %q", i, dec, enc, raw)
		}
	}
}
