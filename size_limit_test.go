package smtp_test

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp"
)

// dataLimitServer starts a server whose backend and size limit are configured
// BEFORE Serve begins (so field writes happen-before the serving goroutine,
// keeping the race detector quiet), then greets, EHLOs and authenticates the
// client so the caller can drive a MAIL/RCPT/DATA transaction directly.
func dataLimitServer(t *testing.T, configure func(be *backend, s *smtp.Server)) (be *backend, s *smtp.Server, c net.Conn, scanner *bufio.Scanner) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	be = new(backend)
	s = smtp.NewServer(be)
	s.Domain = "localhost"
	s.AllowInsecureAuth = true
	configure(be, s)

	go s.Serve(l)

	c, err = net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	scanner = bufio.NewScanner(c)

	scanner.Scan() // 220 greeting

	io.WriteString(c, "EHLO localhost\r\n")
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "250 ") {
			break
		}
	}

	io.WriteString(c, "AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "235 ") {
		t.Fatal("Invalid AUTH response:", scanner.Text())
	}

	return
}

// beginData drives MAIL/RCPT/DATA and leaves the connection ready to receive
// the message body.
func beginData(t *testing.T, c net.Conn, scanner *bufio.Scanner) {
	t.Helper()

	io.WriteString(c, "MAIL FROM:<a@example.com>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid MAIL response:", scanner.Text())
	}

	io.WriteString(c, "RCPT TO:<b@example.com>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid RCPT response:", scanner.Text())
	}

	io.WriteString(c, "DATA\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "354 ") {
		t.Fatal("Invalid DATA response:", scanner.Text())
	}
}

// F12: MaxMessageBytes is an inclusive ceiling. A message whose delivered size
// is exactly MaxMessageBytes is the largest legal message and must be accepted
// and delivered intact.
func TestServerSizeLimit_ExactlyMaxAccepted(t *testing.T) {
	body := "From: a@example.com\r\n\r\nhello world\r\n"

	be, s, c, scanner := dataLimitServer(t, func(be *backend, s *smtp.Server) {
		s.MaxMessageBytes = int64(len(body))
	})
	defer s.Close()
	defer c.Close()

	beginData(t, c, scanner)
	io.WriteString(c, body)
	io.WriteString(c, ".\r\n")

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatalf("a message of exactly MaxMessageBytes must be accepted, got: %q", scanner.Text())
	}
	if len(be.messages) != 1 {
		t.Fatalf("expected exactly one delivered message, got %d", len(be.messages))
	}
	if string(be.messages[0].Data) != body {
		t.Fatalf("delivered body mismatch:\n got %q\nwant %q", string(be.messages[0].Data), body)
	}
}

// F12: one byte over the ceiling must be rejected 552 and not delivered. Guards
// that the inclusive-ceiling fix doesn't shift the boundary the wrong way.
func TestServerSizeLimit_OverMaxRejected(t *testing.T) {
	body := "From: a@example.com\r\n\r\nhello world\r\n"

	be, s, c, scanner := dataLimitServer(t, func(be *backend, s *smtp.Server) {
		s.MaxMessageBytes = int64(len(body)) - 1 // body is exactly Max+1
	})
	defer s.Close()
	defer c.Close()

	beginData(t, c, scanner)
	io.WriteString(c, body)
	io.WriteString(c, ".\r\n")

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "552 ") {
		t.Fatalf("a message of MaxMessageBytes+1 must be rejected 552, got: %q", scanner.Text())
	}
	if len(be.messages) != 0 {
		t.Fatalf("an over-limit message must not be delivered, got %d", len(be.messages))
	}
}

// F4: a message rejected by the backend while WITHIN the size limit must still
// be drained to the end-of-data marker and the connection left usable for a
// following transaction (the polite, RFC-correct behavior — must not regress).
func TestServerSizeLimit_RejectWithinLimitKeepsConnection(t *testing.T) {
	_, s, c, scanner := dataLimitServer(t, func(be *backend, s *smtp.Server) {
		s.MaxMessageBytes = 1000
		be.dataErr = &smtp.SMTPError{
			Code:         554,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "rejected by policy",
		}
	})
	defer s.Close()
	defer c.Close()

	beginData(t, c, scanner)
	io.WriteString(c, "From: a@example.com\r\n\r\nrejected body\r\n")
	io.WriteString(c, ".\r\n")

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "554 ") {
		t.Fatalf("expected 554 policy rejection, got: %q", scanner.Text())
	}

	// The connection must still be usable: a follow-up MAIL FROM is accepted.
	io.WriteString(c, "MAIL FROM:<c@example.com>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatalf("connection must stay alive after an in-limit rejection, MAIL got: %q", scanner.Text())
	}
}

// F4: a client that exceeds MaxMessageBytes and then keeps streaming past a
// whole additional MaxMessageBytes without ever sending the end-of-data marker
// is abusing the connection. The server must bound the drain, respond 552 and
// close — not read unboundedly (which, on the unfixed code, hangs forever).
func TestServerSizeLimit_OverLimitDrainBounded(t *testing.T) {
	_, s, c, scanner := dataLimitServer(t, func(be *backend, s *smtp.Server) {
		s.MaxMessageBytes = 10
	})
	defer s.Close()
	defer c.Close()

	beginData(t, c, scanner)

	// 30 bytes = 3x the limit, no terminating dot, connection kept open.
	io.WriteString(c, strings.Repeat("x", 30))

	// Bound the wait: unfixed code drains unboundedly and never replies, so this
	// deadline is what turns the hang into a visible test failure.
	c.SetReadDeadline(time.Now().Add(3 * time.Second))

	if !scanner.Scan() {
		t.Fatalf("expected a 552 response after the drain budget was exhausted, got none (server hung?): %v", scanner.Err())
	}
	if !strings.HasPrefix(scanner.Text(), "552 ") {
		t.Fatalf("expected 552 after over-limit bounded drain, got: %q", scanner.Text())
	}

	// The server must close the connection rather than keep draining.
	if scanner.Scan() {
		t.Fatalf("expected the connection to be closed after 552, got more data: %q", scanner.Text())
	}
}
