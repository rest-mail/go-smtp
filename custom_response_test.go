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

// readClosed reports whether the server has closed the connection: after the
// terminating status line, a follow-up command must yield no further response.
func readClosed(t *testing.T, c net.Conn, scanner *bufio.Scanner) bool {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	io.WriteString(c, "NOOP\r\n")
	return !scanner.Scan()
}

// A backend that accepts the sender but returns a custom 2xx line from Mail must
// have the status line delivered AND the transaction advanced, so a following
// RCPT succeeds.
func TestCustomResponse_Mail(t *testing.T) {
	_, s, c, scanner := dataLimitServer(t, func(be *backend, s *smtp.Server) {
		be.userErr = smtp.Errorf(250, smtp.EnhancedCode{2, 1, 0}, "sender OK, throttled")
	})
	defer s.Close()
	defer c.Close()

	io.WriteString(c, "MAIL FROM:<a@example.com>\r\n")
	scanner.Scan()
	if got := scanner.Text(); got != "250 2.1.0 sender OK, throttled" {
		t.Fatalf("MAIL custom success line = %q", got)
	}

	io.WriteString(c, "RCPT TO:<b@example.com>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatalf("RCPT after custom-2xx MAIL should succeed, got %q", scanner.Text())
	}
}

// A custom 2xx line from Rcpt must be delivered AND the recipient recorded, so
// DATA proceeds.
func TestCustomResponse_Rcpt(t *testing.T) {
	_, s, c, scanner := dataLimitServer(t, func(be *backend, s *smtp.Server) {
		be.rcptErr = smtp.Errorf(251, smtp.EnhancedCode{2, 1, 5}, "will forward")
	})
	defer s.Close()
	defer c.Close()

	io.WriteString(c, "MAIL FROM:<a@example.com>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatalf("MAIL: %q", scanner.Text())
	}

	io.WriteString(c, "RCPT TO:<b@example.com>\r\n")
	scanner.Scan()
	if got := scanner.Text(); got != "251 2.1.5 will forward" {
		t.Fatalf("RCPT custom success line = %q", got)
	}

	io.WriteString(c, "DATA\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "354 ") {
		t.Fatalf("DATA after custom-2xx RCPT should proceed, got %q", scanner.Text())
	}
}

// A custom 2xx line from Data replaces the default "250 ... OK: queued" and
// leaves the connection reusable.
func TestCustomResponse_Data(t *testing.T) {
	_, s, c, scanner := dataLimitServer(t, func(be *backend, s *smtp.Server) {
		be.dataErr = smtp.Errorf(250, smtp.EnhancedCode{2, 0, 0}, "OK: queued as XYZ987")
	})
	defer s.Close()
	defer c.Close()

	beginData(t, c, scanner)
	io.WriteString(c, "hi\r\n.\r\n")
	scanner.Scan()
	if got := scanner.Text(); got != "250 2.0.0 OK: queued as XYZ987" {
		t.Fatalf("DATA custom success line = %q", got)
	}

	// Connection must remain usable.
	io.WriteString(c, "NOOP\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatalf("connection not reusable after custom DATA success, got %q", scanner.Text())
	}
}

// CloseConnection wrapping a rejection: the server sends the rejection line and
// then closes the connection.
func TestCloseConnection_Mail(t *testing.T) {
	_, s, c, scanner := dataLimitServer(t, func(be *backend, s *smtp.Server) {
		be.userErr = smtp.CloseConnection(smtp.Errorf(554, smtp.EnhancedCode{5, 7, 1}, "banned sender"))
	})
	defer s.Close()
	defer c.Close()

	io.WriteString(c, "MAIL FROM:<a@example.com>\r\n")
	scanner.Scan()
	if got := scanner.Text(); !strings.HasPrefix(got, "554 5.7.1") {
		t.Fatalf("MAIL rejection line = %q", got)
	}
	if !readClosed(t, c, scanner) {
		t.Fatal("connection must be closed after CloseConnection rejection")
	}
}

// CloseConnection wrapping a rejection from Rcpt closes the connection.
func TestCloseConnection_Rcpt(t *testing.T) {
	_, s, c, scanner := dataLimitServer(t, func(be *backend, s *smtp.Server) {
		be.rcptErr = smtp.CloseConnection(smtp.Errorf(550, smtp.EnhancedCode{5, 7, 1}, "too many bad rcpts"))
	})
	defer s.Close()
	defer c.Close()

	io.WriteString(c, "MAIL FROM:<a@example.com>\r\n")
	scanner.Scan()
	io.WriteString(c, "RCPT TO:<b@example.com>\r\n")
	scanner.Scan()
	if got := scanner.Text(); !strings.HasPrefix(got, "550 5.7.1") {
		t.Fatalf("RCPT rejection line = %q", got)
	}
	if !readClosed(t, c, scanner) {
		t.Fatal("connection must be closed after CloseConnection rejection")
	}
}

// CloseConnection wrapping a rejection from Data sends the line then closes.
func TestCloseConnection_Data(t *testing.T) {
	_, s, c, scanner := dataLimitServer(t, func(be *backend, s *smtp.Server) {
		be.dataErr = smtp.CloseConnection(smtp.Errorf(554, smtp.EnhancedCode{5, 7, 1}, "spam"))
	})
	defer s.Close()
	defer c.Close()

	beginData(t, c, scanner)
	io.WriteString(c, "hi\r\n.\r\n")
	scanner.Scan()
	if got := scanner.Text(); !strings.HasPrefix(got, "554 5.7.1") {
		t.Fatalf("DATA rejection line = %q", got)
	}
	if !readClosed(t, c, scanner) {
		t.Fatal("connection must be closed after CloseConnection rejection")
	}
}

// CloseConnection wrapping a 2xx line: a graceful goodbye — the success line is
// sent, then the connection closes.
func TestCloseConnection_GracefulSuccess(t *testing.T) {
	_, s, c, scanner := dataLimitServer(t, func(be *backend, s *smtp.Server) {
		be.userErr = smtp.CloseConnection(smtp.Errorf(250, smtp.EnhancedCode{2, 1, 0}, "so long"))
	})
	defer s.Close()
	defer c.Close()

	io.WriteString(c, "MAIL FROM:<a@example.com>\r\n")
	scanner.Scan()
	if got := scanner.Text(); got != "250 2.1.0 so long" {
		t.Fatalf("MAIL graceful line = %q", got)
	}
	if !readClosed(t, c, scanner) {
		t.Fatal("connection must be closed after graceful CloseConnection")
	}
}

// CloseConnection(nil) is a no-op and must not terminate the connection.
func TestCloseConnection_NilNoop(t *testing.T) {
	if smtp.CloseConnection(nil) != nil {
		t.Fatal("CloseConnection(nil) must return nil")
	}
}
