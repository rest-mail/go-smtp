package smtp_test

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp"
)

// drainEhlo consumes an EHLO multiline response up to and including the final
// "250 " line.
func drainEhlo(scanner interface {
	Scan() bool
	Text() string
}) {
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "250 ") {
			return
		}
	}
}

// TestServerCloseConcurrent verifies that concurrent calls to Server.Close do
// not race on the internal done channel (previously two callers could both
// close it, panicking with "close of closed channel"). Exactly one caller
// should perform the shutdown; every other caller must observe ErrServerClosed.
func TestServerCloseConcurrent(t *testing.T) {
	const iterations = 200
	const closers = 8

	for i := 0; i < iterations; i++ {
		s := smtp.NewServer(new(backend))

		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make([]error, closers)

		for j := 0; j < closers; j++ {
			wg.Add(1)
			go func(j int) {
				defer wg.Done()
				<-start
				results[j] = s.Close()
			}(j)
		}

		close(start) // release all closers simultaneously
		wg.Wait()

		nonClosed := 0
		for _, err := range results {
			if err != smtp.ErrServerClosed {
				nonClosed++
			}
		}
		if nonClosed != 1 {
			t.Fatalf("iteration %d: expected exactly one non-ErrServerClosed result, got %d", i, nonClosed)
		}
	}
}

// TestDataBodyReadDeadlineRefresh verifies that ReadTimeout is enforced as an
// idle timeout throughout a DATA body transfer, rather than as a single
// absolute deadline measured from the DATA command. A body that is dripped over
// a period longer than ReadTimeout, but with each inter-write gap comfortably
// under it, must be accepted.
func TestDataBodyReadDeadlineRefresh(t *testing.T) {
	_, s, c, scanner := testServerGreeted(t, func(s *smtp.Server) {
		s.ReadTimeout = 250 * time.Millisecond
	})
	defer s.Close()
	defer c.Close()

	io.WriteString(c, "EHLO localhost\r\n")
	drainEhlo(scanner)

	io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatalf("MAIL response: %q", scanner.Text())
	}
	io.WriteString(c, "RCPT TO:<root@gchq.gov.uk>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatalf("RCPT response: %q", scanner.Text())
	}
	io.WriteString(c, "DATA\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "354 ") {
		t.Fatalf("DATA response: %q", scanner.Text())
	}

	// 7 writes at 80ms spacing = ~560ms total, each gap well under the 250ms
	// ReadTimeout. Without deadline refresh the transfer is cut off around
	// 250ms and rejected.
	body := []string{
		"From: root@nsa.gov\r\n",
		"\r\n",
		"line one\r\n",
		"line two\r\n",
		"line three\r\n",
		"line four\r\n",
		"line five\r\n",
	}
	for _, part := range body {
		io.WriteString(c, part)
		time.Sleep(80 * time.Millisecond)
	}
	io.WriteString(c, ".\r\n")

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatalf("expected 250 after dripped body, got %q", scanner.Text())
	}
}

// TestDataReadTimeoutClosesConnection verifies that when a read times out while
// the server is consuming the DATA body it responds 451 4.4.2 and closes the
// connection, rather than returning a generic 554 and leaving the socket open
// (which would cause any further client bytes to be re-parsed as commands).
func TestDataReadTimeoutClosesConnection(t *testing.T) {
	_, s, c, scanner := testServerGreeted(t, func(s *smtp.Server) {
		s.ReadTimeout = 200 * time.Millisecond
	})
	defer s.Close()
	defer c.Close()

	io.WriteString(c, "EHLO localhost\r\n")
	drainEhlo(scanner)

	io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatalf("MAIL response: %q", scanner.Text())
	}
	io.WriteString(c, "RCPT TO:<root@gchq.gov.uk>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatalf("RCPT response: %q", scanner.Text())
	}
	io.WriteString(c, "DATA\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "354 ") {
		t.Fatalf("DATA response: %q", scanner.Text())
	}

	// Send a partial body with no terminator, then stall past ReadTimeout.
	io.WriteString(c, "From: root@nsa.gov\r\npartial body without a terminator")

	if !scanner.Scan() {
		t.Fatalf("expected a response line, got scan error: %v", scanner.Err())
	}
	if got := scanner.Text(); !strings.HasPrefix(got, "451 4.4.2") {
		t.Fatalf("expected 451 4.4.2 timeout response, got %q", got)
	}

	// The connection must be closed: a subsequent read returns EOF, not a
	// timeout (which would indicate the socket was left open).
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected connection to be closed after DATA timeout, but read succeeded")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("connection was left open after DATA timeout: %v", err)
	}
}

// TestDataWrappedSMTPError verifies that a *SMTPError returned wrapped (via %w)
// from Session.Data keeps its code/enhanced-code/message, rather than being
// flattened to a generic 554.
func TestDataWrappedSMTPError(t *testing.T) {
	be, s, c, scanner := testServerGreeted(t)
	defer s.Close()
	defer c.Close()

	be.dataErr = fmt.Errorf("backend wrap: %w", &smtp.SMTPError{
		Code:         501,
		EnhancedCode: smtp.EnhancedCode{5, 5, 1},
		Message:      "custom data failure",
	})

	io.WriteString(c, "EHLO localhost\r\n")
	drainEhlo(scanner)
	io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatalf("MAIL response: %q", scanner.Text())
	}
	io.WriteString(c, "RCPT TO:<root@gchq.gov.uk>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatalf("RCPT response: %q", scanner.Text())
	}
	io.WriteString(c, "DATA\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "354 ") {
		t.Fatalf("DATA response: %q", scanner.Text())
	}
	io.WriteString(c, "hi\r\n.\r\n")
	scanner.Scan()
	if got := scanner.Text(); !strings.HasPrefix(got, "501 5.5.1") {
		t.Fatalf("expected 501 5.5.1 from wrapped SMTPError, got %q", got)
	}
}

// TestMailWrappedSMTPError verifies the same errors.As handling for the
// writeError path (Session.Mail returning a wrapped *SMTPError).
func TestMailWrappedSMTPError(t *testing.T) {
	be, s, c, scanner := testServerGreeted(t)
	defer s.Close()
	defer c.Close()

	be.userErr = fmt.Errorf("backend wrap: %w", &smtp.SMTPError{
		Code:         550,
		EnhancedCode: smtp.EnhancedCode{5, 7, 1},
		Message:      "sender blocked",
	})

	io.WriteString(c, "EHLO localhost\r\n")
	drainEhlo(scanner)
	io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
	scanner.Scan()
	if got := scanner.Text(); !strings.HasPrefix(got, "550 5.7.1") {
		t.Fatalf("expected 550 5.7.1 from wrapped SMTPError, got %q", got)
	}
}
