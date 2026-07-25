package smtp_test

import (
	"io"
	"strings"
	"testing"
)

// TestServerNestedMailRejected verifies that a second MAIL command issued while
// a transaction is already open (a prior MAIL not yet completed by DATA/BDAT nor
// reset by RSET) is rejected with 503 (bad sequence of commands), per
// RFC 5321 §4.1.1.2 / §4.1.4. The in-progress transaction must be left intact:
// its sender and any recipients accepted so far are preserved, and the message
// ultimately delivered carries the ORIGINAL sender — the nested MAIL must not
// clobber it or leak its recipients into a new transaction.
func TestServerNestedMailRejected(t *testing.T) {
	be, s, c, scanner := testServerAuthenticated(t)
	defer s.Close()
	defer c.Close()

	// Open a transaction and accept one recipient.
	io.WriteString(c, "MAIL FROM:<a@example.com>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid first MAIL response:", scanner.Text())
	}
	io.WriteString(c, "RCPT TO:<one@example.com>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid first RCPT response:", scanner.Text())
	}

	// Nested MAIL without an intervening RSET must be rejected with 503.
	io.WriteString(c, "MAIL FROM:<b@example.com>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "503 ") {
		t.Fatalf("nested MAIL FROM: got %q, want 503", scanner.Text())
	}

	// The original transaction must still be open: a further RCPT is accepted
	// and joins transaction A.
	io.WriteString(c, "RCPT TO:<two@example.com>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid second RCPT response:", scanner.Text())
	}

	io.WriteString(c, "DATA\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "354 ") {
		t.Fatal("Invalid DATA response:", scanner.Text())
	}
	io.WriteString(c, "From: a@example.com\r\n\r\nbody\r\n.\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid DATA completion response:", scanner.Text())
	}

	if len(be.messages) != 1 {
		t.Fatalf("got %d messages, want 1", len(be.messages))
	}
	msg := be.messages[0]
	// The sender must be the ORIGINAL one; the nested MAIL must not have
	// clobbered it.
	if msg.From != "a@example.com" {
		t.Fatalf("delivered sender = %q, want %q (nested MAIL clobbered the transaction)", msg.From, "a@example.com")
	}
}

// TestServerResetThenMail verifies that after an explicit RSET the transaction
// is cleared, so a subsequent MAIL FROM is accepted and starts a fresh
// transaction with the new sender.
func TestServerResetThenMail(t *testing.T) {
	be, s, c, scanner := testServerAuthenticated(t)
	defer s.Close()
	defer c.Close()

	io.WriteString(c, "MAIL FROM:<a@example.com>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid first MAIL response:", scanner.Text())
	}
	io.WriteString(c, "RCPT TO:<one@example.com>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid RCPT response:", scanner.Text())
	}

	io.WriteString(c, "RSET\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid RSET response:", scanner.Text())
	}

	// After RSET a new MAIL FROM must be accepted.
	io.WriteString(c, "MAIL FROM:<b@example.com>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatalf("MAIL after RSET: got %q, want 250", scanner.Text())
	}
	io.WriteString(c, "RCPT TO:<two@example.com>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid RCPT after RSET response:", scanner.Text())
	}

	io.WriteString(c, "DATA\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "354 ") {
		t.Fatal("Invalid DATA response:", scanner.Text())
	}
	io.WriteString(c, "From: b@example.com\r\n\r\nbody\r\n.\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid DATA completion response:", scanner.Text())
	}

	if len(be.messages) != 1 {
		t.Fatalf("got %d messages, want 1", len(be.messages))
	}
	msg := be.messages[0]
	if msg.From != "b@example.com" {
		t.Fatalf("delivered sender = %q, want %q", msg.From, "b@example.com")
	}
	// The pre-RSET recipient must not have leaked into the new transaction.
	if len(msg.To) != 1 || msg.To[0] != "two@example.com" {
		t.Fatalf("delivered recipients = %v, want [two@example.com] (RSET must clear recipients)", msg.To)
	}
}
