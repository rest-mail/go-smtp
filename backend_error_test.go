package smtp_test

import (
	"io"
	"strings"
	"testing"

	smtp "github.com/rest-mail/go-smtp"
)

func TestErrorf(t *testing.T) {
	err := smtp.Errorf(550, smtp.EnhancedCode{5, 7, 1}, "rejected: %s", "spam")
	if err.Code != 550 {
		t.Errorf("Code = %d, want 550", err.Code)
	}
	if err.EnhancedCode != (smtp.EnhancedCode{5, 7, 1}) {
		t.Errorf("EnhancedCode = %v, want {5 7 1}", err.EnhancedCode)
	}
	if err.Message != "rejected: spam" {
		t.Errorf("Message = %q, want %q", err.Message, "rejected: spam")
	}
	if got := err.Error(); got != "SMTP error 550: rejected: spam" {
		t.Errorf("Error() = %q", got)
	}
}

// TestBackendErrorf_StatusNotLeaked proves the documented contract: a backend
// returning an *SMTPError (built with Errorf) sets the exact status line, rather
// than being wrapped as the generic "554 ... transaction failed: <raw>" leak
// that a plain error produces.
func TestBackendErrorf_StatusNotLeaked(t *testing.T) {
	_, s, c, scanner := dataLimitServer(t, func(be *backend, s *smtp.Server) {
		be.dataErr = smtp.Errorf(550, smtp.EnhancedCode{5, 7, 1}, "policy: %s", "blocked")
	})
	defer s.Close()
	defer c.Close()

	beginData(t, c, scanner)
	io.WriteString(c, "From: a@example.com\r\n\r\nhi\r\n")
	io.WriteString(c, ".\r\n")

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "550 ") {
		t.Fatalf("a backend *SMTPError must set the status code, got: %q", scanner.Text())
	}
	if !strings.Contains(scanner.Text(), "policy: blocked") {
		t.Fatalf("expected the backend-chosen message, got: %q", scanner.Text())
	}
	if strings.Contains(scanner.Text(), "transaction failed") {
		t.Fatalf("status must not be the generic raw-error leak, got: %q", scanner.Text())
	}
}
