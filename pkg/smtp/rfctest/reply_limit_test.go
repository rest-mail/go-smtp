package rfctest

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp/pkg/smtp"
	"github.com/rest-mail/go-smtp/pkg/smtp/server"
)

// A backend's long custom status must not put an oversized line on the wire.
// The success/failure code and transaction state must survive truncation.
//
// checklist: SMTP-LIM-06 SMTP-REP-03
func TestRFC5321_BackendReplyLine512(t *testing.T) {
	for _, code := range []int{250, 450, 550} {
		_, s, c, scanner := dataLimitServer(t, func(be *backend, s *server.Server) {
			be.userErr = smtp.Errorf(code, smtp.EnhancedCode{code / 100, 1, 0}, strings.Repeat("x", 4096))
		})
		t.Cleanup(func() { s.Close() })
		t.Cleanup(func() { c.Close() })
		if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(c, "MAIL FROM:<a@example.com>\r\n"); err != nil {
			t.Fatal(err)
		}
		if !scanner.Scan() {
			t.Fatalf("MAIL reply missing: %v", scanner.Err())
		}
		wantPrefix := fmt.Sprintf("%d %d.1.0 ", code, code/100)
		// Scanner strips CRLF; the two terminator octets still count.
		if got := scanner.Text(); len(got)+2 != 512 || !strings.HasPrefix(got, wantPrefix) {
			t.Fatalf("MAIL reply = %q (%d octets), want prefix %q and 512 octets", got, len(got)+2, wantPrefix)
		}
		if _, err := io.WriteString(c, "RCPT TO:<b@example.com>\r\n"); err != nil {
			t.Fatal(err)
		}
		if !scanner.Scan() {
			t.Fatalf("RCPT reply missing: %v", scanner.Err())
		}
		want := "503 "
		if code == 250 {
			want = "250 "
		}
		if got := scanner.Text(); !strings.HasPrefix(got, want) {
			t.Fatalf("RCPT after MAIL status %d = %q, want %q", code, got, want)
		}
	}
}
