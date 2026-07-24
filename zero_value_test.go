package smtp_test

import (
	"bufio"
	"errors"
	"net"
	"strings"
	"testing"

	smtp "github.com/rest-mail/go-smtp"
)

// TestZeroValueServer verifies a zero-value &Server{} is usable without
// NewServer: Serve accepts a connection (which would otherwise panic writing to
// the nil conns map or logging via a nil ErrorLog), a default line length is
// applied, and Close does not panic closing the nil done channel.
func TestZeroValueServer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	s := &smtp.Server{Backend: new(backend)}
	go s.Serve(l)

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	scanner := bufio.NewScanner(c)
	if !scanner.Scan() || !strings.HasPrefix(scanner.Text(), "220 ") {
		t.Fatalf("zero-value server did not greet: %q (err=%v)", scanner.Text(), scanner.Err())
	}

	if err := s.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Close on a zero-value server returned %v", err)
	}

	// Close() also runs init(); sync.Once establishes the happens-before, so this
	// read of the field the serving goroutine set is race-free.
	if s.MaxLineLength != 2000 {
		t.Errorf("MaxLineLength = %d, want the default 2000 for a zero-value server", s.MaxLineLength)
	}
}
