package smtp

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// newConformanceServer starts a plaintext server backed by nopBackend and
// returns it together with a raw client connection and a buffered reader whose
// greeting line has already been consumed. Everything is torn down via
// t.Cleanup.
func newConformanceServer(t *testing.T, configure func(*Server)) (*Server, net.Conn, *bufio.Reader) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(nopBackend{})
	s.Domain = "localhost"
	if configure != nil {
		configure(s)
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() {
		_ = s.Close()
		_ = ln.Close()
	})

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	br := bufio.NewReader(c)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	return s, c, br
}

func writeCmd(t *testing.T, c net.Conn, s string) {
	t.Helper()
	if _, err := io.WriteString(c, s); err != nil {
		t.Fatalf("write %q: %v", s, err)
	}
}

func readSMTPLine(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v (partial %q)", err, line)
	}
	return strings.TrimRight(line, "\r\n")
}

// drainEHLO sends EHLO and consumes the multi-line 250 response.
func drainEHLO(t *testing.T, c net.Conn, br *bufio.Reader) {
	t.Helper()
	writeCmd(t, c, "EHLO localhost\r\n")
	for {
		line := readSMTPLine(t, br)
		if strings.HasPrefix(line, "250 ") {
			return
		}
		if !strings.HasPrefix(line, "250-") {
			t.Fatalf("unexpected EHLO line: %q", line)
		}
	}
}

// TestMailParamRequiresSpace covers issue #53 item 1: an ESMTP parameter that
// runs straight on from the reverse-path with no separating whitespace
// ("MAIL FROM:<a@b>SIZE=10") must be rejected (RFC 5321 §4.1.1.2), not silently
// accepted as a SIZE parameter.
func TestMailParamRequiresSpace(t *testing.T) {
	_, c, br := newConformanceServer(t, nil)
	drainEHLO(t, c, br)

	writeCmd(t, c, "MAIL FROM:<a@b>SIZE=10\r\n")
	if line := readSMTPLine(t, br); !strings.HasPrefix(line, "501") {
		t.Fatalf("run-on MAIL parameter: got %q, want 501", line)
	}
}

// TestMailParamNoDuplicates covers issue #53 item 1: a repeated ESMTP parameter
// ("SIZE=10 SIZE=20") must be rejected (RFC 5321 §4.1.1.11) rather than silently
// collapsing to the last value.
func TestMailParamNoDuplicates(t *testing.T) {
	_, c, br := newConformanceServer(t, nil)
	drainEHLO(t, c, br)

	writeCmd(t, c, "MAIL FROM:<a@b> SIZE=10 SIZE=20\r\n")
	if line := readSMTPLine(t, br); !strings.HasPrefix(line, "501") {
		t.Fatalf("duplicate MAIL parameter: got %q, want 501", line)
	}
}

// TestAuthRejectsExtraTokens covers issue #53 item 2: AUTH carries a mechanism
// and at most one initial-response (RFC 4954 §4); trailing tokens must be a 501,
// not silently ignored.
func TestAuthRejectsExtraTokens(t *testing.T) {
	_, c, br := newConformanceServer(t, func(s *Server) { s.AllowInsecureAuth = true })
	drainEHLO(t, c, br)

	writeCmd(t, c, "AUTH PLAIN AHVzZXIAcGFzcw== bogus\r\n")
	if line := readSMTPLine(t, br); !strings.HasPrefix(line, "501") {
		t.Fatalf("AUTH with extra tokens: got %q, want 501", line)
	}
}

// TestAuthTLSRequiredCode covers issue #53 item 2: refusing AUTH on an
// unprotected connection must use 530 5.7.0 (RFC 3207 §4), not the unassigned
// 523.
func TestAuthTLSRequiredCode(t *testing.T) {
	_, c, br := newConformanceServer(t, nil) // AllowInsecureAuth stays false
	drainEHLO(t, c, br)

	writeCmd(t, c, "AUTH PLAIN AHVzZXIAcGFzcw==\r\n")
	line := readSMTPLine(t, br)
	if !strings.HasPrefix(line, "530 5.7.0") {
		t.Fatalf("AUTH without TLS: got %q, want 530 5.7.0", line)
	}
}

// TestErrCountCountsConsecutive covers issue #53 item 5: the protocol-error
// tally is consecutive, so bad commands interleaved with successful ones do not
// accumulate to the disconnect threshold.
func TestErrCountCountsConsecutive(t *testing.T) {
	_, c, br := newConformanceServer(t, nil)
	drainEHLO(t, c, br)

	// errThreshold is 3 (disconnect on the 4th consecutive error). Issue four
	// bad commands, each cleared by a following NOOP. Cumulative counting closed
	// the connection on the 4th bad command; consecutive counting keeps it open.
	for i := 0; i < 4; i++ {
		writeCmd(t, c, "ZZZZ\r\n")
		if line := readSMTPLine(t, br); !strings.HasPrefix(line, "500") {
			t.Fatalf("bad command %d: got %q, want 500", i, line)
		}
		writeCmd(t, c, "NOOP\r\n")
		if line := readSMTPLine(t, br); !strings.HasPrefix(line, "250") {
			t.Fatalf("noop %d: connection appears closed, got %q", i, line)
		}
	}

	writeCmd(t, c, "NOOP\r\n")
	if line := readSMTPLine(t, br); !strings.HasPrefix(line, "250") {
		t.Fatalf("connection dropped after interleaved errors: got %q", line)
	}
}

// TestServerCloseSends421 covers issue #53 item 4: Server.Close must deliver a
// 421 service-closing reply (RFC 5321 §3.8) to a live idle connection before the
// socket is dropped.
func TestServerCloseSends421(t *testing.T) {
	s, c, br := newConformanceServer(t, nil)
	drainEHLO(t, c, br)

	done := make(chan string, 1)
	go func() {
		line, _ := br.ReadString('\n')
		done <- line
	}()

	// Let the reader block on the idle connection, then shut the server down.
	time.Sleep(50 * time.Millisecond)
	_ = s.Close()

	select {
	case line := <-done:
		if !strings.HasPrefix(line, "421") {
			t.Fatalf("server close: got %q, want a 421 service-closing reply", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no reply after Server.Close; connection dropped silently")
	}
}

// TestDataCloseHonoursWriteDeadline covers issue #53 item 6: the DATA
// terminating flush must be bounded by a write deadline so a wedged peer that
// stops reading cannot block the close write forever.
func TestDataCloseHonoursWriteDeadline(t *testing.T) {
	cconn, sconn := net.Pipe()
	defer func() { _ = cconn.Close() }()
	defer func() { _ = sconn.Close() }()

	c := NewClient(cconn)
	c.SubmissionTimeout = 100 * time.Millisecond

	// Build a DATA writer directly, skipping the DATA handshake. net.Pipe is
	// unbuffered, so with nothing reading sconn the terminating flush blocks
	// until the write deadline fires.
	cmd := &DataCommand{client: c, wc: c.text.DotWriter()}
	if _, err := io.WriteString(cmd, "Subject: x\r\n\r\nbody\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.close() }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("close returned nil; expected a write-deadline timeout")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close hung: terminating flush ignored the write deadline")
	}
}
