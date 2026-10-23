package server

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/rest-mail/go-smtp/pkg/smtp/internal/testcert"
)

// writeCountingConn records every Write the server makes, so a test can tell
// replies sent together from replies sent one by one.
type writeCountingConn struct {
	net.Conn

	mu      sync.Mutex
	writes  []string
	failErr error
}

func (c *writeCountingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, string(b))
	err := c.failErr
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

// takeWrites returns the writes made since the last call.
func (c *writeCountingConn) takeWrites() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	w := c.writes
	c.writes = nil
	return w
}

func (c *writeCountingConn) failWrites(err error) {
	c.mu.Lock()
	c.failErr = err
	c.mu.Unlock()
}

type flushAuthSession struct{ nopSession }

func (flushAuthSession) AuthMechanisms() []string { return []string{sasl.Plain} }

func (flushAuthSession) Auth(string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(_, username, password string) error {
		if username != "username" || password != "password" {
			return errors.New("invalid credentials")
		}
		return nil
	}), nil
}

type flushAuthBackend struct{}

func (flushAuthBackend) NewSession(*Conn) (Session, error) { return flushAuthSession{}, nil }

// newFlushTestConn serves one connection over an in-memory pipe. A single
// client Write reaches the server in a single read, so a batch of commands
// written at once is deterministically one pipelined batch. Every client read
// is bounded, so a reply the server holds back fails the test instead of
// hanging it.
func newFlushTestConn(t *testing.T, configure func(*Server)) (*writeCountingConn, net.Conn, *bufio.Reader, <-chan error) {
	t.Helper()

	srvSide, cliSide := net.Pipe()
	wc := &writeCountingConn{Conn: srvSide}

	s := New(flushAuthBackend{})
	s.Domain = "localhost"
	s.AllowInsecureAuth = true
	if configure != nil {
		configure(s)
	}

	done := make(chan error, 1)
	go func() { done <- s.handleConn(newConn(wc, s)) }()

	if err := cliSide.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cliSide.Close()
		s.Close()
	})

	br := bufio.NewReader(cliSide)
	if got := readFlushReply(t, br); !strings.HasPrefix(got[0], "220 ") {
		t.Fatalf("greeting = %q", got)
	}
	if n := len(wc.takeWrites()); n != 1 {
		t.Fatalf("greeting took %d writes, want 1", n)
	}
	return wc, cliSide, br, done
}

// readFlushReply reads one (possibly multiline) reply.
func readFlushReply(t *testing.T, br *bufio.Reader) []string {
	t.Helper()
	var lines []string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading reply after %q: %v", lines, err)
		}
		line = strings.TrimSuffix(line, "\r\n")
		lines = append(lines, line)
		if len(line) < 4 || line[3] != '-' {
			return lines
		}
	}
}

func readFlushCodes(t *testing.T, br *bufio.Reader, n int) []string {
	t.Helper()
	codes := make([]string, n)
	for i := range codes {
		codes[i] = readFlushReply(t, br)[0][:3]
	}
	return codes
}

func writeFlushBatch(t *testing.T, c net.Conn, batch string) {
	t.Helper()
	if _, err := io.WriteString(c, batch); err != nil {
		t.Fatalf("writing %q: %v", batch, err)
	}
}

// checklist: SMTP-EXT-01
// checklist: PIPE-SERVER-01 PIPE-SERVER-02
func TestPipelinedRepliesShareOneWrite(t *testing.T) {
	wc, c, br, _ := newFlushTestConn(t, func(s *Server) { s.MaxRecipients = 2 })

	writeFlushBatch(t, c, "EHLO localhost\r\n")
	ehlo := readFlushReply(t, br)
	if len(ehlo) < 2 {
		t.Fatalf("EHLO reply = %q, want multiline", ehlo)
	}
	if writes := wc.takeWrites(); len(writes) != 1 {
		t.Fatalf("multiline EHLO reply took %d writes, want 1: %q", len(writes), writes)
	}

	// Accepted, malformed (rejected), accepted, and over the recipient limit
	// (rejected): every reply in order, sent together once the batch is done.
	writeFlushBatch(t, c, "MAIL FROM:<a@example.org>\r\n"+
		"RCPT TO:<b@example.org>\r\n"+
		"RCPT FOO:<x@example.org>\r\n"+
		"RCPT TO:<c@example.org>\r\n"+
		"RCPT TO:<d@example.org>\r\n")
	want := []string{"250", "250", "501", "250", "452"}
	if got := readFlushCodes(t, br, len(want)); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("reply codes = %v, want %v", got, want)
	}
	writes := wc.takeWrites()
	if len(writes) != 1 {
		t.Fatalf("pipelined MAIL/RCPT batch took %d writes, want 1: %q", len(writes), writes)
	}
	if got := strings.Count(writes[0], "\r\n"); got != len(want) {
		t.Fatalf("the batch write holds %d replies, want %d: %q", got, len(want), writes[0])
	}
}

// checklist: SMTP-EXT-01
// checklist: PIPE-SERVER-07 PIPE-SERVER-08
func TestSingleCommandReplyIsPrompt(t *testing.T) {
	wc, c, br, _ := newFlushTestConn(t, nil)

	for i := 0; i < 3; i++ {
		writeFlushBatch(t, c, "NOOP\r\n")
		if got := readFlushReply(t, br); !strings.HasPrefix(got[0], "250 ") {
			t.Fatalf("NOOP reply = %q", got)
		}
		if n := len(wc.takeWrites()); n != 1 {
			t.Fatalf("NOOP reply took %d writes, want 1", n)
		}
	}
}

// checklist: SMTP-EXT-01
// checklist: PIPE-SERVER-07
func TestPartialPipelinedLineDoesNotHoldReplies(t *testing.T) {
	_, c, br, _ := newFlushTestConn(t, nil)

	// The second command is cut mid-line: the server must not wait for the rest
	// of it before answering the first.
	writeFlushBatch(t, c, "NOOP\r\nNOO")
	if got := readFlushReply(t, br); !strings.HasPrefix(got[0], "250 ") {
		t.Fatalf("NOOP reply = %q", got)
	}
	writeFlushBatch(t, c, "P\r\n")
	if got := readFlushReply(t, br); !strings.HasPrefix(got[0], "250 ") {
		t.Fatalf("second NOOP reply = %q", got)
	}
}

// checklist: SMTP-DATA-01
// checklist: PIPE-SERVER-05
func TestDataReplySentBeforeBody(t *testing.T) {
	wc, c, br, _ := newFlushTestConn(t, nil)

	writeFlushBatch(t, c, "HELO localhost\r\n")
	readFlushReply(t, br)
	wc.takeWrites()

	// DATA ends the pipelined group: its 354 goes out with the replies before
	// it, and before the server waits for a body the client sends only after
	// seeing it.
	writeFlushBatch(t, c, "MAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.org>\r\nDATA\r\n")
	want := []string{"250", "250", "354"}
	if got := readFlushCodes(t, br, len(want)); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("reply codes = %v, want %v", got, want)
	}
	if writes := wc.takeWrites(); len(writes) != 1 {
		t.Fatalf("MAIL/RCPT/DATA batch took %d writes, want 1: %q", len(writes), writes)
	}

	writeFlushBatch(t, c, "Subject: hi\r\n\r\nbody\r\n.\r\n")
	if got := readFlushReply(t, br); !strings.HasPrefix(got[0], "250 ") {
		t.Fatalf("end of data reply = %q", got)
	}
}

// checklist: SMTP-EXT-08 SMTP-AUTH-18
func TestAuthChallengeSentBeforeReadingResponse(t *testing.T) {
	_, c, br, _ := newFlushTestConn(t, nil)

	writeFlushBatch(t, c, "EHLO localhost\r\n")
	readFlushReply(t, br)

	writeFlushBatch(t, c, "NOOP\r\nAUTH PLAIN\r\n")
	if got := readFlushReply(t, br); !strings.HasPrefix(got[0], "250 ") {
		t.Fatalf("NOOP reply = %q", got)
	}
	if got := readFlushReply(t, br); got[0] != "334 " {
		t.Fatalf("AUTH challenge = %q", got)
	}
	writeFlushBatch(t, c, "AHVzZXJuYW1lAHBhc3N3b3Jk\r\n")
	if got := readFlushReply(t, br); !strings.HasPrefix(got[0], "235 ") {
		t.Fatalf("AUTH result = %q", got)
	}
}

// checklist: SMTP-EXT-07
// checklist: TLS-REPLY-01
func TestStartTLSReplySentBeforeHandshake(t *testing.T) {
	cert, err := tls.X509KeyPair(testcert.LocalhostCert, testcert.LocalhostKey)
	if err != nil {
		t.Fatal(err)
	}
	_, c, br, _ := newFlushTestConn(t, func(s *Server) {
		s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	})

	writeFlushBatch(t, c, "EHLO localhost\r\n")
	readFlushReply(t, br)

	writeFlushBatch(t, c, "NOOP\r\nSTARTTLS\r\n")
	want := []string{"250", "220"}
	if got := readFlushCodes(t, br, len(want)); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("reply codes = %v, want %v", got, want)
	}

	tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed test cert
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	writeFlushBatch(t, tc, "EHLO localhost\r\n")
	if got := readFlushReply(t, bufio.NewReader(tc)); !strings.HasPrefix(got[len(got)-1], "250 ") {
		t.Fatalf("EHLO over TLS = %q", got)
	}
}

// checklist: SMTP-CMD-06
// checklist: PIPE-SERVER-05
func TestQuitReplySentBeforeClose(t *testing.T) {
	_, c, br, done := newFlushTestConn(t, nil)

	// Commands pipelined after QUIT are not served.
	writeFlushBatch(t, c, "NOOP\r\nQUIT\r\nNOOP\r\n")
	want := []string{"250", "221"}
	if got := readFlushCodes(t, br, len(want)); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("reply codes = %v, want %v", got, want)
	}
	if line, err := br.ReadString('\n'); err != io.EOF {
		t.Fatalf("after 221: read %q, %v; want EOF", line, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("handleConn = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connection still served after QUIT")
	}
}

// checklist: SMTP-SRV-02
func TestReplyWriteErrorEndsConnection(t *testing.T) {
	errInjected := errors.New("injected write failure")
	wc, c, br, done := newFlushTestConn(t, nil)

	wc.failWrites(errInjected)
	writeFlushBatch(t, c, "NOOP\r\nNOOP\r\n")
	select {
	case err := <-done:
		if !errors.Is(err, errInjected) {
			t.Fatalf("handleConn = %v, want %v", err, errInjected)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connection still served after a reply write failed")
	}
	if line, err := br.ReadString('\n'); err != io.EOF {
		t.Fatalf("after write failure: read %q, %v; want EOF", line, err)
	}
}
