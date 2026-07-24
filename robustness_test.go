package smtp_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
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

// dummyAddr is a stand-in net.Addr for mock connections.
type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "127.0.0.1:0" }

// flakyConn is a net.Conn whose Read supplies an endless stream of NOOP
// commands and whose Write fails after failAfter bytes have been written. Close
// signals the closed channel exactly once.
type flakyConn struct {
	readOff   int
	written   int
	failAfter int
	once      sync.Once
	closed    chan struct{}
}

var noopLine = []byte("NOOP\r\n")

func (fc *flakyConn) Read(b []byte) (int, error) {
	select {
	case <-fc.closed:
		return 0, io.EOF
	default:
	}
	n := 0
	for n < len(b) {
		m := copy(b[n:], noopLine[fc.readOff:])
		n += m
		fc.readOff += m
		if fc.readOff >= len(noopLine) {
			fc.readOff = 0
		}
	}
	return n, nil
}

func (fc *flakyConn) Write(b []byte) (int, error) {
	if fc.written >= fc.failAfter {
		return 0, fmt.Errorf("flakyConn: simulated write failure after %d bytes", fc.written)
	}
	fc.written += len(b)
	return len(b), nil
}

func (fc *flakyConn) Close() error {
	fc.once.Do(func() { close(fc.closed) })
	return nil
}

func (fc *flakyConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (fc *flakyConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (fc *flakyConn) SetDeadline(time.Time) error      { return nil }
func (fc *flakyConn) SetReadDeadline(time.Time) error  { return nil }
func (fc *flakyConn) SetWriteDeadline(time.Time) error { return nil }

// singleConnListener yields one connection then blocks until closed.
type singleConnListener struct {
	conn net.Conn
	gave bool
	done chan struct{}
	once sync.Once
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if !l.gave {
		l.gave = true
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return dummyAddr{} }

// TestWriteErrorBreaksLoop verifies that once a response write fails, the
// connection command loop stops instead of spinning forever processing
// commands whose responses can never reach the (gone) peer.
func TestWriteErrorBreaksLoop(t *testing.T) {
	fc := &flakyConn{failAfter: 100, closed: make(chan struct{})}
	l := &singleConnListener{conn: fc, done: make(chan struct{})}

	s := smtp.NewServer(new(backend))
	s.Domain = "localhost"
	s.AllowInsecureAuth = true
	go s.Serve(l)
	defer s.Close()

	select {
	case <-fc.closed:
		// handleConn exited (and closed the conn) after the write error.
	case <-time.After(3 * time.Second):
		t.Fatal("handleConn kept running after a write error (loop did not break)")
	}
}

// step is one scripted result from stepConn.Read.
type step struct {
	data []byte
	err  error
}

// stepConn is a net.Conn whose Read returns a scripted sequence of results and
// whose Write silently succeeds. Once the script is exhausted Read returns EOF.
type stepConn struct {
	steps  []step
	i      int
	once   sync.Once
	closed chan struct{}
}

func (sc *stepConn) Read(b []byte) (int, error) {
	if sc.i >= len(sc.steps) {
		return 0, io.EOF
	}
	s := sc.steps[sc.i]
	sc.i++
	n := copy(b, s.data)
	return n, s.err
}

func (sc *stepConn) Write(b []byte) (int, error)      { return len(b), nil }
func (sc *stepConn) Close() error                     { sc.once.Do(func() { close(sc.closed) }); return nil }
func (sc *stepConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (sc *stepConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (sc *stepConn) SetDeadline(time.Time) error      { return nil }
func (sc *stepConn) SetReadDeadline(time.Time) error  { return nil }
func (sc *stepConn) SetWriteDeadline(time.Time) error { return nil }

// econnreset returns a realistically-wrapped connection-reset error.
func econnreset() error {
	return &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}
}

// serveOneAndDrain serves a single scripted connection and waits for its
// handler goroutine (and thus any error log it would emit) to complete.
func serveOneAndDrain(t *testing.T, sc *stepConn, s *smtp.Server) {
	t.Helper()
	l := &singleConnListener{conn: sc, done: make(chan struct{})}
	go s.Serve(l)

	select {
	case <-sc.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("connection was not handled in time")
	}

	// Shutdown waits for the per-connection goroutine to finish, which happens
	// after it has logged (or chosen not to log).
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

// TestHealthcheckNoCommandNotLogged verifies that a connection reset before any
// command is issued (a bare TCP health check) does not produce an error-log
// entry.
func TestHealthcheckNoCommandNotLogged(t *testing.T) {
	var logBuf bytes.Buffer
	sc := &stepConn{steps: []step{{nil, econnreset()}}, closed: make(chan struct{})}

	s := smtp.NewServer(new(backend))
	s.Domain = "localhost"
	s.ErrorLog = log.New(&logBuf, "", 0)

	serveOneAndDrain(t, sc, s)

	if logBuf.Len() != 0 {
		t.Fatalf("expected no error log for zero-command connection, got: %q", logBuf.String())
	}
}

// TestMidSessionErrorStillLogged verifies the silencing is scoped: a connection
// reset after a command has been processed is still logged.
func TestMidSessionErrorStillLogged(t *testing.T) {
	var logBuf bytes.Buffer
	sc := &stepConn{
		steps:  []step{{[]byte("NOOP\r\n"), nil}, {nil, econnreset()}},
		closed: make(chan struct{}),
	}

	s := smtp.NewServer(new(backend))
	s.Domain = "localhost"
	s.ErrorLog = log.New(&logBuf, "", 0)

	serveOneAndDrain(t, sc, s)

	if logBuf.Len() == 0 {
		t.Fatal("expected a mid-session connection error to be logged, but log was empty")
	}
}
