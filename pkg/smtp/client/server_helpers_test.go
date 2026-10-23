// Copies of the server package's test fixtures, written against its public
// API, so the client tests can drive a real server. A package server test
// cannot share them: server tests importing a helper package that imports
// server would form an import cycle.

package client

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/rest-mail/go-smtp/pkg/smtp"
	"github.com/rest-mail/go-smtp/pkg/smtp/internal/testcert"
	"github.com/rest-mail/go-smtp/pkg/smtp/server"
)

// writeCountingConn records every Write the server makes, so a test can tell
// replies sent together from replies sent one by one.
type writeCountingConn struct {
	net.Conn

	mu      sync.Mutex
	writes  []string
	failErr error

	closeOnce sync.Once
	closed    chan error // if set, receives nil when the server closes
}

func (c *writeCountingConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() {
		if c.closed != nil {
			c.closed <- nil
		}
	})
	return err
}

// oneConnListener hands Server.Serve a single connection, then blocks until
// it is closed.
type oneConnListener struct {
	conn   net.Conn
	once   sync.Once
	closed chan struct{}
	shut   sync.Once
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error {
	l.shut.Do(func() { close(l.closed) })
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

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

func (flushAuthBackend) NewSession(*server.Conn) (server.Session, error) {
	return flushAuthSession{}, nil
}

// newFlushTestConn serves one connection over an in-memory pipe. A single
// client Write reaches the server in a single read, so a batch of commands
// written at once is deterministically one pipelined batch. Every client read
// is bounded, so a reply the server holds back fails the test instead of
// hanging it.
func newFlushTestConn(t *testing.T, configure func(*server.Server)) (*writeCountingConn, net.Conn, *bufio.Reader, <-chan error) {
	t.Helper()

	srvSide, cliSide := net.Pipe()
	wc := &writeCountingConn{Conn: srvSide}

	s := server.New(flushAuthBackend{})
	s.Domain = "localhost"
	s.AllowInsecureAuth = true
	if configure != nil {
		configure(s)
	}

	// done receives once the server has finished with the connection and
	// closed it.
	done := make(chan error, 1)
	wc.closed = done
	go s.Serve(&oneConnListener{conn: wc, closed: make(chan struct{})})

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

// nopBackend is a minimal Backend used by internal robustness tests.
type nopBackend struct{}

func (nopBackend) NewSession(*server.Conn) (server.Session, error) { return nopSession{}, nil }

type nopSession struct{}

func (nopSession) Reset() {}

func (nopSession) Logout() error { return nil }

func (nopSession) Mail(string, *smtp.MailOptions) error { return nil }

func (nopSession) Rcpt(string, *smtp.RcptOptions) error { return nil }

func (nopSession) Data(io.Reader) error { return nil }

func rfc3207TLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	cert, err := tls.X509KeyPair(testcert.LocalhostCert, testcert.LocalhostKey)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

type transportProofSession struct {
	flushAuthSession
	mail func(string, *smtp.MailOptions) error
	rcpt func(string, *smtp.RcptOptions) error
	data chan string
}

func (s transportProofSession) Mail(from string, opts *smtp.MailOptions) error {
	if s.mail != nil {
		return s.mail(from, opts)
	}
	return nil
}

func (s transportProofSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	if s.rcpt != nil {
		return s.rcpt(to, opts)
	}
	return nil
}

func (s transportProofSession) Data(r io.Reader) error {
	b, err := io.ReadAll(r)
	if err == nil {
		s.data <- string(b)
	}
	return err
}

func transportProofClient(t *testing.T, session server.Session, configure func(*server.Server)) (*Client, *writeCountingConn) {
	t.Helper()
	s := server.New(server.BackendFunc(func(*server.Conn) (server.Session, error) { return session, nil }))
	s.Domain = "localhost"
	s.AllowInsecureAuth = true
	if configure != nil {
		configure(s)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := raw.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	wc := &writeCountingConn{Conn: raw}
	c := New(wc)
	c.CommandTimeout = 5 * time.Second
	c.SubmissionTimeout = 5 * time.Second
	t.Cleanup(func() {
		c.Close()
		s.Close()
		if err := <-done; err != nil && err != server.ErrServerClosed {
			t.Errorf("Serve: %v", err)
		}
	})
	return c, wc
}

// The generic server supports relay as well as submission. The backend makes
// the submission authorization decision, as in ExampleServer.
type submissionPolicySession struct {
	nopSession
	authorized bool
	events     chan string
}

func (*submissionPolicySession) AuthMechanisms() []string { return []string{sasl.Plain} }

func (s *submissionPolicySession) Auth(string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(identity, username, password string) error {
		if identity != "" || username != "user" || password != "password" {
			return server.ErrAuthFailed
		}
		s.authorized = true
		return nil
	}), nil
}

func (s *submissionPolicySession) Mail(from string, _ *smtp.MailOptions) error {
	if !s.authorized {
		s.events <- "denied:" + from
		return server.ErrAuthRequired
	}
	s.events <- "mail:" + from
	return nil
}

func (s *submissionPolicySession) Rcpt(to string, _ *smtp.RcptOptions) error {
	s.events <- "rcpt:" + to
	return nil
}

func (s *submissionPolicySession) Data(r io.Reader) error {
	b, err := io.ReadAll(r)
	if err == nil {
		s.events <- "data:" + string(b)
	}
	return err
}

type rfc8689Session struct {
	nopSession
	mail chan smtp.MailOptions
	data chan string
}

func (s rfc8689Session) Mail(_ string, opts *smtp.MailOptions) error {
	s.mail <- *opts
	return nil
}

func (s rfc8689Session) Data(r io.Reader) error {
	b, err := io.ReadAll(r)
	s.data <- string(b)
	return err
}

type rfc8689Wire struct {
	raw  net.Conn
	br   *bufio.Reader
	mail chan smtp.MailOptions
	data chan string
}

func newRFC8689Wire(t *testing.T, enabled, encrypted bool) *rfc8689Wire {
	t.Helper()
	w := &rfc8689Wire{mail: make(chan smtp.MailOptions, 16), data: make(chan string, 16)}
	_, w.raw, w.br, _ = newFlushTestConn(t, func(s *server.Server) {
		s.EnableREQUIRETLS = enabled
		s.TLSConfig = rfc3207TLSConfig(t)
		s.Backend = server.BackendFunc(func(*server.Conn) (server.Session, error) {
			return rfc8689Session{mail: w.mail, data: w.data}, nil
		})
	})
	w.command(t, "EHLO client.example", "250")
	if encrypted {
		w.command(t, "STARTTLS", "220")
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(testcert.LocalhostCert) {
			t.Fatal("invalid test certificate")
		}
		// Use the fixture CA and its actual DNS name; no verification bypass.
		tc := tls.Client(w.raw, &tls.Config{RootCAs: roots, ServerName: "example.com"})
		if err := tc.Handshake(); err != nil {
			t.Fatal(err)
		}
		w.raw, w.br = tc, bufio.NewReader(tc)
		w.command(t, "EHLO client.example", "250")
	}
	return w
}

func (w *rfc8689Wire) command(t *testing.T, cmd, want string) []string {
	t.Helper()
	writeFlushBatch(t, w.raw, cmd+"\r\n")
	reply := readFlushReply(t, w.br)
	if !strings.HasPrefix(reply[0], want+" ") && !strings.HasPrefix(reply[0], want+"-") {
		t.Fatalf("%q = %q, want %s", cmd, reply, want)
	}
	return reply
}

func (w *rfc8689Wire) requireMail(t *testing.T, want bool) {
	t.Helper()
	select {
	case opts := <-w.mail:
		if opts.RequireTLS != want {
			t.Fatalf("RequireTLS = %v, want %v", opts.RequireTLS, want)
		}
	default:
		t.Fatal("MAIL did not reach backend")
	}
}

func (w *rfc8689Wire) deliver(t *testing.T, body string) {
	t.Helper()
	w.command(t, "RCPT TO:<recipient@example.net>", "250")
	w.command(t, "DATA", "354")
	writeFlushBatch(t, w.raw, body+".\r\n")
	if reply := readFlushReply(t, w.br); !strings.HasPrefix(reply[0], "250 ") {
		t.Fatal(reply)
	}
	select {
	case got := <-w.data:
		if got != body {
			t.Fatalf("body = %q, want %q", got, body)
		}
	default:
		t.Fatal("DATA did not reach backend")
	}
	w.command(t, "NOOP", "250")
}
