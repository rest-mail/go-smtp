package smtp

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func rfc3207TLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

// checklist: TLS-SYNTAX-02
func TestRFC3207RejectsParameters(t *testing.T) {
	for _, command := range []string{"STARTTLS ignored", "sTaRtTlS extra", "STARTTLS  x=y", "STARTTLS \u0085"} {
		t.Run(command, func(t *testing.T) {
			_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
				s.TLSConfig = rfc3207TLSConfig(t)
			})
			writeFlushBatch(t, raw, command+"\r\n")
			if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, "501 ") {
				t.Fatalf("%q: got %q, want 501", command, got)
			}
			writeFlushBatch(t, raw, "NOOP\r\n")
			if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, "250 ") {
				t.Fatalf("session after syntax error: %q", got)
			}
		})
	}
}

// checklist: TLS-CLIENT-01 TLS-CLIENT-02 TLS-STATE-02 TLS-STATE-03 TLS-STATE-04 TLS-EXAMPLE-01
func TestRFC3207ClientUpgrade(t *testing.T) {
	_, raw, _, _ := newFlushTestConn(t, func(s *Server) {
		s.TLSConfig = rfc3207TLSConfig(t)
	})
	// newFlushTestConn already consumed the server's greeting.
	c := NewClient(raw)
	c.didGreet = true
	if ok, value := c.Extension("STARTTLS"); !ok || value != "" {
		t.Fatalf("STARTTLS advertisement = %v, %q", ok, value)
	}
	c.rcpts = []string{"old@example.org"}
	if err := c.startTLS(&tls.Config{InsecureSkipVerify: true}); err != nil { //nolint:gosec // self-signed test certificate
		t.Fatal(err)
	}
	if state, ok := c.TLSConnectionState(); !ok || !state.HandshakeComplete {
		t.Fatalf("upgrade returned before handshake: ok=%v state=%+v", ok, state)
	}
	if c.ext != nil || len(c.rcpts) != 0 {
		t.Fatalf("pre-TLS knowledge retained: extensions=%v recipients=%v", c.ext, c.rcpts)
	}
	// Extension must issue a fresh EHLO over TLS and use only its new reply.
	if ok, _ := c.Extension("STARTTLS"); ok {
		t.Fatal("STARTTLS advertised after TLS")
	}
	if ok, _ := c.Extension("8BITMIME"); !ok {
		t.Fatal("post-TLS EHLO failed")
	}
	if err := c.startTLS(nil); err == nil {
		t.Fatal("client attempted a nested TLS upgrade")
	}
	if err := c.Noop(); err != nil {
		t.Fatalf("connection after refused nested TLS: %v", err)
	}
}

// checklist: TLS-CLIENT-01 TLS-CLIENT-03
func TestRFC3207ClientHandshakeFailure(t *testing.T) {
	// The legacy client tests install a global hook that trusts this test CA.
	hook := testHookStartTLS
	testHookStartTLS = nil
	t.Cleanup(func() { testHookStartTLS = hook })
	_, raw, _, done := newFlushTestConn(t, func(s *Server) {
		s.TLSConfig = rfc3207TLSConfig(t)
	})
	c := NewClient(raw)
	c.didGreet = true
	// The self-signed certificate is not trusted by this client.
	if err := c.startTLS(&tls.Config{ServerName: "example.com"}); err == nil {
		t.Fatal("STARTTLS succeeded with an untrusted certificate")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed client handshake did not close the connection")
	}
}

// checklist: TLS-CLIENT-01 TLS-CLIENT-03
func TestRFC3207ClientHandshakeTimeout(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() { clientSide.Close(); serverSide.Close() })
	done := make(chan error, 1)
	go func() {
		defer serverSide.Close()
		br := bufio.NewReader(serverSide)
		for _, step := range []struct{ command, reply string }{
			{"EHLO localhost\r\n", "250-localhost\r\n250 STARTTLS\r\n"},
			{"STARTTLS\r\n", "220 ready\r\n"},
		} {
			line, err := br.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			if line != step.command {
				done <- fmt.Errorf("command = %q, want %q", line, step.command)
				return
			}
			if _, err := io.WriteString(serverSide, step.reply); err != nil {
				done <- err
				return
			}
		}
		// Consume ClientHello but never send a ServerHello.
		_, err := io.Copy(io.Discard, br)
		done <- err
	}()
	c := NewClient(clientSide)
	c.didGreet = true
	c.CommandTimeout = 50 * time.Millisecond
	if err := c.startTLS(&tls.Config{InsecureSkipVerify: true}); err == nil { //nolint:gosec // no certificate is sent
		t.Fatal("STARTTLS succeeded with a stalled handshake")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("client did not close after handshake timeout")
	}
}

type rfc3207Session struct {
	flushAuthSession
	loggedOut chan struct{}
}

func (s rfc3207Session) Logout() error {
	close(s.loggedOut)
	return nil
}

// checklist: TLS-SYNTAX-01 TLS-STATE-01 TLS-STATE-04 TLS-STATE-05 TLS-EXAMPLE-01
func TestRFC3207ServerDiscardsKnowledge(t *testing.T) {
	type snapshot struct {
		host  string
		tls   bool
		proxy *XClientAttrs
	}
	snapshots := make(chan snapshot, 2)
	logouts := make(chan chan struct{}, 2)
	_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
		s.TLSConfig = rfc3207TLSConfig(t)
		s.EnableXCLIENT = true
		s.TrustXCLIENT = func(*Conn) bool { return true }
		s.Backend = BackendFunc(func(c *Conn) (Session, error) {
			state, ok := c.TLSConnectionState()
			snapshots <- snapshot{c.Hostname(), ok && state.HandshakeComplete, c.XClient()}
			logout := make(chan struct{})
			logouts <- logout
			return rfc3207Session{loggedOut: logout}, nil
		})
	})
	command := func(line string, code string) []string {
		t.Helper()
		writeFlushBatch(t, raw, line+"\r\n")
		reply := readFlushReply(t, br)
		if !strings.HasPrefix(reply[0], code+" ") && !strings.HasPrefix(reply[0], code+"-") {
			t.Fatalf("%s: %q, want %s", line, reply, code)
		}
		return reply
	}
	command("XCLIENT ADDR=203.0.113.1 LOGIN=old", "220")
	caps := command("EHLO before.example", "250")
	if !containsLine(caps, "250-STARTTLS") && !containsLine(caps, "250 STARTTLS") {
		t.Fatalf("missing bare STARTTLS keyword: %q", caps)
	}
	before := <-snapshots
	oldLogout := <-logouts
	if before.host != "before.example" || before.tls || before.proxy == nil {
		t.Fatalf("pre-TLS session: %+v", before)
	}
	command("AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk", "235")
	command("STARTTLS", "220")
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed test certificate
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	br = bufio.NewReader(tc)
	writeFlushBatch(t, tc, "MAIL FROM:<a@example.org>\r\n")
	if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, "503 ") {
		t.Fatalf("MAIL before fresh EHLO: %q", got)
	}
	select {
	case <-oldLogout:
	default:
		t.Fatal("old session was not logged out")
	}
	writeFlushBatch(t, tc, "EHLO after.example\r\n")
	caps = readFlushReply(t, br)
	if strings.Contains(strings.Join(caps, "\n"), "STARTTLS") {
		t.Fatalf("STARTTLS advertised over TLS: %q", caps)
	}
	after := <-snapshots
	if after.host != "after.example" || !after.tls || after.proxy != nil {
		t.Fatalf("post-TLS session: %+v", after)
	}
	writeFlushBatch(t, tc, "AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk\r\n")
	if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, "235 ") {
		t.Fatalf("pre-TLS authentication survived: %q", got)
	}
}

// checklist: TLS-CLIENT-01 TLS-CLIENT-03
func TestRFC3207ConstructorsVerifyHandshake(t *testing.T) {
	hook := testHookStartTLS
	testHookStartTLS = nil
	t.Cleanup(func() { testHookStartTLS = hook })
	for _, constructor := range []string{"DialStartTLS", "NewClientStartTLS"} {
		t.Run(constructor, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			s := NewServer(nopBackend{})
			s.Domain = "localhost"
			s.TLSConfig = rfc3207TLSConfig(t)
			s.ReadTimeout = time.Second
			s.WriteTimeout = time.Second
			go s.Serve(ln) //nolint:errcheck // closed by cleanup
			t.Cleanup(func() { s.Close() })
			cfg := &tls.Config{ServerName: "example.com"}
			var client *Client
			if constructor == "DialStartTLS" {
				client, err = DialStartTLS(ln.Addr().String(), cfg)
			} else {
				raw, dialErr := net.Dial("tcp", ln.Addr().String())
				if dialErr != nil {
					t.Fatal(dialErr)
				}
				defer raw.Close()
				client, err = NewClientStartTLS(raw, cfg)
			}
			if client != nil {
				client.Close()
			}
			if err == nil || client != nil {
				t.Fatalf("%s returned (%v, %v) with an untrusted certificate", constructor, client, err)
			}
		})
	}
}

// checklist: TLS-POLICY-01
func TestRFC3207PlaintextDelivery(t *testing.T) {
	_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
		s.TLSConfig = rfc3207TLSConfig(t)
	})
	// Advertising STARTTLS must not by itself require TLS for local delivery.
	for _, step := range []struct{ command, code string }{
		{"HELO client.example", "250"},
		{"MAIL FROM:<a@example.org>", "250"},
		{"RCPT TO:<b@example.org>", "250"},
		{"DATA", "354"},
		{"Subject: example\r\n\r\nbody\r\n.", "250"},
	} {
		writeFlushBatch(t, raw, step.command+"\r\n")
		if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, step.code+" ") {
			t.Fatalf("%s: %q, want %s", step.command, got, step.code)
		}
	}
}

// checklist: TLS-REPLY-02
func TestRFC3207ClientTemporaryRefusal(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() { clientSide.Close(); serverSide.Close() })
	done := make(chan error, 1)
	go func() {
		defer serverSide.Close()
		br := bufio.NewReader(serverSide)
		for _, step := range []struct{ command, reply string }{
			{"", "220 localhost\r\n"},
			{"EHLO localhost\r\n", "250-localhost\r\n250 STARTTLS\r\n"},
			{"STARTTLS\r\n", "454 TLS temporarily unavailable\r\n"},
		} {
			if step.command != "" {
				line, err := br.ReadString('\n')
				if err != nil {
					done <- err
					return
				}
				if line != step.command {
					done <- fmt.Errorf("command = %q, want %q", line, step.command)
					return
				}
			}
			if _, err := io.WriteString(serverSide, step.reply); err != nil {
				done <- err
				return
			}
		}
		// A TLS-required constructor must close, never send mail in plaintext.
		extra, err := io.ReadAll(br)
		if len(extra) != 0 {
			err = fmt.Errorf("plaintext after TLS refusal: %q", extra)
		}
		done <- err
	}()
	if err := clientSide.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	client, err := NewClientStartTLS(clientSide, nil)
	var smtpErr *SMTPError
	if client != nil {
		client.Close()
	}
	if client != nil || !errors.As(err, &smtpErr) || smtpErr.Code != 454 {
		t.Fatalf("constructor returned (%v, %v), want nil client and SMTP error 454", client, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("constructor did not close after TLS refusal")
	}
}

func containsLine(lines []string, want string) bool {
	for _, line := range lines {
		if line == want {
			return true
		}
	}
	return false
}
