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

// tlsPolicySession records whether each accepted MAIL arrived over TLS and,
// when requireTLS is set, refuses plaintext MAIL as a host policy would.
type tlsPolicySession struct {
	nopSession
	tls        bool
	requireTLS bool
	mails      chan<- bool
}

func (s tlsPolicySession) Mail(string, *MailOptions) error {
	if s.requireTLS && !s.tls {
		return &SMTPError{Code: 530, EnhancedCode: EnhancedCode{5, 7, 0}, Message: "Must issue a STARTTLS command first"}
	}
	s.mails <- s.tls
	return nil
}

// tlsPolicyBackend builds sessions from the connection's TLS state at session
// creation, which RFC 3207 §4.2 repeats after every successful STARTTLS.
type tlsPolicyBackend struct {
	requireTLS func(c *Conn) bool
	mails      chan bool
}

func (b tlsPolicyBackend) NewSession(c *Conn) (Session, error) {
	state, ok := c.TLSConnectionState()
	return tlsPolicySession{
		tls:        ok && state.HandshakeComplete,
		requireTLS: b.requireTLS != nil && b.requireTLS(c),
		mails:      b.mails,
	}, nil
}

// rfc3207PolicyServer listens on loopback so the public Dial and DialStartTLS
// constructors run against a real server. It returns the address and the
// channel of MAIL commands the backend accepted (true when over TLS).
func rfc3207PolicyServer(t *testing.T, configure func(*Server, *tlsPolicyBackend)) (string, <-chan bool) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	be := &tlsPolicyBackend{mails: make(chan bool, 4)}
	s := NewServer(be)
	s.Domain = "localhost"
	s.ReadTimeout = 5 * time.Second
	s.WriteTimeout = 5 * time.Second
	if configure != nil {
		configure(s, be)
	}
	go s.Serve(ln) //nolint:errcheck // closed by cleanup
	t.Cleanup(func() { s.Close() })
	return ln.Addr().String(), be.mails
}

func rfc3207Send(c *Client) error {
	return c.SendMail("a@example.org", []string{"b@example.org"}, strings.NewReader("Subject: tls\r\n\r\nbody\r\n"))
}

func expectNoMail(t *testing.T, mails <-chan bool) {
	t.Helper()
	select {
	case overTLS := <-mails:
		t.Fatalf("backend accepted MAIL (tls=%v) under a failed TLS policy", overTLS)
	default:
	}
}

// checklist: TLS-POLICY-05
func TestRFC3207ClientQuitsAfterRejectedTLS(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() { clientSide.Close(); serverSide.Close() })
	cfg := rfc3207TLSConfig(t)
	done := make(chan error, 1)
	go func() {
		defer serverSide.Close()
		br := bufio.NewReader(serverSide)
		for _, step := range []struct{ command, reply string }{
			{"", "220 localhost\r\n"},
			{"EHLO localhost\r\n", "250-localhost\r\n250 STARTTLS\r\n"},
			{"STARTTLS\r\n", "220 ready\r\n"},
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
		tc := tls.Server(serverSide, cfg)
		if err := tc.Handshake(); err != nil {
			done <- err
			return
		}
		// RFC 3207 §4.1: the first command after a negotiation the client
		// rejects is QUIT, not another EHLO.
		line, err := bufio.NewReader(tc).ReadString('\n')
		if err != nil {
			done <- err
			return
		}
		if line != "QUIT\r\n" {
			done <- fmt.Errorf("first command over TLS = %q, want QUIT", line)
			return
		}
		if _, err := io.WriteString(tc, "221 bye\r\n"); err != nil {
			done <- err
			return
		}
		// Read until the client closes, absorbing its close_notify.
		_, err = io.Copy(io.Discard, tc)
		done <- err
	}()
	if err := clientSide.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	c, err := NewClientStartTLS(clientSide, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed test certificate
	if err != nil {
		t.Fatal(err)
	}
	// The host inspects the completed negotiation and finds it too weak.
	if state, ok := c.TLSConnectionState(); !ok || !state.HandshakeComplete {
		t.Fatalf("TLS state = %v, %+v", ok, state)
	}
	if err := c.Quit(); err != nil {
		t.Fatalf("QUIT after rejected TLS: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server never saw QUIT")
	}
}

// checklist: TLS-SEC-01
func TestRFC3207RequireTLSForSelectedHosts(t *testing.T) {
	hook := testHookStartTLS
	testHookStartTLS = nil
	t.Cleanup(func() { testHookStartTLS = hook })

	// Server side: a host policy refuses plaintext MAIL from a selected client
	// and accepts the same client once TLS is negotiated.
	t.Run("server", func(t *testing.T) {
		addr, mails := rfc3207PolicyServer(t, func(s *Server, be *tlsPolicyBackend) {
			s.TLSConfig = rfc3207TLSConfig(t)
			be.requireTLS = func(c *Conn) bool { return c.Hostname() == "selected.example" }
		})
		plain, err := Dial(addr)
		if err != nil {
			t.Fatal(err)
		}
		defer plain.Close()
		if err := plain.Hello("selected.example"); err != nil {
			t.Fatal(err)
		}
		var smtpErr *SMTPError
		if err := plain.Mail("a@example.org", nil); !errors.As(err, &smtpErr) || smtpErr.Code != 530 || smtpErr.EnhancedCode != (EnhancedCode{5, 7, 0}) {
			t.Fatalf("plaintext MAIL from selected host = %v, want 530 5.7.0", err)
		}
		expectNoMail(t, mails)

		other, err := Dial(addr)
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		if err := other.Hello("other.example"); err != nil {
			t.Fatal(err)
		}
		if err := rfc3207Send(other); err != nil {
			t.Fatalf("unselected plaintext delivery: %v", err)
		}
		if overTLS := <-mails; overTLS {
			t.Fatal("unselected host recorded as TLS")
		}

		secure, err := Dial(addr)
		if err != nil {
			t.Fatal(err)
		}
		defer secure.Close()
		if err := secure.Hello("selected.example"); err != nil {
			t.Fatal(err)
		}
		if err := secure.startTLS(&tls.Config{InsecureSkipVerify: true}); err != nil { //nolint:gosec // self-signed test certificate
			t.Fatal(err)
		}
		if err := rfc3207Send(secure); err != nil {
			t.Fatalf("selected host over TLS: %v", err)
		}
		if overTLS := <-mails; !overTLS {
			t.Fatal("selected host's MAIL not recorded as TLS")
		}
	})

	// Client side: a TLS-required constructor transfers nothing unless the
	// configured negotiation succeeds.
	t.Run("client", func(t *testing.T) {
		noTLS, noTLSMails := rfc3207PolicyServer(t, nil)
		if c, err := DialStartTLS(noTLS, &tls.Config{InsecureSkipVerify: true}); err == nil || c != nil { //nolint:gosec // never reached
			t.Fatalf("DialStartTLS without STARTTLS = (%v, %v)", c, err)
		}
		expectNoMail(t, noTLSMails)

		tls12, tls12Mails := rfc3207PolicyServer(t, func(s *Server, _ *tlsPolicyBackend) {
			s.TLSConfig = rfc3207TLSConfig(t)
			s.TLSConfig.MaxVersion = tls.VersionTLS12
		})
		if c, err := DialStartTLS(tls12, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}); err == nil || c != nil { //nolint:gosec // self-signed test certificate
			t.Fatalf("DialStartTLS below the configured TLS version = (%v, %v)", c, err)
		}
		expectNoMail(t, tls12Mails)

		c, err := DialStartTLS(tls12, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // self-signed test certificate
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if err := rfc3207Send(c); err != nil {
			t.Fatal(err)
		}
		if overTLS := <-tls12Mails; !overTLS {
			t.Fatal("required-TLS delivery not recorded as TLS")
		}
	})
}

// checklist: TLS-SEC-02
func TestRFC3207OpportunisticTLS(t *testing.T) {
	hook := testHookStartTLS
	testHookStartTLS = nil
	t.Cleanup(func() { testHookStartTLS = hook })
	// Opportunistic policy: use TLS when offered, otherwise deliver in
	// plaintext on a fresh connection.
	deliver := func(addr string) error {
		c, err := DialStartTLS(addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed test certificate
		if err != nil {
			if c, err = Dial(addr); err != nil {
				return err
			}
		}
		defer c.Close()
		return rfc3207Send(c)
	}
	for _, offered := range []bool{true, false} {
		t.Run(fmt.Sprintf("offered=%v", offered), func(t *testing.T) {
			addr, mails := rfc3207PolicyServer(t, func(s *Server, _ *tlsPolicyBackend) {
				if offered {
					s.TLSConfig = rfc3207TLSConfig(t)
				}
			})
			if err := deliver(addr); err != nil {
				t.Fatal(err)
			}
			if overTLS := <-mails; overTLS != offered {
				t.Fatalf("delivered with tls=%v, want %v", overTLS, offered)
			}
			expectNoMail(t, mails)
		})
	}
}

// checklist: TLS-POLICY-04
func TestRFC3207PeersDecideOnNegotiatedSecurity(t *testing.T) {
	hook := testHookStartTLS
	testHookStartTLS = nil
	t.Cleanup(func() { testHookStartTLS = hook })
	refuse := errors.New("negotiated security refused")

	// The client refuses the negotiated state before any SMTP command.
	t.Run("client", func(t *testing.T) {
		addr, mails := rfc3207PolicyServer(t, func(s *Server, _ *tlsPolicyBackend) {
			s.TLSConfig = rfc3207TLSConfig(t)
		})
		var checked bool
		cfg := &tls.Config{InsecureSkipVerify: true, VerifyConnection: func(tls.ConnectionState) error { //nolint:gosec // self-signed test certificate
			checked = true
			return refuse
		}}
		c, err := DialStartTLS(addr, cfg)
		if !checked || c != nil || !errors.Is(err, refuse) {
			t.Fatalf("DialStartTLS = (%v, %v), checked=%v", c, err, checked)
		}
		expectNoMail(t, mails)
	})

	// The server refuses the negotiated state; no SMTP continues on it.
	t.Run("server", func(t *testing.T) {
		sessions := make(chan bool, 4)
		addr, mails := rfc3207PolicyServer(t, func(s *Server, be *tlsPolicyBackend) {
			s.TLSConfig = rfc3207TLSConfig(t)
			s.TLSConfig.VerifyConnection = func(tls.ConnectionState) error { return refuse }
			be.requireTLS = func(c *Conn) bool {
				_, ok := c.TLSConnectionState()
				sessions <- ok
				return false
			}
		})
		c, err := Dial(addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.CommandTimeout = 2 * time.Second
		if err := c.startTLS(&tls.Config{InsecureSkipVerify: true}); err == nil { //nolint:gosec // self-signed test certificate
			// TLS 1.3 completes the client's side first; the server's
			// refusal then ends the connection before any reply.
			if err := c.Noop(); err == nil {
				t.Fatal("SMTP continued after the server refused the TLS state")
			}
		}
		if ok := <-sessions; ok {
			t.Fatal("pre-TLS session reported TLS")
		}
		select {
		case ok := <-sessions:
			t.Fatalf("server created a session (tls=%v) after refusing TLS", ok)
		default:
		}
		expectNoMail(t, mails)
	})
}

// checklist: TLS-STATE-06
func TestRFC3207CapabilitiesChangeAfterTLS(t *testing.T) {
	_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
		s.TLSConfig = rfc3207TLSConfig(t)
		s.AllowInsecureAuth = false
	})
	ehlo := func(conn net.Conn, br *bufio.Reader) []string {
		t.Helper()
		writeFlushBatch(t, conn, "EHLO client.example\r\n")
		return readFlushReply(t, br)
	}
	before := strings.Join(ehlo(raw, br), "\n")
	if strings.Contains(before, "AUTH") || !strings.Contains(before, "STARTTLS") {
		t.Fatalf("plaintext capabilities: %q", before)
	}
	writeFlushBatch(t, raw, "STARTTLS\r\n")
	if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, "220 ") {
		t.Fatalf("STARTTLS: %q", got)
	}
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed test certificate
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	tbr := bufio.NewReader(tc)
	after := ehlo(tc, tbr)
	if !containsLine(after, "250-AUTH PLAIN") && !containsLine(after, "250 AUTH PLAIN") {
		t.Fatalf("AUTH not offered over TLS: %q", after)
	}
	if strings.Contains(strings.Join(after, "\n"), "STARTTLS") {
		t.Fatalf("STARTTLS offered over TLS: %q", after)
	}
	writeFlushBatch(t, tc, "AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk\r\n")
	if got := readFlushReply(t, tbr)[0]; !strings.HasPrefix(got, "235 ") {
		t.Fatalf("AUTH over TLS: %q", got)
	}
}
