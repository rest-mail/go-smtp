package client

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp/pkg/smtp"
	"github.com/rest-mail/go-smtp/pkg/smtp/server"
)

// checklist: TLS-SEC-01
func TestRFC3207RequireTLSForSelectedHosts(t *testing.T) {
	hook := testHookStartTLS
	testHookStartTLS = nil
	t.Cleanup(func() { testHookStartTLS = hook })

	// Server side: a host policy refuses plaintext MAIL from a selected client
	// and accepts the same client once TLS is negotiated.
	t.Run("server", func(t *testing.T) {
		addr, mails := rfc3207PolicyServer(t, func(s *server.Server, be *tlsPolicyBackend) {
			s.TLSConfig = rfc3207TLSConfig(t)
			be.requireTLS = func(c *server.Conn) bool { return c.Hostname() == "selected.example" }
		})
		plain, err := Dial(addr)
		if err != nil {
			t.Fatal(err)
		}
		defer plain.Close()
		if err := plain.Hello("selected.example"); err != nil {
			t.Fatal(err)
		}
		var smtpErr *smtp.SMTPError
		if err := plain.Mail("a@example.org", nil); !errors.As(err, &smtpErr) || smtpErr.Code != 530 || smtpErr.EnhancedCode != (smtp.EnhancedCode{5, 7, 0}) {
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

		tls12, tls12Mails := rfc3207PolicyServer(t, func(s *server.Server, _ *tlsPolicyBackend) {
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
			addr, mails := rfc3207PolicyServer(t, func(s *server.Server, _ *tlsPolicyBackend) {
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
		addr, mails := rfc3207PolicyServer(t, func(s *server.Server, _ *tlsPolicyBackend) {
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
		addr, mails := rfc3207PolicyServer(t, func(s *server.Server, be *tlsPolicyBackend) {
			s.TLSConfig = rfc3207TLSConfig(t)
			s.TLSConfig.VerifyConnection = func(tls.ConnectionState) error { return refuse }
			be.requireTLS = func(c *server.Conn) bool {
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

// tlsPolicyBackend builds sessions from the connection's TLS state at session
// creation, which RFC 3207 §4.2 repeats after every successful STARTTLS.
type tlsPolicyBackend struct {
	requireTLS func(c *server.Conn) bool
	mails      chan bool
}

func (b tlsPolicyBackend) NewSession(c *server.Conn) (server.Session, error) {
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
func rfc3207PolicyServer(t *testing.T, configure func(*server.Server, *tlsPolicyBackend)) (string, <-chan bool) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	be := &tlsPolicyBackend{mails: make(chan bool, 4)}
	s := server.New(be)
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

// tlsPolicySession records whether each accepted MAIL arrived over TLS and,
// when requireTLS is set, refuses plaintext MAIL as a host policy would.
type tlsPolicySession struct {
	nopSession
	tls        bool
	requireTLS bool
	mails      chan<- bool
}

func (s tlsPolicySession) Mail(string, *smtp.MailOptions) error {
	if s.requireTLS && !s.tls {
		return &smtp.SMTPError{Code: 530, EnhancedCode: smtp.EnhancedCode{5, 7, 0}, Message: "Must issue a STARTTLS command first"}
	}
	s.mails <- s.tls
	return nil
}
