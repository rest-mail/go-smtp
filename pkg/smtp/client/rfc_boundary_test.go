package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/emersion/go-sasl"
	"github.com/rest-mail/go-smtp/pkg/smtp"
	"github.com/rest-mail/go-smtp/pkg/smtp/internal/testcert"
	"github.com/rest-mail/go-smtp/pkg/smtp/server"
)

// The deployment installs PLAIN and TLS; the transport must connect them.
// checklist: SMTP-AUTH-24
func TestRFC4954PlainOverTLS(t *testing.T) {
	for _, initial := range []bool{false, true} {
		t.Run(fmt.Sprintf("initial-response=%v", initial), func(t *testing.T) {
			events := make(chan string, 4)
			_, raw, _, _ := newFlushTestConn(t, func(s *server.Server) {
				s.AllowInsecureAuth = false
				s.TLSConfig = rfc3207TLSConfig(t)
				s.Backend = server.BackendFunc(func(c *server.Conn) (server.Session, error) {
					state, ok := c.TLSConnectionState()
					if ok && state.HandshakeComplete {
						return &submissionPolicySession{events: events}, nil
					}
					return flushAuthSession{}, nil
				})
			})
			c := New(raw)
			c.didGreet = true // The harness has consumed the greeting.
			if c.SupportsAuth(sasl.Plain) {
				t.Fatal("PLAIN advertised before TLS with insecure auth disabled")
			}
			if err := c.Auth(sasl.NewPlainClient("", "username", "password")); err == nil {
				t.Fatal("PLAIN accepted before TLS")
			} else if smtpErr, ok := err.(*smtp.SMTPError); !ok || smtpErr.Code != 530 {
				t.Fatalf("plaintext AUTH = %v, want SMTP 530", err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(testcert.LocalhostCert) {
				t.Fatal("invalid test certificate")
			}
			if err := c.startTLS(&tls.Config{RootCAs: roots, ServerName: "example.com"}); err != nil {
				t.Fatal(err)
			}
			if state, ok := c.TLSConnectionState(); !ok || !state.HandshakeComplete || len(state.VerifiedChains) == 0 {
				t.Fatalf("TLS not verified: %+v, %v", state, ok)
			}
			if !c.SupportsAuth(sasl.Plain) {
				t.Fatal("PLAIN missing after TLS")
			}
			var auth sasl.Client = sasl.NewPlainClient("", "user", "password")
			if !initial {
				auth = &boundaryPlainClient{Client: auth}
			}
			if err := c.Auth(auth); err != nil {
				t.Fatal(err)
			}
			if err := c.Mail("sender@example.org", nil); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-events:
				if got != "mail:sender@example.org" {
					t.Fatalf("authenticated backend event = %q", got)
				}
			default:
				t.Fatal("missing authenticated backend event")
			}
			if err := c.Reset(); err != nil {
				t.Fatal(err)
			}
			if err := c.Noop(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Move the same PLAIN response from AUTH's initial argument to the 334 round.
type boundaryPlainClient struct {
	sasl.Client
	response []byte
}

func (c *boundaryPlainClient) Start() (string, []byte, error) {
	mech, response, err := c.Client.Start()
	c.response = response
	return mech, nil, err
}

func (c *boundaryPlainClient) Next(challenge []byte) ([]byte, error) {
	if len(challenge) != 0 {
		return nil, fmt.Errorf("PLAIN challenge is not empty: %q", challenge)
	}
	return c.response, nil
}
