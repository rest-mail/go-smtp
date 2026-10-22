package smtp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
)

type boundaryEnvelope struct {
	address string
	mail    MailOptions
	rcpt    RcptOptions
}

type boundarySession struct {
	nopSession
	envelopes chan boundaryEnvelope
	bodies    chan string
}

func (s boundarySession) Mail(address string, opts *MailOptions) error {
	s.envelopes <- boundaryEnvelope{address: address, mail: *opts}
	return nil
}

func (s boundarySession) Rcpt(address string, opts *RcptOptions) error {
	s.envelopes <- boundaryEnvelope{address: address, rcpt: *opts}
	return nil
}

func (s boundarySession) Data(r io.Reader) error {
	body, err := io.ReadAll(r)
	if err == nil {
		s.bodies <- string(body)
	}
	return err
}

// Replies are read before these checks, so every expected backend event must
// already be present. Fail immediately if an event is missing.
func readBoundaryEnvelope(t *testing.T, events <-chan boundaryEnvelope) boundaryEnvelope {
	t.Helper()
	select {
	case event := <-events:
		return event
	default:
		t.Fatal("missing backend envelope event")
		return boundaryEnvelope{}
	}
}

func readBoundaryBody(t *testing.T, bodies <-chan string) string {
	t.Helper()
	select {
	case body := <-bodies:
		return body
	default:
		t.Fatal("missing backend body")
		return ""
	}
}

// The default budget must accept each RFC's extended command, including CRLF.
// Padding the base command to 512 octets keeps the mailbox itself within the
// path limit. Check the parsed option as well as delivery and subsequent framing.
// checklist: UTF8-MAIL-04 RRVS-LEN-01 BY-LEN-01
func TestRFCExtendedCommandBudgets(t *testing.T) {
	for _, tc := range []struct {
		name, parameter string
		extra           int
		rcpt            bool
	}{
		{"SMTPUTF8", "  SMTPUTF8", 10, false},
		{"RRVS", " RRVS=2014-04-03T23:01:00+01:00;R", 33, true},
		{"DELIVERBY", " BY=-999999999;NT", 17, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			envelopes := make(chan boundaryEnvelope, 4)
			bodies := make(chan string, 1)
			_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
				s.EnableSMTPUTF8 = true
				s.EnableRRVS = true
				s.EnableDELIVERBY = true
				s.Backend = BackendFunc(func(*Conn) (Session, error) {
					return boundarySession{envelopes: envelopes, bodies: bodies}, nil
				})
			})
			command := func(line, want string) []string {
				t.Helper()
				writeFlushBatch(t, raw, line+"\r\n")
				reply := readFlushReply(t, br)
				if !strings.HasPrefix(reply[0], want) {
					t.Fatalf("%d-octet command: reply %q, want %s", len(line)+2, reply, want)
				}
				return reply
			}
			caps := strings.Join(command("EHLO client.example", "250"), "\n")
			if !strings.Contains(caps, tc.name) {
				t.Fatalf("missing %s advertisement: %s", tc.name, caps)
			}
			base := "MAIL FROM:<sender@example.org>"
			if tc.rcpt {
				command(base, "250 ")
				base = "RCPT TO:<recipient@example.org>"
			}
			line := base + strings.Repeat(" ", 512-len(base)-2) + tc.parameter
			if len(line)+2 != 512+tc.extra {
				t.Fatalf("command length = %d, want %d", len(line)+2, 512+tc.extra)
			}
			command(line, "250 ")
			if !tc.rcpt {
				command("RCPT TO:<recipient@example.org>", "250 ")
			}
			mail, rcpt := readBoundaryEnvelope(t, envelopes), readBoundaryEnvelope(t, envelopes)
			if mail.address != "sender@example.org" || rcpt.address != "recipient@example.org" {
				t.Fatalf("backend envelope: %+v, %+v", mail, rcpt)
			}
			switch tc.name {
			case "SMTPUTF8":
				if !mail.mail.UTF8 {
					t.Fatal("SMTPUTF8 lost at command boundary")
				}
			case "RRVS":
				want := time.Date(2014, 4, 3, 22, 1, 0, 0, time.UTC)
				if !rcpt.rcpt.RequireRecipientValidSince.Equal(want) || rcpt.rcpt.RequireRecipientValidSinceAction != RRVSActionReject {
					t.Fatalf("RRVS lost at command boundary: %+v", rcpt.rcpt)
				}
			case "DELIVERBY":
				want := DeliverByOptions{Time: -999999999 * time.Second, Mode: DeliverByNotify, Trace: true}
				if mail.mail.DeliverBy == nil || *mail.mail.DeliverBy != want {
					t.Fatalf("BY lost at command boundary: %+v", mail.mail.DeliverBy)
				}
			}
			command("DATA", "354 ")
			command("Subject: boundary\r\n\r\nbody\r\n.", "250 ")
			if got := readBoundaryBody(t, bodies); got != "Subject: boundary\r\n\r\nbody\r\n" {
				t.Fatalf("delivered body = %q", got)
			}
			command("NOOP", "250 ")
			command("QUIT", "221 ")
		})
	}
}

// The deployment installs PLAIN and TLS; the transport must connect them.
// checklist: SMTP-AUTH-24
func TestRFC4954PlainOverTLS(t *testing.T) {
	for _, initial := range []bool{false, true} {
		t.Run(fmt.Sprintf("initial-response=%v", initial), func(t *testing.T) {
			events := make(chan string, 4)
			_, raw, _, _ := newFlushTestConn(t, func(s *Server) {
				s.AllowInsecureAuth = false
				s.TLSConfig = rfc3207TLSConfig(t)
				s.Backend = BackendFunc(func(c *Conn) (Session, error) {
					state, ok := c.TLSConnectionState()
					if ok && state.HandshakeComplete {
						return &submissionPolicySession{events: events}, nil
					}
					return flushAuthSession{}, nil
				})
			})
			c := NewClient(raw)
			c.didGreet = true // The harness has consumed the greeting.
			if c.SupportsAuth(sasl.Plain) {
				t.Fatal("PLAIN advertised before TLS with insecure auth disabled")
			}
			if err := c.Auth(sasl.NewPlainClient("", "username", "password")); err == nil {
				t.Fatal("PLAIN accepted before TLS")
			} else if smtpErr, ok := err.(*SMTPError); !ok || smtpErr.Code != 530 {
				t.Fatalf("plaintext AUTH = %v, want SMTP 530", err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(localhostCert) {
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

type storageRefusalSession struct {
	boundarySession
	refuse bool
}

func (s *storageRefusalSession) Mail(address string, opts *MailOptions) error {
	if s.refuse {
		s.envelopes <- boundaryEnvelope{address: address, mail: *opts}
		s.refuse = false
		return &SMTPError{Code: 452, EnhancedCode: EnhancedCode{4, 3, 1}, Message: "Insufficient system storage"}
	}
	return s.boundarySession.Mail(address, opts)
}

// Storage availability is a backend decision; its 452 must survive the wire
// and leave no active transaction. A later attempt can succeed on this session.
// checklist: SIZE-REPLY-03
func TestRFC1870TemporaryStorageRefusal(t *testing.T) {
	envelopes := make(chan boundaryEnvelope, 4)
	bodies := make(chan string, 1)
	_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
		s.Backend = BackendFunc(func(*Conn) (Session, error) {
			return &storageRefusalSession{boundarySession: boundarySession{envelopes: envelopes, bodies: bodies}, refuse: true}, nil
		})
	})
	command := func(line, want string) {
		t.Helper()
		writeFlushBatch(t, raw, line+"\r\n")
		if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, want) {
			t.Fatalf("%s: got %q, want %s", line, got, want)
		}
	}
	command("EHLO client.example", "250")
	command("MAIL FROM:<sender@example.org> SIZE=42", "452 4.3.1 Insufficient system storage")
	if got := readBoundaryEnvelope(t, envelopes); got.address != "sender@example.org" || got.mail.Size != 42 {
		t.Fatalf("refused declaration: %+v", got)
	}
	command("RCPT TO:<recipient@example.org>", "503 ")
	command("DATA", "503 ")
	command("NOOP", "250 ")
	if len(envelopes) != 0 || len(bodies) != 0 {
		t.Fatal("refused MAIL admitted recipient or data")
	}
	command("RSET", "250 ")
	command("MAIL FROM:<sender@example.org> SIZE=42", "250 ")
	command("RCPT TO:<recipient@example.org>", "250 ")
	mail, rcpt := readBoundaryEnvelope(t, envelopes), readBoundaryEnvelope(t, envelopes)
	if mail.address != "sender@example.org" || mail.mail.Size != 42 || rcpt.address != "recipient@example.org" {
		t.Fatalf("retried envelope: %+v, %+v", mail, rcpt)
	}
	command("DATA", "354 ")
	command("Subject: retry\r\n\r\nbody\r\n.", "250 ")
	if got := readBoundaryBody(t, bodies); got != "Subject: retry\r\n\r\nbody\r\n" {
		t.Fatalf("retried body = %q", got)
	}
	command("QUIT", "221 ")
}
