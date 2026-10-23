package server

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp/pkg/smtp"
)

type boundaryEnvelope struct {
	address string
	mail    smtp.MailOptions
	rcpt    smtp.RcptOptions
}

type boundarySession struct {
	nopSession
	envelopes chan boundaryEnvelope
	bodies    chan string
}

func (s boundarySession) Mail(address string, opts *smtp.MailOptions) error {
	s.envelopes <- boundaryEnvelope{address: address, mail: *opts}
	return nil
}

func (s boundarySession) Rcpt(address string, opts *smtp.RcptOptions) error {
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
				if !rcpt.rcpt.RequireRecipientValidSince.Equal(want) || rcpt.rcpt.RequireRecipientValidSinceAction != smtp.RRVSActionReject {
					t.Fatalf("RRVS lost at command boundary: %+v", rcpt.rcpt)
				}
			case "DELIVERBY":
				want := smtp.DeliverByOptions{Time: -999999999 * time.Second, Mode: smtp.DeliverByNotify, Trace: true}
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

type storageRefusalSession struct {
	boundarySession
	refuse bool
}

func (s *storageRefusalSession) Mail(address string, opts *smtp.MailOptions) error {
	if s.refuse {
		s.envelopes <- boundaryEnvelope{address: address, mail: *opts}
		s.refuse = false
		return &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 3, 1}, Message: "Insufficient system storage"}
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
