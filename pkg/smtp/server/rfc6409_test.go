package server

import (
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/rest-mail/go-smtp/pkg/smtp"
)

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
			return ErrAuthFailed
		}
		s.authorized = true
		return nil
	}), nil
}

func (s *submissionPolicySession) Mail(from string, _ *smtp.MailOptions) error {
	if !s.authorized {
		s.events <- "denied:" + from
		return ErrAuthRequired
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

// checklist: SUB-AUTH-01 SUB-AUTH-03 SUB-NULL-01
func TestRFC6409SubmissionAuthentication(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		for _, preauthorized := range []bool{false, true} {
			t.Run(fmt.Sprintf("BDAT=%v/preauthorized=%v", chunked, preauthorized), func(t *testing.T) {
				events := make(chan string, 32)
				_, raw, br, done := newFlushTestConn(t, func(s *Server) {
					// PLAIN over a pipe is for this test only. Production submission
					// should use TLS; the STARTTLS audit covers that transport.
					s.Backend = BackendFunc(func(*Conn) (Session, error) {
						return &submissionPolicySession{authorized: preauthorized, events: events}, nil
					})
				})
				command := func(cmd, want string) {
					t.Helper()
					writeFlushBatch(t, raw, cmd+"\r\n")
					if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, want) {
						t.Fatalf("%s: got %q, want prefix %q", cmd, got, want)
					}
				}
				event := func(want string) {
					t.Helper()
					select {
					case got := <-events:
						if got != want {
							t.Fatalf("backend event = %q, want %q", got, want)
						}
					default:
						t.Fatalf("missing backend event %q", want)
					}
				}

				writeFlushBatch(t, raw, "EHLO client.example.net\r\n")
				if caps := strings.Join(readFlushReply(t, br), "\n"); !strings.Contains(caps, "250-AUTH PLAIN\n") {
					t.Fatalf("AUTH not advertised: %s", caps)
				}
				if !preauthorized {
					for _, from := range []string{"user@example.net", "", "user@example.net"} {
						command("MAIL FROM:<"+from+">", "530 5.7.0 Please authenticate first")
						event("denied:" + from)
						command("RCPT TO:<recipient@example.net>", "503 ")
						command("DATA", "503 ")
						command("BDAT 0 LAST", "503 ")
						command("NOOP", "250 ")
					}
					bad := base64.StdEncoding.EncodeToString([]byte("\x00user\x00wrong"))
					command("AUTH PLAIN "+bad, "535 5.7.8 ")
					command("MAIL FROM:<user@example.net>", "530 5.7.0 ")
					event("denied:user@example.net")
					good := base64.StdEncoding.EncodeToString([]byte("\x00user\x00password"))
					command("AUTH PLAIN "+good, "235 2.7.0 ")
				}

				// Null reverse paths remain legal once authorized. RSET, repeated
				// EHLO and message completion must keep the session usable.
				const body = "From: user@example.net\r\n\r\nsubmission\r\n"
				for _, reset := range []string{"RSET", "EHLO client.example.net", "NOOP"} {
					command(reset, "250")
					command("MAIL FROM:<>", "250 ")
					event("mail:")
					command("RCPT TO:<recipient@example.net>", "250 ")
					event("rcpt:recipient@example.net")
					if chunked {
						command(fmt.Sprintf("BDAT %d LAST\r\n%s", len(body), strings.TrimSuffix(body, "\r\n")), "250 ")
					} else {
						command("DATA", "354 ")
						command(body+".", "250 ")
					}
					event("data:" + body)
				}
				command("QUIT", "221 ")
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("connection did not close after QUIT")
				}
				select {
				case got := <-events:
					t.Fatalf("unexpected backend call: %q", got)
				default:
				}
			})
		}
	}
}

// RFC 6409 §§5–7 list the extensions a submission server should or must
// offer, and two it must not. ETRN and ATRN are unknown commands here, so
// they are neither advertised nor accepted. §5.1 and §8.8 then hold for an
// authorized session: malformed envelope paths get 501 before the backend
// sees them, and valid paths reach it byte for byte, never rewritten.
// checklist: SUB-EXT-01 SUB-EXT-02 SUB-SYN-01 SUB-MOD-01
func TestRFC6409SubmissionExtensions(t *testing.T) {
	events := make(chan string, 8)
	_, raw, br, done := newFlushTestConn(t, func(s *Server) {
		s.EnableDSN = true
		s.Backend = BackendFunc(func(*Conn) (Session, error) {
			return &submissionPolicySession{authorized: true, events: events}, nil
		})
	})
	command := func(cmd, want string) {
		t.Helper()
		writeFlushBatch(t, raw, cmd+"\r\n")
		if got := readFlushReply(t, br); len(got) != 1 || !strings.HasPrefix(got[0], want) {
			t.Fatalf("%s: got %q, want prefix %q", cmd, got, want)
		}
	}
	event := func(want string) {
		t.Helper()
		select {
		case got := <-events:
			if got != want {
				t.Fatalf("backend event = %q, want %q", got, want)
			}
		default:
			t.Fatalf("missing backend event %q", want)
		}
	}

	writeFlushBatch(t, raw, "EHLO client.example.net\r\n")
	lines := readFlushReply(t, br)
	offered := make(map[string]bool)
	for _, line := range lines[1:] {
		keyword, _, _ := strings.Cut(line[4:], " ")
		offered[keyword] = true
	}
	for _, want := range []string{"PIPELINING", "ENHANCEDSTATUSCODES", "DSN", "8BITMIME", "AUTH"} {
		if !offered[want] {
			t.Errorf("EHLO does not advertise %s: %q", want, lines)
		}
	}
	for _, banned := range []string{"ETRN", "ATRN"} {
		if offered[banned] {
			t.Errorf("EHLO advertises %s: %q", banned, lines)
		}
	}

	for _, cmd := range []string{"ETRN example.net", "ETRN @example.net", "ATRN example.net"} {
		command(cmd, "500 5.5.2 ")
	}
	command("NOOP", "250 ")

	for _, bad := range []string{"<user@@example.net>", "<a b@example.net>", "<user@example.net"} {
		command("MAIL FROM:"+bad, "501 ")
	}
	const from = "User.Name+tag@Sub.Example.NET"
	command("MAIL FROM:<"+from+">", "250 ")
	event("mail:" + from)
	for _, bad := range []string{"<rcpt@@example.net>", "<a b@example.net>", "<rcpt@example.net"} {
		command("RCPT TO:"+bad, "501 ")
	}
	const to = "Mixed.Case+tag@Sub.Example.NET"
	command("RCPT TO:<"+to+">", "250 ")
	event("rcpt:" + to)
	command("QUIT", "221 ")
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connection did not close after QUIT")
	}
	select {
	case got := <-events:
		t.Fatalf("unexpected backend call: %q", got)
	default:
	}
}
