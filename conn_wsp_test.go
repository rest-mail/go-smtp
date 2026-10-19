package smtp_test

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"

	smtp "github.com/rest-mail/go-smtp"
)

// Only SP and HTAB separate the words of a command (RFC 5321 §4.1.2). The
// bytes of a Unicode space such as U+0085 NEL or U+00A0 NBSP are content: they
// are kept in a value, and where the grammar asks for ASCII they make the
// argument malformed rather than being trimmed away.

// checklist: SMTP-SYN-07
func TestMailUnicodeSpaceIsNotSeparator(t *testing.T) {
	for _, tc := range []struct {
		line, want string
	}{
		// Not whitespace, so nothing separates the path from what follows.
		{"MAIL FROM:<root@nsa.gov>\u0085", "501 5.5.2 "},
		{"MAIL FROM:<root@nsa.gov> SIZE=10", "501 5.5.2 "},
		// Not whitespace before the path either.
		{"MAIL FROM: <root@nsa.gov>", "501 5.5.2 "},
		// Inside and at the end of a value it stays in the value.
		{"MAIL FROM:<root@nsa.gov> BODY=8BIT\u0085MIME", "501 5.5.4 "},
		{"MAIL FROM:<root@nsa.gov> BODY=8BITMIME\u0085", "501 5.5.4 "},
		{"MAIL FROM:<root@nsa.gov> SIZE=10 ", "501 5.5.4 "},
		// SP and HTAB still separate.
		{"MAIL FROM:<root@nsa.gov>\tBODY=8BITMIME SIZE=10", "250 "},
	} {
		t.Run(tc.line, func(t *testing.T) {
			_, s, c, scanner := testServerAuthenticated(t)
			defer s.Close()
			defer c.Close()

			io.WriteString(c, tc.line+"\r\n")
			scanner.Scan()
			if !strings.HasPrefix(scanner.Text(), tc.want) {
				t.Fatalf("%q: got %q, want %q", tc.line, scanner.Text(), tc.want)
			}
		})
	}
}

// checklist: SMTP-SYN-07
func TestRcptUnicodeSpaceIsNotSeparator(t *testing.T) {
	for _, tc := range []struct {
		line, want string
	}{
		{"RCPT TO:<root@gchq.gov.uk>\u0085", "501 5.5.2 "},
		{"RCPT TO:<root@gchq.gov.uk> NOTIFY=NEVER", "501 5.5.2 "},
		{"RCPT TO: <root@gchq.gov.uk>", "501 5.5.2 "},
		{"RCPT TO:<root@gchq.gov.uk> NOTIFY=NE\u0085VER", "501 5.5.4 "},
		{"RCPT TO:<root@gchq.gov.uk> NOTIFY=NEVER\u0085", "501 5.5.4 "},
		{"RCPT TO:<root@gchq.gov.uk>\tNOTIFY=NEVER", "250 "},
	} {
		t.Run(tc.line, func(t *testing.T) {
			_, s, c, scanner, _ := testServerEhlo(t, func(s *smtp.Server) {
				s.EnableDSN = true
			})
			defer s.Close()
			defer c.Close()

			io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
			scanner.Scan()
			if !strings.HasPrefix(scanner.Text(), "250 ") {
				t.Fatal("Invalid MAIL response:", scanner.Text())
			}

			io.WriteString(c, tc.line+"\r\n")
			scanner.Scan()
			if !strings.HasPrefix(scanner.Text(), tc.want) {
				t.Fatalf("%q: got %q, want %q", tc.line, scanner.Text(), tc.want)
			}
		})
	}
}

// checklist: SMTP-EXT-13
func TestServerXClientKeepsUnicodeSpaceInValue(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	be := &xclientBackend{ch: make(chan *smtp.XClientAttrs, 1)}
	s := smtp.NewServer(be)
	s.Domain = "localhost"
	s.EnableXCLIENT = true
	s.TrustXCLIENT = func(*smtp.Conn) bool { return true }
	go s.Serve(l)
	defer s.Close()

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	scanner := bufio.NewScanner(c)
	scanner.Scan() // 220

	io.WriteString(c, "XCLIENT NAME=client\u0085example\tLOGIN=alice \r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "220 ") {
		t.Fatalf("XCLIENT should be honored with a fresh 220 greeting, got: %q", scanner.Text())
	}
	readEHLOCaps(t, c, scanner)

	select {
	case attrs := <-be.ch:
		if attrs == nil {
			t.Fatal("Conn.XClient() was nil after a trusted XCLIENT")
		}
		if attrs.Name != "client\u0085example" {
			t.Errorf("Name = %q, want %q", attrs.Name, "client\u0085example")
		}
		if attrs.Login != "alice " {
			t.Errorf("Login = %q, want %q", attrs.Login, "alice ")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("NewSession was not called after EHLO")
	}
}

// mechBackend offers PLAIN only, and refuses any other mechanism name.
type mechBackend struct{}

func (mechBackend) NewSession(*smtp.Conn) (smtp.Session, error) { return mechSession{}, nil }

type mechSession struct{ ctxSession }

func (mechSession) AuthMechanisms() []string { return []string{sasl.Plain} }

func (mechSession) Auth(mech string) (sasl.Server, error) {
	if mech != sasl.Plain {
		return nil, smtp.ErrAuthUnknownMechanism
	}
	return sasl.NewPlainServer(func(identity, username, password string) error {
		return nil
	}), nil
}

// checklist: SMTP-EXT-08
func TestServerAuthUnicodeSpaceIsNotSeparator(t *testing.T) {
	const ir = "AHVzZXJuYW1lAHBhc3N3b3Jk"
	for _, tc := range []struct {
		line, want string
	}{
		// The mechanism name is ASCII: one with a NEL or NBSP is unknown.
		{"AUTH PLAIN\u0085", "504 5.7.4 "},
		{"AUTH PLAIN " + ir, "504 5.7.4 "},
		// The initial response is base64: a NEL or NBSP makes it invalid.
		{"AUTH PLAIN " + ir + "\u0085", "454 4.7.0 "},
		{"AUTH PLAIN AHVz ZXJuYW1lAHBhc3N3b3Jk", "454 4.7.0 "},
		{"AUTH PLAIN\t" + ir, "235 "},
	} {
		t.Run(tc.line, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			s := smtp.NewServer(mechBackend{})
			s.Domain = "localhost"
			s.AllowInsecureAuth = true
			go s.Serve(l)
			defer s.Close()

			c, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			scanner := bufio.NewScanner(c)
			scanner.Scan() // 220
			readEHLOCaps(t, c, scanner)

			io.WriteString(c, tc.line+"\r\n")
			scanner.Scan()
			if !strings.HasPrefix(scanner.Text(), tc.want) {
				t.Fatalf("%q: got %q, want %q", tc.line, scanner.Text(), tc.want)
			}
		})
	}
}

// checklist: SMTP-EXT-05
func TestServerBdatUnicodeSpaceIsNotSeparator(t *testing.T) {
	for _, tc := range []struct {
		line, want string
	}{
		// The chunk size is ASCII digits.
		{"BDAT 8\u0085", "501 5.5.4 Malformed size"},
		{"BDAT 8 LAST", "501 5.5.4 Malformed size"},
		// LAST is ASCII.
		{"BDAT 8 LAST ", "501 5.5.4 Unknown BDAT argument"},
		{"BDAT 8 LA\u0085ST", "501 5.5.4 Unknown BDAT argument"},
		{"BDAT 8\tLAST", "250 "},
	} {
		t.Run(tc.line, func(t *testing.T) {
			_, s, c, scanner := testServerAuthenticated(t)
			defer s.Close()
			defer c.Close()

			io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
			scanner.Scan()
			if !strings.HasPrefix(scanner.Text(), "250 ") {
				t.Fatal("Invalid MAIL response:", scanner.Text())
			}
			io.WriteString(c, "RCPT TO:<root@gchq.gov.uk>\r\n")
			scanner.Scan()
			if !strings.HasPrefix(scanner.Text(), "250 ") {
				t.Fatal("Invalid RCPT response:", scanner.Text())
			}

			// Send the chunk either way, so a server that wrongly accepts the
			// size answers rather than waiting for it.
			io.WriteString(c, tc.line+"\r\nHey <3\r\n")
			scanner.Scan()
			if !strings.HasPrefix(scanner.Text(), tc.want) {
				t.Fatalf("%q: got %q, want %q", tc.line, scanner.Text(), tc.want)
			}
		})
	}
}
