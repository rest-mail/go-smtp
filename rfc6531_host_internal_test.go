package smtp

import (
	"errors"
	"io"
	"strings"
	"testing"
)

type utf8HostMessage struct {
	from string
	utf8 bool
	body string
}
type utf8HostSession struct {
	nopSession
	message utf8HostMessage
	got     chan utf8HostMessage
	deliver func(utf8HostMessage) error
}

func (s *utf8HostSession) Mail(from string, o *MailOptions) error {
	s.message = utf8HostMessage{from: from, utf8: o.UTF8}
	return nil
}
func (s *utf8HostSession) Data(r io.Reader) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.message.body = string(b)
	if s.got != nil {
		s.got <- s.message
	}
	if s.deliver != nil {
		return s.deliver(s.message)
	}
	return nil
}
func utf8HostClient(t *testing.T, enable bool, session Session) (*Client, *writeCountingConn) {
	t.Helper()
	_, raw, _, _ := newFlushTestConn(t, func(s *Server) {
		s.EnableSMTPUTF8 = enable
		s.Backend = BackendFunc(func(*Conn) (Session, error) { return session, nil })
	})
	wire := &writeCountingConn{Conn: raw}
	c := NewClient(wire)
	c.didGreet = true // harness consumed the actual greeting
	t.Cleanup(func() { c.Close() })
	return c, wire
}
func utf8HostSend(c *Client, body string, useUTF8 bool) error {
	if err := c.Mail("sender@example.org", &MailOptions{UTF8: useUTF8}); err != nil {
		return err
	}
	if err := c.Rcpt("recipient@example.org", nil); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err = io.WriteString(w, body); err != nil {
		return err
	}
	return w.Close()
}

// The host knows the message requires SMTPUTF8 even with an ASCII envelope.
// Its explicit flag protects UTF-8 headers at any MIME nesting depth; it does
// not make the streaming client inspect or automatically classify content.
// checklist: UTF8-BODY-01
func TestRFC6531DeclaredInternationalizedHeaders(t *testing.T) {
	bodies := []string{
		"From: sender@example.org\r\nTo: recipient@example.org\r\nSubject: café\r\n\r\nbody\r\n",
		"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=part\r\n\r\n--part\r\nContent-Type: message/rfc822\r\n\r\nFrom: sender@example.org\r\nSubject: café\r\n\r\nnested\r\n--part--\r\n",
	}
	for _, enabled := range []bool{false, true} {
		for _, body := range bodies {
			t.Run(strings.Split(body, "\r\n")[0]+"/enabled="+map[bool]string{true: "yes", false: "no"}[enabled], func(t *testing.T) {
				got := make(chan utf8HostMessage, 2)
				c, wire := utf8HostClient(t, enabled, &utf8HostSession{got: got})
				err := utf8HostSend(c, body, true)
				if enabled {
					if err != nil {
						t.Fatal(err)
					}
					m := <-got
					if !m.utf8 || m.from != "sender@example.org" || m.body != body {
						t.Fatalf("message=%+v", m)
					}
					if written := strings.Join(wire.takeWrites(), ""); !strings.Contains(written, " SMTPUTF8\r\n") || !strings.Contains(written, body) {
						t.Fatalf("missing flag/content: %q", written)
					}
				} else {
					if err == nil {
						t.Fatal("non-SMTPUTF8 peer accepted declared internationalized message")
					}
					if written := strings.Join(wire.takeWrites(), ""); strings.Contains(written, "MAIL ") || strings.Contains(written, "DATA\r\n") || strings.Contains(written, "café") {
						t.Fatalf("refused content leaked: %q", written)
					}
					if len(got) != 0 {
						t.Fatal("refused message reached backend")
					}
				}
				// Refusal and success both leave the connection usable for ASCII mail.
				const ascii = "Subject: plain\r\n\r\nbody\r\n"
				if err := utf8HostSend(c, ascii, false); err != nil {
					t.Fatal(err)
				}
				m := <-got
				if m.utf8 || m.body != ascii {
					t.Fatalf("ASCII retry=%+v", m)
				}
				if err := c.Noop(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// A configured relay host selects RFC 6531 section 3.2's reject option.
// Neither retry, downgrade nor notification generation is supplied by the
// transport. Both hops below are actual SMTP connections.
// checklist: UTF8-DOWN-01
func TestRFC6531HostRejectsUnsupportedNextHop(t *testing.T) {
	delivered := make(chan utf8HostMessage, 1)
	next, nextWire := utf8HostClient(t, false, &utf8HostSession{got: delivered})
	relay := &utf8HostSession{deliver: func(m utf8HostMessage) error {
		err := utf8HostSend(next, m.body, m.utf8)
		if err != nil {
			return &SMTPError{Code: 550, EnhancedCode: EnhancedCode{5, 6, 7}, Message: "Next hop cannot accept internationalized mail"}
		}
		return nil
	}}
	incoming, _ := utf8HostClient(t, true, relay)
	const international = "Subject: café\r\n\r\nbody\r\n"
	err := utf8HostSend(incoming, international, true)
	var se *SMTPError
	if !errors.As(err, &se) || se.Code != 550 || se.EnhancedCode != (EnhancedCode{5, 6, 7}) {
		t.Fatalf("upstream rejection=%v", err)
	}
	if written := strings.Join(nextWire.takeWrites(), ""); strings.Contains(written, "MAIL ") || strings.Contains(written, "DATA\r\n") || strings.Contains(written, "café") {
		t.Fatalf("unsupported hop received message: %q", written)
	}
	if len(delivered) != 0 {
		t.Fatal("unsupported message delivered")
	}
	const ascii = "Subject: plain\r\n\r\nbody\r\n"
	if err := utf8HostSend(incoming, ascii, false); err != nil {
		t.Fatal(err)
	}
	if m := <-delivered; m.utf8 || m.body != ascii {
		t.Fatalf("relay recovery=%+v", m)
	}
	if err := incoming.Noop(); err != nil {
		t.Fatal(err)
	}
	if err := next.Noop(); err != nil {
		t.Fatal(err)
	}
}
