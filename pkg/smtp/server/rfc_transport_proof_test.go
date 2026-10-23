package server

import (
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/rest-mail/go-smtp/pkg/smtp"
	"github.com/rest-mail/go-smtp/pkg/smtp/client"
)

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

func transportProofClient(t *testing.T, session Session, configure func(*Server)) (*client.Client, *writeCountingConn) {
	t.Helper()
	s := New(BackendFunc(func(*Conn) (Session, error) { return session, nil }))
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
	c := client.New(wc)
	c.CommandTimeout = 5 * time.Second
	c.SubmissionTimeout = 5 * time.Second
	t.Cleanup(func() {
		c.Close()
		s.Close()
		if err := <-done; err != nil && err != ErrServerClosed {
			t.Errorf("Serve: %v", err)
		}
	})
	return c, wc
}

// checklist: PRI-TIME-01
func TestRFC6710IndependentDeliverByOnWire(t *testing.T) {
	for _, priority := range []bool{false, true} {
		for _, by := range []bool{false, true} {
			t.Run(fmt.Sprintf("priority=%v/by=%v", priority, by), func(t *testing.T) {
				got := make(chan *smtp.MailOptions, 2)
				data := make(chan string, 1)
				c, _ := transportProofClient(t, transportProofSession{mail: func(_ string, o *smtp.MailOptions) error { got <- o; return nil }, data: data}, func(s *Server) { s.EnableMTPRIORITY = priority; s.EnableDELIVERBY = by })
				for name, want := range map[string]bool{"MT-PRIORITY": priority, "DELIVERBY": by} {
					ok, _ := c.Extension(name)
					if ok != want {
						t.Fatalf("%s=%v, want %v", name, ok, want)
					}
				}
				p := -9
				// Each option is independently refused when its capability is off.
				if !priority {
					if err := c.Mail("a@example.org", &smtp.MailOptions{MTPriority: &p}); err == nil {
						t.Fatal("unadvertised priority accepted")
					}
				}
				if !by {
					if err := c.Mail("a@example.org", &smtp.MailOptions{DeliverBy: &smtp.DeliverByOptions{Time: time.Minute, Mode: smtp.DeliverByReturn}}); err == nil {
						t.Fatal("unadvertised DELIVERBY accepted")
					}
				}
				if len(got) != 0 {
					t.Fatal("refused option reached backend")
				}
				opts := &smtp.MailOptions{}
				if priority {
					opts.MTPriority = &p
				}
				if by {
					opts.DeliverBy = &smtp.DeliverByOptions{Time: 120 * time.Second, Mode: smtp.DeliverByReturn, Trace: true}
				}
				if err := c.Mail("a@example.org", opts); err != nil {
					t.Fatal(err)
				}
				if len(got) != 1 {
					t.Fatalf("MAIL calls=%d", len(got))
				}
				o := <-got
				if !reflect.DeepEqual(o.MTPriority, opts.MTPriority) || !reflect.DeepEqual(o.DeliverBy, opts.DeliverBy) {
					t.Fatalf("options=%+v want %+v", o, opts)
				}
				if err := c.Rcpt("b@example.org", nil); err != nil {
					t.Fatal(err)
				}
				w, err := c.Data()
				if err != nil {
					t.Fatal(err)
				}
				const body = "Subject: independent\r\n\r\ncontent\r\n"
				if _, err = io.WriteString(w, body); err != nil {
					t.Fatal(err)
				}
				if err = w.Close(); err != nil {
					t.Fatal(err)
				}
				if len(data) != 1 {
					t.Fatalf("DATA calls=%d", len(data))
				}
				if got := <-data; got != body {
					t.Fatalf("body=%q", got)
				}
				if err := c.Quit(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// checklist: MIME-CLIENT-03
func TestRFC3030ClientRefusesBinaryOnWire(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			data := make(chan string, 1)
			mails := make(chan smtp.BodyType, 2)
			c, wc := transportProofClient(t, transportProofSession{mail: func(_ string, o *smtp.MailOptions) error { mails <- o.Body; return nil }, data: data}, func(s *Server) { s.EnableBINARYMIME = enabled })
			advertised, _ := c.Extension("BINARYMIME")
			if advertised != enabled {
				t.Fatal("wrong binary advertisement")
			}
			wc.takeWrites()
			if err := c.Mail("a@example.org", &smtp.MailOptions{Body: smtp.BodyBinaryMIME}); err == nil {
				t.Fatal("binary MAIL accepted without a BDAT sender")
			}
			if writes := wc.takeWrites(); len(writes) != 0 || len(mails) != 0 {
				t.Fatalf("refused binary leaked: %q, calls=%d", writes, len(mails))
			}
			// Refusal leaves no transaction: ordinary text can be delivered afterwards.
			if err := c.Mail("a@example.org", &smtp.MailOptions{Body: smtp.Body7Bit}); err != nil {
				t.Fatal(err)
			}
			if len(mails) != 1 {
				t.Fatalf("MAIL calls=%d", len(mails))
			}
			if got := <-mails; got != smtp.Body7Bit {
				t.Fatal(got)
			}
			if err := c.Rcpt("b@example.org", nil); err != nil {
				t.Fatal(err)
			}
			w, err := c.Data()
			if err != nil {
				t.Fatal(err)
			}
			const body = "Subject: text\r\n\r\nseven bit\r\n"
			if _, err = io.WriteString(w, body); err != nil {
				t.Fatal(err)
			}
			if err = w.Close(); err != nil {
				t.Fatal(err)
			}
			if len(data) != 1 {
				t.Fatalf("DATA calls=%d", len(data))
			}
			if got := <-data; got != body {
				t.Fatalf("data=%q", got)
			}
			if err := c.Quit(); err != nil {
				t.Fatal(err)
			}
			if wire := strings.Join(wc.takeWrites(), ""); strings.Contains(wire, "BINARYMIME") || strings.Contains(wire, "BDAT") {
				t.Fatalf("binary on wire: %q", wire)
			}
		})
	}
}

// checklist: PIPE-CLIENT-08
func TestRFC2920ExtensionCommandBetweenGroups(t *testing.T) {
	data := make(chan string, 1)
	c, wc := transportProofClient(t, transportProofSession{data: data}, nil)
	p, err := c.Pipeline()
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Reset(); err != nil {
		t.Fatal(err)
	}
	if results := p.Wait(); len(results) != 1 || results[0] != nil {
		t.Fatalf("first group: %v", results)
	}
	// AUTH is an extension command outside the API's three queueable verbs.
	// Finish its whole exchange before starting the next group.
	if err = c.Auth(sasl.NewPlainClient("", "username", "password")); err != nil {
		t.Fatal(err)
	}
	if err = p.Mail("a@example.org", nil); err != nil {
		t.Fatal(err)
	}
	if err = p.Rcpt("b@example.org", nil); err != nil {
		t.Fatal(err)
	}
	if results := p.Wait(); len(results) != 2 || results[0] != nil || results[1] != nil {
		t.Fatalf("second group: %v", results)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	const body = "Subject: groups\r\n\r\nbody\r\n"
	if _, err = io.WriteString(w, body); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if len(data) != 1 {
		t.Fatalf("DATA calls=%d", len(data))
	}
	if got := <-data; got != body {
		t.Fatalf("data=%q", got)
	}
	if err = c.Quit(); err != nil {
		t.Fatal(err)
	}
	want := "EHLO localhost\r\nRSET\r\nAUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk\r\nMAIL FROM:<a@example.org> BODY=8BITMIME\r\nRCPT TO:<b@example.org>\r\nDATA\r\n" + body + ".\r\nQUIT\r\n"
	if wire := strings.Join(wc.takeWrites(), ""); wire != want {
		t.Fatalf("wire=%q want=%q", wire, want)
	}
}
