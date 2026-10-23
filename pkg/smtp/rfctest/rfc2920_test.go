package rfctest

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp/pkg/smtp"
	"github.com/rest-mail/go-smtp/pkg/smtp/client"
	"github.com/rest-mail/go-smtp/pkg/smtp/server"
)

type pipelineExampleSession struct {
	*session
	reject map[string]bool
}

func (s *pipelineExampleSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	if s.reject[to] {
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "recipient refused"}
	}
	return s.session.Rcpt(to, opts)
}

// RFC 2920 §4: pipeline the envelope through DATA, including the case in
// which the final RCPT fails but an earlier one succeeded. The no-recipient
// variant rejects DATA and never invokes delivery.
// checklist: PIPE-EHLO-01 PIPE-SERVER-01 PIPE-SERVER-03 PIPE-SERVER-04 PIPE-SERVER-08 PIPE-SERVER-09 PIPE-EXAMPLE-01
func TestRFC2920Examples(t *testing.T) {
	for _, tc := range []struct {
		name       string
		recipients []string
		reject     map[string]bool
	}{
		{"RFC success", []string{"ned@innosoft.com", "dan@innosoft.com", "kvc@innosoft.com"}, nil},
		{"last refused", []string{"ned@innosoft.com", "dan@innosoft.com", "kvc@innosoft.com"}, map[string]bool{"kvc@innosoft.com": true}},
		{"RFC all refused", []string{"nsb@thumper.bellcore.com", "galvin@tis.com"}, map[string]bool{"nsb@thumper.bellcore.com": true, "galvin@tis.com": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			be := new(backend)
			_, s, c, scanner, caps := testServerEhlo(t, func(s *server.Server) {
				s.Backend = server.BackendFunc(func(*server.Conn) (server.Session, error) {
					return &pipelineExampleSession{&session{backend: be, anonymous: true}, tc.reject}, nil
				})
			})
			defer s.Close()
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			if !caps["PIPELINING"] {
				t.Fatalf("missing parameterless PIPELINING: %v", caps)
			}
			next := func() string {
				if !scanner.Scan() {
					t.Fatalf("reply: %v", scanner.Err())
				}
				return scanner.Text()
			}
			batch := "MAIL FROM:<mrose@dbc.mtview.ca.us>\r\n"
			wantCodes := []string{"250 "}
			var accepted []string
			for _, to := range tc.recipients {
				batch += "RCPT TO:<" + to + ">\r\n"
				code := "250 "
				if tc.reject[to] {
					code = "550 "
				} else {
					accepted = append(accepted, to)
				}
				wantCodes = append(wantCodes, code)
			}
			dataCode := "354 "
			if len(accepted) == 0 {
				dataCode = "503 "
			} // RFC 5321 sequencing code.
			wantCodes = append(wantCodes, dataCode)
			if _, err := io.WriteString(c, batch+"DATA\r\n"); err != nil {
				t.Fatal(err)
			}
			for i, want := range wantCodes {
				if got := next(); !strings.HasPrefix(got, want) {
					t.Fatalf("reply %d = %q, want %q", i, got, want)
				}
			}
			body := "Subject: example\r\n\r\nbody\r\n"
			if len(accepted) > 0 {
				// The final data response and QUIT are also a legal group (§3.1).
				if _, err := io.WriteString(c, body+".\r\nQUIT\r\n"); err != nil {
					t.Fatal(err)
				}
				if got := next(); !strings.HasPrefix(got, "250 ") {
					t.Fatal(got)
				}
			} else {
				if _, err := io.WriteString(c, "RSET\r\nQUIT\r\n"); err != nil {
					t.Fatal(err)
				}
				if got := next(); !strings.HasPrefix(got, "250 ") {
					t.Fatal(got)
				}
			}
			if got := next(); !strings.HasPrefix(got, "221 ") {
				t.Fatal(got)
			}
			if len(accepted) == 0 {
				if len(be.anonmsgs) != 0 {
					t.Fatalf("delivered without recipients: %+v", be.anonmsgs)
				}
			} else if len(be.anonmsgs) != 1 || strings.Join(be.anonmsgs[0].To, ",") != strings.Join(accepted, ",") || string(be.anonmsgs[0].Data) != body {
				t.Fatalf("wrong delivery: %+v; recipients %v", be.anonmsgs, accepted)
			}
		})
	}
}

// Deliberately misleading and repeated response text must never be used to
// match commands. A multiline response consumes one slot; a rejection does
// not prevent reading later slots, and synchronous operation resumes cleanly.
// checklist: PIPE-CLIENT-01 PIPE-CLIENT-02 PIPE-CLIENT-03 PIPE-CLIENT-04
func TestRFC2920ClientResponseCorrelation(t *testing.T) {
	for _, tc := range []struct {
		name, replies string
		codes         []int
	}{
		{"multiline and mixed", "250-RCPT rejected\r\n250 MAIL ignored\r\n550-MAIL accepted\r\n550 RCPT accepted\r\n251 RCPT accepted\r\n", []int{0, 550, 0}},
		{"MAIL failure still drains", "550 same text\r\n503 same text\r\n503 same text\r\n", []int{550, 503, 503}},
		{"all recipients refused", "250 same text\r\n550 same text\r\n450 same text\r\n", []int{0, 550, 450}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cconn, sconn := net.Pipe()
			done := make(chan error, 1)
			go func() {
				defer sconn.Close()
				sconn.SetDeadline(time.Now().Add(5 * time.Second))
				r := bufio.NewReader(sconn)
				read := func(want string) error {
					got, err := r.ReadString('\n')
					if err != nil {
						return err
					}
					if got != want+"\r\n" {
						return fmt.Errorf("command = %q, want %q", got, want)
					}
					return nil
				}
				serve := func() error {
					if _, err := io.WriteString(sconn, "220 example ESMTP\r\n"); err != nil {
						return err
					}
					if err := read("EHLO localhost"); err != nil {
						return err
					}
					if _, err := io.WriteString(sconn, "250-example\r\n250 PIPELINING\r\n"); err != nil {
						return err
					}
					for _, want := range []string{"MAIL FROM:<a@example.org>", "RCPT TO:<b@example.org>", "RCPT TO:<c@example.org>"} {
						if err := read(want); err != nil {
							return err
						}
					}
					if _, err := io.WriteString(sconn, tc.replies); err != nil {
						return err
					}
					if err := read("NOOP"); err != nil {
						return err
					}
					_, err := io.WriteString(sconn, "250 synchronized\r\n")
					return err
				}
				done <- serve()
			}()
			c := client.New(cconn)
			defer c.Close()
			t.Cleanup(func() {
				cconn.Close()
				if err := <-done; err != nil {
					t.Errorf("script: %v", err)
				}
			})
			c.CommandTimeout = 2 * time.Second
			p, err := c.Pipeline()
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Mail("a@example.org", nil); err != nil {
				t.Fatal(err)
			}
			for _, to := range []string{"b@example.org", "c@example.org"} {
				if err := p.Rcpt(to, nil); err != nil {
					t.Fatal(err)
				}
			}
			results := p.Wait()
			if len(results) != len(tc.codes) {
				t.Fatalf("results = %v", results)
			}
			for i, code := range tc.codes {
				if code == 0 {
					if results[i] != nil {
						t.Fatalf("result %d: %v", i, results[i])
					}
				} else {
					var smtpErr *smtp.SMTPError
					if !errors.As(results[i], &smtpErr) || smtpErr.Code != code {
						t.Fatalf("result %d: %v, want %d", i, results[i], code)
					}
				}
			}
			if err := c.Noop(); err != nil {
				t.Fatalf("after pipeline: %v", err)
			}
		})
	}
}

// A nonconforming peer can accept DATA despite refusing every RCPT. Following
// §3.1's recovery advice, explicitly check DATA and transmit only the terminator.
// checklist: PIPE-CLIENT-05
func TestRFC2920EmptyDataRecovery(t *testing.T) {
	for _, zeroWrite := range []bool{false, true} {
		t.Run(fmt.Sprint(zeroWrite), func(t *testing.T) {
			testRFC2920EmptyDataRecovery(t, zeroWrite)
		})
	}
}

func testRFC2920EmptyDataRecovery(t *testing.T, zeroWrite bool) {
	cconn, sconn := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer sconn.Close()
		sconn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(sconn)
		serve := func() error {
			exchanges := []struct {
				commands []string
				reply    string
			}{
				{nil, "220 example ESMTP\r\n"},
				{[]string{"EHLO localhost"}, "250-example\r\n250 PIPELINING\r\n"},
				{[]string{"MAIL FROM:<a@example.org>", "RCPT TO:<b@example.org>"}, "250 OK\r\n550 refused\r\n"},
				{[]string{"DATA"}, "354 continue\r\n"},
				{[]string{"."}, "554 no recipients\r\n"},
				{[]string{"RSET"}, "250 reset\r\n"},
			}
			for _, exchange := range exchanges {
				for _, want := range exchange.commands {
					got, err := r.ReadString('\n')
					if err != nil {
						return err
					}
					if got != want+"\r\n" {
						return fmt.Errorf("command %q, want %q", got, want)
					}
				}
				if _, err := io.WriteString(sconn, exchange.reply); err != nil {
					return err
				}
			}
			return nil
		}
		done <- serve()
	}()
	c := client.New(cconn)
	defer c.Close()
	t.Cleanup(func() {
		cconn.Close()
		if err := <-done; err != nil {
			t.Errorf("script: %v", err)
		}
	})
	c.CommandTimeout = 2 * time.Second
	p, err := c.Pipeline()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Mail("a@example.org", nil); err != nil {
		t.Fatal(err)
	}
	if err := p.Rcpt("b@example.org", nil); err != nil {
		t.Fatal(err)
	}
	results := p.Wait()
	if len(results) != 2 || results[0] != nil || results[1] == nil {
		t.Fatalf("results: %v", results)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	if zeroWrite {
		if n, err := w.Write(nil); n != 0 || err != nil {
			t.Fatalf("zero write = %d, %v", n, err)
		}
	}
	var smtpErr *smtp.SMTPError
	if err := w.Close(); !errors.As(err, &smtpErr) || smtpErr.Code != 554 {
		t.Fatalf("empty message result: %v", err)
	}
	if n, err := w.Write([]byte("must not be sent")); n != 0 || err == nil {
		t.Fatalf("write after close = %d, %v", n, err)
	}
	if err := w.Close(); err == nil {
		t.Fatal("second close succeeded")
	}
	if err := c.Reset(); err != nil {
		t.Fatal(err)
	}
}

// The default envelope replies identify their command implicitly by sender,
// recipient or reset text, rather than returning indistinguishable OKs.
// checklist: PIPE-SERVER-10
func TestRFC2920ReplyText(t *testing.T) {
	_, s, c, scanner, _ := testServerEhlo(t)
	defer s.Close()
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	for _, tc := range []struct{ command, marker string }{
		{"MAIL FROM:<sender@example.org>", "sender@example.org"},
		{"RCPT TO:<recipient@example.org>", "recipient@example.org"},
		{"RSET", "reset"},
	} {
		if _, err := io.WriteString(c, tc.command+"\r\n"); err != nil {
			t.Fatal(err)
		}
		if !scanner.Scan() {
			t.Fatalf("reply: %v", scanner.Err())
		}
		if got := scanner.Text(); !strings.HasPrefix(got, "250 ") || !strings.Contains(got, tc.marker) {
			t.Fatalf("%s: reply %q does not identify command (%q)", tc.command, got, tc.marker)
		}
	}
}

// Closing an unwritten public DATA writer delivers zero octets, and leaves
// the connection usable for the next transaction. Real content still uses
// normal dot transparency, including after a zero-length Write.
// checklist: PIPE-CLIENT-05
func TestRFC2920EmptyDataWriter(t *testing.T) {
	be, s, conn, _ := testServer(t)
	defer s.Close()
	c := client.New(conn)
	defer c.Close()
	c.CommandTimeout = 2 * time.Second
	c.SubmissionTimeout = 2 * time.Second
	for _, body := range []string{"", ".nonempty\r\n"} {
		if err := c.Mail("a@example.org", nil); err != nil {
			t.Fatal(err)
		}
		if err := c.Rcpt("b@example.org", nil); err != nil {
			t.Fatal(err)
		}
		w, err := c.Data()
		if err != nil {
			t.Fatal(err)
		}
		if n, err := w.Write(nil); n != 0 || err != nil {
			t.Fatalf("zero write = %d, %v", n, err)
		}
		if body != "" {
			if _, err := io.WriteString(w, body); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if n, err := w.Write([]byte("closed")); n != 0 || err == nil {
			t.Fatalf("write after close = %d, %v", n, err)
		}
		if err := w.Close(); err == nil {
			t.Fatal("double close succeeded")
		}
		if got := string(be.anonmsgs[len(be.anonmsgs)-1].Data); got != body {
			t.Fatalf("content = %q, want %q", got, body)
		}
	}
	if err := c.Quit(); err != nil {
		t.Fatal(err)
	}
	if len(be.anonmsgs) != 2 {
		t.Fatalf("deliveries = %d", len(be.anonmsgs))
	}
}
