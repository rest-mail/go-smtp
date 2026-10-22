package smtp

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
)

type transportProofSession struct {
	flushAuthSession
	mail func(string, *MailOptions) error
	rcpt func(string, *RcptOptions) error
	data chan string
}

func (s transportProofSession) Mail(from string, opts *MailOptions) error {
	if s.mail != nil {
		return s.mail(from, opts)
	}
	return nil
}

func (s transportProofSession) Rcpt(to string, opts *RcptOptions) error {
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

func transportProofClient(t *testing.T, session Session, configure func(*Server)) (*Client, *writeCountingConn) {
	t.Helper()
	s := NewServer(BackendFunc(func(*Conn) (Session, error) { return session, nil }))
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
	c := NewClient(wc)
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

// checklist: PRI-PROFILE-01
func TestRFC6710ProfileGrammarOnWire(t *testing.T) {
	profiles := []string{"", "a", "AZaz09-_.", strings.Repeat("x", 20), strings.Repeat("x", 21), "mélange", "a\r\n250 injected"}
	// Exercise every possible octet against the RFC's ASCII grammar.
	for b := 0; b < 256; b++ {
		profiles = append(profiles, "a"+string([]byte{byte(b)})+"z")
	}
	for _, lmtp := range []bool{false, true} {
		for _, profile := range profiles {
			t.Run(fmt.Sprintf("lmtp=%v/%x", lmtp, profile), func(t *testing.T) {
				valid := len(profile) <= 20
				for _, b := range []byte(profile) {
					if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.') {
						valid = false
					}
				}
				sessions := make(chan struct{}, 1)
				_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
					s.LMTP = lmtp
					s.EnableMTPRIORITY = true
					s.MtPriorityProfile = PriorityProfile(profile)
					s.Backend = BackendFunc(func(*Conn) (Session, error) { sessions <- struct{}{}; return nopSession{}, nil })
				})
				hello := "EHLO"
				if lmtp {
					hello = "LHLO"
				}
				writeFlushBatch(t, raw, hello+" example.org\r\n")
				reply := readFlushReply(t, br)
				if valid {
					want := "MT-PRIORITY"
					if profile != "" {
						want += " " + profile
					}
					found := false
					for _, line := range reply {
						if len(line) >= 4 && line[4:] == want {
							found = true
						}
					}
					if !strings.HasPrefix(reply[0], "250") || !found || len(sessions) != 1 {
						t.Fatalf("profile %q: reply=%q sessions=%d", profile, reply, len(sessions))
					}
				} else {
					if len(reply) != 1 || !strings.HasPrefix(reply[0], "451 4.3.5 ") || len(sessions) != 0 {
						t.Fatalf("invalid profile %q: reply=%q sessions=%d", profile, reply, len(sessions))
					}
					writeFlushBatch(t, raw, "MAIL FROM:<a@example.org>\r\n")
					if reply := readFlushReply(t, br); !strings.HasPrefix(reply[0], "503 ") {
						t.Fatal(reply)
					}
				}
				writeFlushBatch(t, raw, "NOOP\r\n")
				if reply := readFlushReply(t, br); !strings.HasPrefix(reply[0], "250 ") {
					t.Fatal(reply)
				}
			})
		}
	}
	t.Run("disabled invalid profile", func(t *testing.T) {
		_, raw, br, _ := newFlushTestConn(t, func(s *Server) { s.MtPriorityProfile = "bad profile" })
		writeFlushBatch(t, raw, "EHLO example.org\r\n")
		reply := readFlushReply(t, br)
		if !strings.HasPrefix(reply[0], "250") || strings.Contains(strings.Join(reply, "\n"), "MT-PRIORITY") {
			t.Fatal(reply)
		}
	})
}

// checklist: PRI-TIME-01
func TestRFC6710IndependentDeliverByOnWire(t *testing.T) {
	for _, priority := range []bool{false, true} {
		for _, by := range []bool{false, true} {
			t.Run(fmt.Sprintf("priority=%v/by=%v", priority, by), func(t *testing.T) {
				got := make(chan *MailOptions, 2)
				data := make(chan string, 1)
				c, _ := transportProofClient(t, transportProofSession{mail: func(_ string, o *MailOptions) error { got <- o; return nil }, data: data}, func(s *Server) { s.EnableMTPRIORITY = priority; s.EnableDELIVERBY = by })
				for name, want := range map[string]bool{"MT-PRIORITY": priority, "DELIVERBY": by} {
					ok, _ := c.Extension(name)
					if ok != want {
						t.Fatalf("%s=%v, want %v", name, ok, want)
					}
				}
				p := -9
				// Each option is independently refused when its capability is off.
				if !priority {
					if err := c.Mail("a@example.org", &MailOptions{MTPriority: &p}); err == nil {
						t.Fatal("unadvertised priority accepted")
					}
				}
				if !by {
					if err := c.Mail("a@example.org", &MailOptions{DeliverBy: &DeliverByOptions{Time: time.Minute, Mode: DeliverByReturn}}); err == nil {
						t.Fatal("unadvertised DELIVERBY accepted")
					}
				}
				if len(got) != 0 {
					t.Fatal("refused option reached backend")
				}
				opts := &MailOptions{}
				if priority {
					opts.MTPriority = &p
				}
				if by {
					opts.DeliverBy = &DeliverByOptions{Time: 120 * time.Second, Mode: DeliverByReturn, Trace: true}
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
			mails := make(chan BodyType, 2)
			c, wc := transportProofClient(t, transportProofSession{mail: func(_ string, o *MailOptions) error { mails <- o.Body; return nil }, data: data}, func(s *Server) { s.EnableBINARYMIME = enabled })
			advertised, _ := c.Extension("BINARYMIME")
			if advertised != enabled {
				t.Fatal("wrong binary advertisement")
			}
			wc.takeWrites()
			if err := c.Mail("a@example.org", &MailOptions{Body: BodyBinaryMIME}); err == nil {
				t.Fatal("binary MAIL accepted without a BDAT sender")
			}
			if writes := wc.takeWrites(); len(writes) != 0 || len(mails) != 0 {
				t.Fatalf("refused binary leaked: %q, calls=%d", writes, len(mails))
			}
			// Refusal leaves no transaction: ordinary text can be delivered afterwards.
			if err := c.Mail("a@example.org", &MailOptions{Body: Body7Bit}); err != nil {
				t.Fatal(err)
			}
			if len(mails) != 1 {
				t.Fatalf("MAIL calls=%d", len(mails))
			}
			if got := <-mails; got != Body7Bit {
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

// checklist: DSN-HOST-06
func TestRFC3461CombinedCommandBudget(t *testing.T) {
	mails := make(chan *MailOptions, 1)
	rcpts := make(chan *RcptOptions, 1)
	data := make(chan string, 1)
	_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
		s.TLSConfig = rfc3207TLSConfig(t)
		s.EnableDSN = true
		s.EnableSMTPUTF8 = true
		s.EnableREQUIRETLS = true
		s.EnableBINARYMIME = true
		s.EnableRRVS = true
		s.EnableDELIVERBY = true
		s.EnableMTPRIORITY = true
		s.Backend = BackendFunc(func(*Conn) (Session, error) {
			return transportProofSession{mail: func(_ string, o *MailOptions) error { mails <- o; return nil }, rcpt: func(_ string, o *RcptOptions) error { rcpts <- o; return nil }, data: data}, nil
		})
	})
	// REQUIRETLS is advertised only after TLS, so negotiate before sending
	// the combined envelope. The self-signed fixture is already used by the
	// STARTTLS suite; certificate policy is outside this budget proof.
	c := NewClient(raw)
	c.didGreet = true // newFlushTestConn consumed the real greeting.
	if err := c.startTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatal(err)
	} //nolint:gosec // self-signed test certificate
	raw = c.conn
	br = bufio.NewReader(raw)
	command := func(line, code string) {
		t.Helper()
		writeFlushBatch(t, raw, line+"\r\n")
		if reply := readFlushReply(t, br); !strings.HasPrefix(reply[0], code) {
			t.Fatalf("reply=%q want %s", reply, code)
		}
	}
	writeFlushBatch(t, raw, "EHLO example.org\r\n")
	caps := readFlushReply(t, br)
	for _, capability := range []string{"PIPELINING", "8BITMIME", "CHUNKING", "BINARYMIME", "AUTH PLAIN", "DSN", "SIZE 0", "SMTPUTF8", "REQUIRETLS", "RRVS", "DELIVERBY", "MT-PRIORITY"} {
		found := false
		for _, line := range caps {
			if len(line) >= 4 && line[4:] == capability {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing %s: %q", capability, caps)
		}
	}
	// Default 2000 includes CRLF. All built-in MAIL and RCPT parameter families
	// coexist. Fill unused capacity with legal separators to test the reader at
	// its inclusive boundary, beyond DSN's 1036-octet minimum.
	padded := func(line string) string {
		t.Helper()
		if len(line)+2 > 2000 {
			t.Fatal("fixture too long")
		}
		return line + strings.Repeat(" ", 2000-len(line)-2)
	}
	const body = "Subject: budget\r\n\r\nbody\r\n"
	envid := strings.Repeat("e", 100)
	original := strings.Repeat("x", 500)
	command(padded("MAIL FROM:<a@example.org> BODY=BINARYMIME SIZE=00000000000000000025 SMTPUTF8 REQUIRETLS RET=HDRS ENVID="+envid+" AUTH=a@example.org BY=999999999;RT MT-PRIORITY=-9"), "250")
	if len(mails) != 1 {
		t.Fatalf("MAIL calls=%d", len(mails))
	}
	o := <-mails
	if o.Body != BodyBinaryMIME || o.Size != int64(len(body)) || !o.UTF8 || !o.RequireTLS || o.Return != DSNReturnHeaders || o.EnvelopeID != envid || o.Auth == nil || *o.Auth != "a@example.org" || o.DeliverBy == nil || o.DeliverBy.Time != 999999999*time.Second || o.DeliverBy.Mode != DeliverByReturn || !o.DeliverBy.Trace || o.MTPriority == nil || *o.MTPriority != -9 {
		t.Fatalf("MAIL options=%+v", o)
	}
	command(padded("RCPT TO:<b@example.org> NOTIFY=SUCCESS,FAILURE,DELAY ORCPT=rfc822;"+original+" RRVS=2014-05-19T22:57:43Z;R"), "250")
	if len(rcpts) != 1 {
		t.Fatalf("RCPT calls=%d", len(rcpts))
	}
	r := <-rcpts
	if r.OriginalRecipient != original || r.OriginalRecipientType != DSNAddressType("rfc822") || !reflect.DeepEqual(r.Notify, []DSNNotify{DSNNotifySuccess, DSNNotifyFailure, DSNNotifyDelayed}) || !r.RequireRecipientValidSince.Equal(time.Date(2014, 5, 19, 22, 57, 43, 0, time.UTC)) || r.RequireRecipientValidSinceAction != RRVSActionReject {
		t.Fatalf("RCPT options=%+v", r)
	}
	writeFlushBatch(t, raw, fmt.Sprintf("BDAT %d LAST\r\n%s", len(body), body))
	if reply := readFlushReply(t, br); !strings.HasPrefix(reply[0], "250 ") {
		t.Fatal(reply)
	}
	if len(data) != 1 {
		t.Fatalf("DATA calls=%d", len(data))
	}
	if got := <-data; got != body {
		t.Fatalf("body=%q", got)
	}
	command("NOOP", "250")
}

// checklist: TLS-PIPE-01
func TestRFC3207StartTLSBetweenGroups(t *testing.T) {
	data := make(chan string, 1)
	c, wc := transportProofClient(t, transportProofSession{data: data}, func(s *Server) { s.TLSConfig = rfc3207TLSConfig(t) })
	p, err := c.Pipeline()
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Reset(); err != nil {
		t.Fatal(err)
	}
	if results := p.Wait(); len(results) != 1 || results[0] != nil {
		t.Fatalf("pre-TLS group: %v", results)
	}
	if wire := strings.Join(wc.takeWrites(), ""); wire != "EHLO localhost\r\nRSET\r\n" {
		t.Fatalf("pre-TLS wire=%q", wire)
	}
	if err = c.startTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatal(err)
	} //nolint:gosec // self-signed test certificate
	// STARTTLS is the last plaintext command; only TLS records follow it.
	if wire := strings.Join(wc.takeWrites(), ""); !strings.HasPrefix(wire, "STARTTLS\r\n\x16") {
		t.Fatalf("upgrade wire=%q", wire)
	}
	if state, ok := c.TLSConnectionState(); !ok || !state.HandshakeComplete {
		t.Fatal("upgrade did not complete")
	}
	p, err = c.Pipeline()
	if err != nil {
		t.Fatal(err)
	} // fresh encrypted EHLO
	if ok, _ := c.Extension("STARTTLS"); ok {
		t.Fatal("STARTTLS advertised after upgrade")
	}
	if err = p.Mail("a@example.org", nil); err != nil {
		t.Fatal(err)
	}
	if err = p.Rcpt("b@example.org", nil); err != nil {
		t.Fatal(err)
	}
	if results := p.Wait(); len(results) != 2 || results[0] != nil || results[1] != nil {
		t.Fatalf("post-TLS group: %v", results)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	const body = "Subject: TLS group\r\n\r\ncontent\r\n"
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
}
