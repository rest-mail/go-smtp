package client

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp/pkg/smtp"
	"github.com/rest-mail/go-smtp/pkg/smtp/server"
)

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
				_, raw, br, _ := newFlushTestConn(t, func(s *server.Server) {
					s.LMTP = lmtp
					s.EnableMTPRIORITY = true
					s.MtPriorityProfile = smtp.PriorityProfile(profile)
					s.Backend = server.BackendFunc(func(*server.Conn) (server.Session, error) { sessions <- struct{}{}; return nopSession{}, nil })
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
		_, raw, br, _ := newFlushTestConn(t, func(s *server.Server) { s.MtPriorityProfile = "bad profile" })
		writeFlushBatch(t, raw, "EHLO example.org\r\n")
		reply := readFlushReply(t, br)
		if !strings.HasPrefix(reply[0], "250") || strings.Contains(strings.Join(reply, "\n"), "MT-PRIORITY") {
			t.Fatal(reply)
		}
	})
}

// checklist: DSN-HOST-06
func TestRFC3461CombinedCommandBudget(t *testing.T) {
	mails := make(chan *smtp.MailOptions, 1)
	rcpts := make(chan *smtp.RcptOptions, 1)
	data := make(chan string, 1)
	_, raw, br, _ := newFlushTestConn(t, func(s *server.Server) {
		s.TLSConfig = rfc3207TLSConfig(t)
		s.EnableDSN = true
		s.EnableSMTPUTF8 = true
		s.EnableREQUIRETLS = true
		s.EnableBINARYMIME = true
		s.EnableRRVS = true
		s.EnableDELIVERBY = true
		s.EnableMTPRIORITY = true
		s.Backend = server.BackendFunc(func(*server.Conn) (server.Session, error) {
			return transportProofSession{mail: func(_ string, o *smtp.MailOptions) error { mails <- o; return nil }, rcpt: func(_ string, o *smtp.RcptOptions) error { rcpts <- o; return nil }, data: data}, nil
		})
	})
	// REQUIRETLS is advertised only after TLS, so negotiate before sending
	// the combined envelope. The self-signed fixture is already used by the
	// STARTTLS suite; certificate policy is outside this budget proof.
	c := New(raw)
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
	if o.Body != smtp.BodyBinaryMIME || o.Size != int64(len(body)) || !o.UTF8 || !o.RequireTLS || o.Return != smtp.DSNReturnHeaders || o.EnvelopeID != envid || o.Auth == nil || *o.Auth != "a@example.org" || o.DeliverBy == nil || o.DeliverBy.Time != 999999999*time.Second || o.DeliverBy.Mode != smtp.DeliverByReturn || !o.DeliverBy.Trace || o.MTPriority == nil || *o.MTPriority != -9 {
		t.Fatalf("MAIL options=%+v", o)
	}
	command(padded("RCPT TO:<b@example.org> NOTIFY=SUCCESS,FAILURE,DELAY ORCPT=rfc822;"+original+" RRVS=2014-05-19T22:57:43Z;R"), "250")
	if len(rcpts) != 1 {
		t.Fatalf("RCPT calls=%d", len(rcpts))
	}
	r := <-rcpts
	if r.OriginalRecipient != original || r.OriginalRecipientType != smtp.DSNAddressType("rfc822") || !reflect.DeepEqual(r.Notify, []smtp.DSNNotify{smtp.DSNNotifySuccess, smtp.DSNNotifyFailure, smtp.DSNNotifyDelayed}) || !r.RequireRecipientValidSince.Equal(time.Date(2014, 5, 19, 22, 57, 43, 0, time.UTC)) || r.RequireRecipientValidSinceAction != smtp.RRVSActionReject {
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
	c, wc := transportProofClient(t, transportProofSession{data: data}, func(s *server.Server) { s.TLSConfig = rfc3207TLSConfig(t) })
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
