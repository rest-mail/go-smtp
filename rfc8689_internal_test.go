package smtp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type rfc8689Session struct {
	nopSession
	mail chan MailOptions
	data chan string
}

func (s rfc8689Session) Mail(_ string, opts *MailOptions) error {
	s.mail <- *opts
	return nil
}
func (s rfc8689Session) Data(r io.Reader) error {
	b, err := io.ReadAll(r)
	s.data <- string(b)
	return err
}

type rfc8689Wire struct {
	raw  net.Conn
	br   *bufio.Reader
	mail chan MailOptions
	data chan string
}

func newRFC8689Wire(t *testing.T, enabled, encrypted bool) *rfc8689Wire {
	t.Helper()
	w := &rfc8689Wire{mail: make(chan MailOptions, 16), data: make(chan string, 16)}
	_, w.raw, w.br, _ = newFlushTestConn(t, func(s *Server) {
		s.EnableREQUIRETLS = enabled
		s.TLSConfig = rfc3207TLSConfig(t)
		s.Backend = BackendFunc(func(*Conn) (Session, error) {
			return rfc8689Session{mail: w.mail, data: w.data}, nil
		})
	})
	w.command(t, "EHLO client.example", "250")
	if encrypted {
		w.command(t, "STARTTLS", "220")
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(localhostCert) {
			t.Fatal("invalid test certificate")
		}
		// Use the fixture CA and its actual DNS name; no verification bypass.
		tc := tls.Client(w.raw, &tls.Config{RootCAs: roots, ServerName: "example.com"})
		if err := tc.Handshake(); err != nil {
			t.Fatal(err)
		}
		w.raw, w.br = tc, bufio.NewReader(tc)
		w.command(t, "EHLO client.example", "250")
	}
	return w
}
func (w *rfc8689Wire) command(t *testing.T, cmd, want string) []string {
	t.Helper()
	writeFlushBatch(t, w.raw, cmd+"\r\n")
	reply := readFlushReply(t, w.br)
	if !strings.HasPrefix(reply[0], want+" ") && !strings.HasPrefix(reply[0], want+"-") {
		t.Fatalf("%q = %q, want %s", cmd, reply, want)
	}
	return reply
}
func (w *rfc8689Wire) requireMail(t *testing.T, want bool) {
	t.Helper()
	select {
	case opts := <-w.mail:
		if opts.RequireTLS != want {
			t.Fatalf("RequireTLS = %v, want %v", opts.RequireTLS, want)
		}
	default:
		t.Fatal("MAIL did not reach backend")
	}
}
func (w *rfc8689Wire) deliver(t *testing.T, body string) {
	t.Helper()
	w.command(t, "RCPT TO:<recipient@example.net>", "250")
	w.command(t, "DATA", "354")
	writeFlushBatch(t, w.raw, body+".\r\n")
	if reply := readFlushReply(t, w.br); !strings.HasPrefix(reply[0], "250 ") {
		t.Fatal(reply)
	}
	select {
	case got := <-w.data:
		if got != body {
			t.Fatalf("body = %q, want %q", got, body)
		}
	default:
		t.Fatal("DATA did not reach backend")
	}
	w.command(t, "NOOP", "250")
}

// checklist: REQTLS-EHLO-01
func TestRFC8689Advertisement(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, encrypted := range []bool{false, true} {
			t.Run(fmt.Sprintf("enabled=%v/TLS=%v", enabled, encrypted), func(t *testing.T) {
				w := newRFC8689Wire(t, enabled, encrypted)
				count := 0
				for _, line := range w.command(t, "EHLO client.example", "250") {
					if strings.HasPrefix(line[4:], "REQUIRETLS") {
						count++
						if line[4:] != "REQUIRETLS" {
							t.Fatalf("parameterized capability: %q", line)
						}
					}
				}
				want := 0
				if enabled && encrypted {
					want = 1
				}
				if count != want {
					t.Fatalf("REQUIRETLS count = %d, want %d", count, want)
				}
				if !enabled {
					w.command(t, "MAIL FROM:<a@example.org> REQUIRETLS", "504 5.5.4")
				}
			})
		}
	}
}

// checklist: REQTLS-SYN-01
func TestRFC8689ParameterGrammar(t *testing.T) {
	w := newRFC8689Wire(t, true, true)
	for _, arg := range []string{"REQUIRETLS=", "REQUIRETLS=yes", "REQUIRETLS=No", "REQUIRETLS REQUIRETLS"} {
		w.command(t, "MAIL FROM:<a@example.org> "+arg, "501 5.5.4")
		if len(w.mail) != 0 {
			t.Fatal("invalid parameter reached backend")
		}
		w.command(t, "NOOP", "250")
	}
	w.command(t, "MAIL FROM:<a@example.org> rEqUiReTlS", "250")
	w.requireMail(t, true)
	w.command(t, "RCPT TO:<b@example.org> REQUIRETLS", "500 5.5.4")
	w.deliver(t, "Subject: grammar\r\n\r\nbody\r\n")
}

// checklist: REQTLS-TLS-01
func TestRFC8689ServerRefusesPlaintext(t *testing.T) {
	w := newRFC8689Wire(t, true, false)
	w.command(t, "MAIL FROM:<a@example.org> REQUIRETLS", "530 5.7.0")
	if len(w.mail) != 0 {
		t.Fatal("plaintext REQUIRETLS reached backend")
	}
	w.command(t, "RCPT TO:<b@example.org>", "503")
	w.command(t, "MAIL FROM:<a@example.org>", "250")
	w.requireMail(t, false)
	w.deliver(t, "Subject: ordinary\r\n\r\nallowed plaintext\r\n")
}

// checklist: REQTLS-RECEIVE-01
func TestRFC8689ReceiptAndReset(t *testing.T) {
	w := newRFC8689Wire(t, true, true)
	for _, reset := range []string{"RSET", "EHLO client.example", "DATA"} {
		w.command(t, "MAIL FROM:<a@example.org> REQUIRETLS", "250")
		w.requireMail(t, true)
		if reset == "DATA" {
			// Header interpretation belongs to the host; the explicit envelope bit
			// survives even if the opaque content requests TLS-Required: No.
			w.deliver(t, "TLS-Required: No\r\nSubject: protected\r\n\r\nbody\r\n")
		} else {
			w.command(t, reset, "250")
		}
		w.command(t, "MAIL FROM:<a@example.org>", "250")
		w.requireMail(t, false)
		w.deliver(t, "Subject: next\r\n\r\nno inherited requirement\r\n")
	}
}

// checklist: REQTLS-LEN-01
func TestRFC8689MailLength(t *testing.T) {
	w := newRFC8689Wire(t, true, true)
	prefix, suffix := "MAIL FROM:<", "> REQUIRETLS\r\n"
	from := strings.Repeat("a", 523-len(prefix)-len(suffix)-len("@example.org")) + "@example.org"
	cmd := prefix + from + suffix
	if len(cmd) != 523 {
		t.Fatal(len(cmd))
	}
	w.command(t, strings.TrimSuffix(cmd, "\r\n"), "250")
	w.requireMail(t, true)
	w.deliver(t, "Subject: extended length\r\n\r\nbody\r\n")
}

// checklist: REQTLS-CLIENT-01
func TestRFC8689ClientRefusesPlaintext(t *testing.T) {
	for _, pipeline := range []bool{false, true} {
		t.Run(fmt.Sprintf("pipeline=%v", pipeline), func(t *testing.T) {
			cli, peer := net.Pipe()
			t.Cleanup(func() { cli.Close(); peer.Close() })
			if err := cli.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				br := bufio.NewReader(peer)
				for _, step := range []struct{ want, reply string }{
					{"EHLO localhost\r\n", "250-localhost\r\n250-PIPELINING\r\n250 REQUIRETLS\r\n"},
					{"NOOP\r\n", "250 ok\r\n"},
				} {
					got, err := br.ReadString('\n')
					if err != nil {
						done <- err
						return
					}
					if got != step.want {
						done <- fmt.Errorf("got %q, want %q", got, step.want)
						peer.Close()
						return
					}
					if _, err := io.WriteString(peer, step.reply); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			c := NewClient(cli)
			c.didGreet = true
			var err error
			if pipeline {
				var p *Pipeliner
				p, err = c.Pipeline()
				if err != nil {
					t.Fatal(err)
				}
				err = p.Mail("a@example.org", &MailOptions{RequireTLS: true})
				if got := p.Wait(); len(got) != 0 {
					t.Fatalf("refused request queued: %v", got)
				}
			} else {
				err = c.Mail("a@example.org", &MailOptions{RequireTLS: true})
			}
			if err == nil {
				t.Fatal("plaintext REQUIRETLS accepted")
			}
			if err := c.Noop(); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// checklist: REQTLS-CLIENT-02 REQTLS-EXAMPLE-01
func TestRFC8689ClientNegotiation(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, pipeline := range []bool{false, true} {
			t.Run(fmt.Sprintf("enabled=%v/pipeline=%v", enabled, pipeline), func(t *testing.T) {
				w := newRFC8689Wire(t, enabled, true)
				c := NewClient(w.raw)
				c.didGreet = true
				var transcript bytes.Buffer
				c.DebugWriter = &transcript
				var err error
				opts := &MailOptions{RequireTLS: true}
				if pipeline {
					var p *Pipeliner
					p, err = c.Pipeline()
					if err != nil {
						t.Fatal(err)
					}
					err = p.Mail("roger@example.org", opts)
					if queued := p.Wait(); enabled {
						if len(queued) != 1 || queued[0] != nil {
							t.Fatalf("pipeline replies: %v", queued)
						}
					} else if len(queued) != 0 {
						t.Fatalf("unsupported request queued: %v", queued)
					}
				} else {
					err = c.Mail("roger@example.org", opts)
				}
				if enabled {
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(transcript.String(), "MAIL FROM:<roger@example.org> BODY=8BITMIME REQUIRETLS\r\n") {
						t.Fatalf("missing REQUIRETLS MAIL on wire: %q", transcript.String())
					}
					w.requireMail(t, true)
					if err := c.Rcpt("editor@example.net", nil); err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(transcript.String(), "RCPT TO:<editor@example.net>\r\n") {
						t.Fatalf("missing example recipient on wire: %q", transcript.String())
					}
					d, err := c.Data()
					if err != nil {
						t.Fatal(err)
					}
					body := "From: roger@example.org\r\nTo: editor@example.net\r\nSubject: TLS required\r\n\r\nprotected body\r\n"
					if _, err := io.WriteString(d, body); err != nil {
						t.Fatal(err)
					}
					if err := d.Close(); err != nil {
						t.Fatal(err)
					}
					select {
					case got := <-w.data:
						if got != body {
							t.Fatalf("body = %q", got)
						}
					default:
						t.Fatal("DATA did not reach backend")
					}
				} else {
					if err == nil {
						t.Fatal("unadvertised REQUIRETLS accepted")
					}
					if strings.Contains(transcript.String(), "MAIL FROM:") {
						t.Fatalf("unsupported request sent MAIL: %q", transcript.String())
					}
					if len(w.mail) != 0 {
						t.Fatal("unsupported request reached backend")
					}
					if err := c.Mail("alice@example.org", nil); err != nil {
						t.Fatal(err)
					}
					w.requireMail(t, false)
					if err := c.Reset(); err != nil {
						t.Fatal(err)
					}
				}
				if err := c.Noop(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
