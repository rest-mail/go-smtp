package client

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp/pkg/smtp"
)

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
			c := New(cli)
			c.didGreet = true
			var err error
			if pipeline {
				var p *Pipeliner
				p, err = c.Pipeline()
				if err != nil {
					t.Fatal(err)
				}
				err = p.Mail("a@example.org", &smtp.MailOptions{RequireTLS: true})
				if got := p.Wait(); len(got) != 0 {
					t.Fatalf("refused request queued: %v", got)
				}
			} else {
				err = c.Mail("a@example.org", &smtp.MailOptions{RequireTLS: true})
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
				c := New(w.raw)
				c.didGreet = true
				var transcript bytes.Buffer
				c.DebugWriter = &transcript
				var err error
				opts := &smtp.MailOptions{RequireTLS: true}
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
