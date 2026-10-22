package smtp

import (
	"fmt"
	"strings"
	"testing"
)

// RFC 5321 §4.1.1.1 advises receivers to tolerate the identifying suffix
// historically sent after an address literal. It is not part of the client's
// identity. RFC 2033 §4.1 gives LHLO the same semantics as EHLO.
//
// checklist: SMTP-CMD-11 SMTP-RSET-02 LMTP-HELLO-01
func TestRFC5321HelloIdentifyingSuffix(t *testing.T) {
	for _, verb := range []string{"HELO", "EHLO", "LHLO"} {
		for _, literal := range []string{"[192.0.2.1]", "[IPv6:2001:db8::1]"} {
			for _, suffix := range []string{
				" old-client (version 1.0)",
				"\told-client (version 1.0)",
				" \tlegacy\tclient info",
				" " + strings.Repeat("x", 200),
				" legacy café\u00a0client",
			} {
				t.Run(fmt.Sprintf("%s/%s/%q", verb, literal, suffix), func(t *testing.T) {
					started := make(chan string, 2)
					senders := make(chan string, 2)
					body := make(chan string, 1)
					_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
						s.LMTP = verb == "LHLO"
						s.Backend = BackendFunc(func(c *Conn) (Session, error) {
							started <- c.Hostname()
							return transportProofSession{
								mail: func(from string, _ *MailOptions) error {
									senders <- c.Hostname() + ":" + from
									return nil
								},
								data: body,
							}, nil
						})
					})
					command := func(cmd, want string) []string {
						t.Helper()
						writeFlushBatch(t, raw, cmd+"\r\n")
						reply := readFlushReply(t, br)
						if !strings.HasPrefix(reply[0], want) {
							t.Fatalf("%q: reply %q, want %q", cmd, reply, want)
						}
						return reply
					}
					hello := func(name string) {
						t.Helper()
						reply := command(verb+" "+name+suffix, "250")
						// HELO must remain a single-line greeting; EHLO and LHLO
						// retain their extended capability replies.
						prefix := "250-localhost Hello "
						if verb == "HELO" {
							prefix = "250 2.0.0 localhost Hello "
							if len(reply) != 1 {
								t.Fatalf("HELO returned capabilities: %q", reply)
							}
						} else if len(reply) < 2 {
							t.Fatalf("extended greeting lost capabilities: %q", reply)
						}
						if reply[0] != prefix+name {
							t.Fatalf("greeting identity = %q, want %q", reply[0], prefix+name)
						}
					}
					hello(literal)
					if len(started) != 1 || <-started != literal {
						t.Fatal("backend did not receive the bare address literal")
					}
					command("MAIL FROM:<old@example.org>", "250 ")
					if got := <-senders; got != literal+":old@example.org" {
						t.Fatalf("initial envelope identity = %q", got)
					}
					command("RCPT TO:<old-recipient@example.org>", "250 ")

					// A later greeting still resets the transaction, updates the
					// identity, and reuses the established backend session.
					const next = "MiXeD.Example.org"
					hello(next)
					if len(started) != 0 {
						t.Fatal("second greeting unexpectedly replaced the session")
					}
					command("RCPT TO:<stray@example.org>", "503 ")
					command("DATA", "503 ")
					command("MAIL FROM:<new@example.org>", "250 ")
					if got := <-senders; got != next+":new@example.org" {
						t.Fatalf("new envelope identity = %q", got)
					}
					command("RCPT TO:<new-recipient@example.org>", "250 ")
					command("DATA", "354 ")
					command("Subject: legacy hello\r\n\r\nbody\r\n.", "250 ")
					if got := <-body; got != "Subject: legacy hello\r\n\r\nbody\r\n" {
						t.Fatalf("delivered body = %q", got)
					}
					// In LMTP, QUIT also detects a stray final status for the
					// recipient discarded by the second LHLO.
					command("QUIT", "221 ")
				})
			}
		}
	}
}
