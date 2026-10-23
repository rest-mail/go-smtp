package rfctest

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// RFC 5321 §4.1.1 recommends tolerating trailing whitespace before CRLF.
// Check real command dispatch, RSET state, DATA octets and QUIT framing.
// checklist: SMTP-SYN-16
func TestRFC5321TrailingCommandWhitespace(t *testing.T) {
	for _, suffix := range []string{" ", "\t", " \t ", "\t\t"} {
		t.Run(fmt.Sprintf("%q", suffix), func(t *testing.T) {
			be, s, c, scanner := testServerGreeted(t)
			defer s.Close()
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			next := func() string {
				if !scanner.Scan() {
					t.Fatalf("reply: %v", scanner.Err())
				}
				return scanner.Text()
			}
			command := func(verb, want string) { expectReply(t, c, next, verb+suffix+"\r\n", want) }
			command("HELO client.example.org", "250 ")
			command("NOOP", "250 ")
			command("MAIL FROM:<old@example.org>", "250 ")
			command("RCPT TO:<old-recipient@example.org>", "250 ")
			command("RSET", "250 ")
			command("RCPT TO:<not-accepted@example.org>", "503 ")
			command("MAIL FROM:<new@example.org>", "250 ")
			command("RCPT TO:<new-recipient@example.org>", "250 ")
			command("DATA", "354 ")
			body := "Subject: whitespace \t\r\n\r\nbody \t\r\n"
			expectReply(t, c, next, body+".\r\n", "250 ")
			if len(be.anonmsgs) != 1 {
				t.Fatalf("delivered %d messages", len(be.anonmsgs))
			}
			msg := be.anonmsgs[0]
			if msg.From != "new@example.org" || strings.Join(msg.To, ",") != "new-recipient@example.org" || string(msg.Data) != body {
				t.Fatalf("wrong delivery: %+v", msg)
			}
			command("QUIT", "221 ")
			if scanner.Scan() || scanner.Err() != nil {
				t.Fatalf("after QUIT: %q, %v", scanner.Text(), scanner.Err())
			}
		})
	}
}
