package smtp_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp"
)

// checklist: SMTP-AUDIT-01
func TestRFC5321_ParameterlessCommands(t *testing.T) {
	for _, command := range []string{"RSET", "QUIT", "DATA"} {
		t.Run(command, func(t *testing.T) {
			be, s, c, scanner := testServerGreeted(t)
			defer s.Close()
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			next := func() string { scanner.Scan(); return scanner.Text() }
			expectReply(t, c, next, "HELO client.example\r\n", "250 ")
			expectReply(t, c, next, "MAIL FROM:<sender@example.org>\r\n", "250 ")
			expectReply(t, c, next, "RCPT TO:<recipient@example.org>\r\n", "250 ")
			expectReply(t, c, next, command+" forbidden\r\n", "501 ")
			expectReply(t, c, next, "NOOP\r\n", "250 ")
			expectReply(t, c, next, "DATA\r\n", "354 ")
			expectReply(t, c, next, "Subject: preserved\r\n\r\nbody\r\n.\r\n", "250 ")
			if len(be.anonmsgs) != 1 || be.anonmsgs[0].From != "sender@example.org" || len(be.anonmsgs[0].To) != 1 || be.anonmsgs[0].To[0] != "recipient@example.org" {
				t.Fatalf("transaction lost: %+v", be.anonmsgs)
			}
			expectReply(t, c, next, "QUIT\r\n", "221 ")
			if scanner.Scan() || scanner.Err() != nil {
				t.Fatalf("QUIT did not close cleanly: %q, %v", scanner.Text(), scanner.Err())
			}
		})
	}
}

// checklist: SMTP-AUDIT-02 SMTP-AUDIT-03 SMTP-AUDIT-04
func TestRFC5321_OpaqueContentAndMinimumMessage(t *testing.T) {
	be, s, c, scanner := testServerGreeted(t)
	defer s.Close()
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	next := func() string { scanner.Scan(); return scanner.Text() }
	expectReply(t, c, next, "HELO client.example\r\n", "250 ")
	expectReply(t, c, next, "MAIL FROM:<>\r\n", "250 ")
	expectReply(t, c, next, "RCPT TO:<recipient@example.org>\r\n", "250 ")
	expectReply(t, c, next, "DATA\r\n", "354 ")
	// Deliberately malformed trace and Resent fields must not be interpreted by
	// the transport. Include ASCII controls and over 64 KiB with legal lines.
	body := "Received: unparseable trace\r\nReceived: second untouched\r\nResent-To: a@example.org\r\n\r\n\x00\x01\t\v\f\x7f\r\n" + strings.Repeat(strings.Repeat("x", 998)+"\r\n", 66)
	expectReply(t, c, next, body+".\r\n", "250 ")
	if len(be.anonmsgs) != 1 || string(be.anonmsgs[0].Data) != body || be.anonmsgs[0].From != "" {
		t.Fatal("opaque message or null envelope changed")
	}
	// The completed DATA consumed the sender/recipients; no partial reuse.
	expectReply(t, c, next, "RCPT TO:<other@example.org>\r\n", "503 ")
	expectReply(t, c, next, "MAIL FROM:<new@example.org>\r\n", "250 ")
}

// checklist: SMTP-AUDIT-05 SMTP-AUDIT-06
func TestRFC5321_HeloAndRejectedEhlo(t *testing.T) {
	be, s, c, scanner := testServerGreeted(t)
	defer s.Close()
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	next := func() string { scanner.Scan(); return scanner.Text() }
	// A single-line HELO reply must not carry EHLO capabilities. NOOP exposes
	// any extra queued reply without depending on a read timeout.
	expectReply(t, c, next, "HELO client.example\r\n", "250 ")
	expectReply(t, c, next, "NOOP\r\n", "250 2.0.0 ")
	expectReply(t, c, next, "MAIL FROM:<sender@example.org>\r\n", "250 ")
	expectReply(t, c, next, "RCPT TO:<recipient@example.org>\r\n", "250 ")
	expectReply(t, c, next, "EHLO\r\n", "501 ")
	expectReply(t, c, next, "DATA\r\n", "354 ")
	expectReply(t, c, next, "body\r\n.\r\n", "250 ")
	if len(be.anonmsgs) != 1 || be.anonmsgs[0].From != "sender@example.org" || len(be.anonmsgs[0].To) != 1 {
		t.Fatal("rejected EHLO changed transaction")
	}
}

// checklist: SMTP-AUDIT-07
func TestRFC5321_QuotedLocalPartEquivalence(t *testing.T) {
	for _, local := range []string{`user`, `"user"`, `"u\ser"`} {
		t.Run(local, func(t *testing.T) {
			be, s, c, scanner := testServerGreeted(t)
			defer s.Close()
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			next := func() string { scanner.Scan(); return scanner.Text() }
			expectReply(t, c, next, "HELO client.example\r\n", "250 ")
			expectReply(t, c, next, "MAIL FROM:<"+local+"@example.org>\r\n", "250 ")
			expectReply(t, c, next, "RCPT TO:<"+local+"@example.org>\r\n", "250 ")
			expectReply(t, c, next, "DATA\r\n", "354 ")
			expectReply(t, c, next, "body\r\n.\r\n", "250 ")
			if len(be.anonmsgs) != 1 || be.anonmsgs[0].From != "user@example.org" || be.anonmsgs[0].To[0] != "user@example.org" {
				t.Fatal("quoted forms are not equivalent")
			}
		})
	}
}

// checklist: SMTP-AUDIT-27 SMTP-AUDIT-34 SMTP-AUDIT-47 SMTP-AUDIT-97 SMTP-AUDIT-102
func TestRFC5321_ClientAuditSequence(t *testing.T) {
	for _, body := range []string{"line\r\n.dot", "line\r\n.dot\r\n"} {
		t.Run(fmt.Sprintf("terminated=%v", strings.HasSuffix(body, "\r\n")), func(t *testing.T) {
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			serverSide.SetDeadline(time.Now().Add(5 * time.Second))
			done := make(chan error, 1)
			go func() {
				reader := bufio.NewReader(serverSide)
				exchanges := []struct{ want, reply string }{
					{"", "220 peer.example ESMTP\r\n"},
					{"EHLO client.example\r\n", "250 peer.example\r\n"},
					{"MAIL FROM:<sender@example.org>\r\n", "550 sender refused\r\n"},
					// Identical MAIL must reach the peer again; its previous 5yz is not cached.
					{"MAIL FROM:<sender@example.org>\r\n", "250 sender accepted\r\n"},
					{"RCPT TO:<recipient@example.org>\r\n", "250 recipient accepted\r\n"},
					{"DATA\r\n", "354 go ahead\r\n"},
					{"line\r\n..dot\r\n.\r\n", "250 stored\r\n"},
					{"RSET\r\n", "250 reset\r\n"},
					{"QUIT\r\n", "221 bye\r\n"},
				}
				for _, exchange := range exchanges {
					got := make([]byte, len(exchange.want))
					if _, err := io.ReadFull(reader, got); err != nil {
						done <- err
						return
					}
					if string(got) != exchange.want {
						done <- fmt.Errorf("wire = %q, want %q", got, exchange.want)
						return
					}
					if _, err := io.WriteString(serverSide, exchange.reply); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			client := smtp.NewClient(clientSide)
			client.CommandTimeout = 2 * time.Second
			client.SubmissionTimeout = 2 * time.Second
			if err := client.Hello("client.example"); err != nil {
				t.Fatal(err)
			}
			if err := client.Mail("sender@example.org", nil); err == nil {
				t.Fatal("MAIL refusal lost")
			}
			if err := client.Mail("sender@example.org", nil); err != nil {
				t.Fatal(err)
			}
			opts := &smtp.RcptOptions{
				Notify:                           []smtp.DSNNotify{smtp.DSNNotifyNever},
				OriginalRecipientType:            smtp.DSNAddressTypeRFC822,
				OriginalRecipient:                "original@example.org",
				RequireRecipientValidSince:       time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				RequireRecipientValidSinceAction: smtp.RRVSActionContinue,
			}
			if err := client.Rcpt("recipient@example.org", opts); err != nil {
				t.Fatal(err)
			}
			data, err := client.Data()
			if err != nil {
				t.Fatal(err)
			}
			// A missing final CRLF is supplied exactly once; an existing one is not
			// doubled. No extra blank line may precede the dot terminator.
			if _, err = io.WriteString(data, body); err != nil {
				t.Fatal(err)
			}
			if err = data.Close(); err != nil {
				t.Fatal(err)
			}
			if err = client.Reset(); err != nil {
				t.Fatal(err)
			}
			if err = client.Quit(); err != nil {
				t.Fatal(err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
