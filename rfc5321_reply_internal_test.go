package smtp

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// RFC 5321 §4.2.1 and §4.3.2: a client MUST be prepared for reply codes this
// document does not list, and MUST handle them by the first digit only. The
// text is not consulted, and an empty text is acceptable.
//
// checklist: SMTP-CLI-09
func TestRFC5321_ClientFirstDigitOnly(t *testing.T) {
	c, wrote := newScriptedClient("229 \r\n" + // greeting, empty text
		"259-mx\r\n259 PIPELINING\r\n" + // EHLO
		"252 cannot verify, will try\r\n" + // VRFY
		"251 sender noted\r\n" + // MAIL
		"299 recipient noted\r\n" + // RCPT
		"399 go ahead\r\n" + // DATA
		"259 queued\r\n" + // end of data
		"258 reset\r\n" + // RSET
		"250 mx\r\n" + // EHLO again after RSET
		"257 \r\n" + // NOOP
		"222 bye\r\n") // QUIT
	if err := c.Verify("a@example.org"); err != nil {
		t.Fatalf("VRFY 252: %v", err)
	}
	if ok, _ := c.Extension("PIPELINING"); !ok {
		t.Error("EHLO 259 reply not parsed for its keywords")
	}
	if err := c.Mail("a@example.org", nil); err != nil {
		t.Fatalf("MAIL 251: %v", err)
	}
	if err := c.Rcpt("b@example.org", nil); err != nil {
		t.Fatalf("RCPT 299: %v", err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatalf("DATA 399: %v", err)
	}
	io.WriteString(w, "hi\r\n")
	if err := w.Close(); err != nil {
		t.Fatalf("end of data 259: %v", err)
	}
	if err := c.Reset(); err != nil {
		t.Fatalf("RSET 258: %v", err)
	}
	if err := c.Noop(); err != nil {
		t.Fatalf("NOOP 257: %v", err)
	}
	if err := c.Quit(); err != nil {
		t.Fatalf("QUIT 222: %v", err)
	}
	if !strings.Contains(wrote.String(), "hi\r\n.\r\n") {
		t.Errorf("message data not sent after 399: %q", wrote.String())
	}
}

// The first digit decides failure too: an unlisted 4yz or 5yz is an error
// carrying that code, and a 3yz where a completion is due is not a success.
// A 2yz to DATA is not the 3yz go-ahead, so no message data follows it, and
// none follows a 554 "no valid recipients" either (§3.3).
//
// checklist: SMTP-CLI-09 SMTP-DATA-08
func TestRFC5321_ClientFirstDigitFailures(t *testing.T) {
	const hello = "220 mx\r\n250 mx\r\n"
	for _, tc := range []struct {
		name    string
		replies string
		call    func(*Client) error
		code    int
	}{
		{"RCPT 471", hello + "250 ok\r\n471 try later\r\n", func(c *Client) error {
			if err := c.Mail("a@example.org", nil); err != nil {
				return err
			}
			return c.Rcpt("b@example.org", nil)
		}, 471},
		{"MAIL 599", hello + "599 no\r\n", func(c *Client) error { return c.Mail("a@example.org", nil) }, 599},
		{"MAIL 354", hello + "354 what\r\n", func(c *Client) error { return c.Mail("a@example.org", nil) }, 354},
		{"DATA 250", hello + "250 ok\r\n250 ok\r\n250 not a go-ahead\r\n", func(c *Client) error {
			if err := c.Mail("a@example.org", nil); err != nil {
				return err
			}
			if err := c.Rcpt("b@example.org", nil); err != nil {
				return err
			}
			_, err := c.Data()
			return err
		}, 250},
		{"DATA 554", hello + "250 ok\r\n550 no such user\r\n554 no valid recipients\r\n", func(c *Client) error {
			if err := c.Mail("a@example.org", nil); err != nil {
				return err
			}
			c.Rcpt("b@example.org", nil)
			_, err := c.Data()
			return err
		}, 554},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, wrote := newScriptedClient(tc.replies)
			err := tc.call(c)
			var smtpErr *SMTPError
			if !errors.As(err, &smtpErr) || smtpErr.Code != tc.code {
				t.Fatalf("got %v, want an SMTPError with code %d", err, tc.code)
			}
			if strings.HasPrefix(tc.name, "DATA") && !strings.HasSuffix(wrote.String(), "DATA\r\n") {
				t.Errorf("client wrote past DATA: %q", wrote.String())
			}
		})
	}
}

// Pipelined MAIL and RCPT follow the same first-digit rule (RFC 5321 §4.2.1,
// RFC 2920 §3.1).
//
// checklist: SMTP-CLI-09
func TestRFC5321_PipelinerFirstDigitOnly(t *testing.T) {
	c, _ := newScriptedClient("220 mx\r\n250-mx\r\n250 PIPELINING\r\n251 ok\r\n299 ok\r\n" + "471 later\r\n")
	p, err := c.Pipeline()
	if err != nil {
		t.Fatal(err)
	}
	p.Mail("a@example.org", nil)
	p.Rcpt("b@example.org", nil)
	p.Rcpt("c@example.org", nil)
	errs := p.Wait()
	if len(errs) != 3 || errs[0] != nil || errs[1] != nil {
		t.Fatalf("got %v, want MAIL 251 and RCPT 299 accepted", errs)
	}
	var smtpErr *SMTPError
	if !errors.As(errs[2], &smtpErr) || smtpErr.Code != 471 {
		t.Fatalf("third result %v, want the 471", errs[2])
	}
}

// RFC 5321 §4.1.1.10 and §3.8: the client does not close the channel before
// it has sent QUIT, and waits for the reply before closing.
//
// checklist: SMTP-CLI-10
func TestRFC5321_ClientQuitWaitsForReply(t *testing.T) {
	cconn, sconn := net.Pipe()
	defer sconn.Close()
	c := NewClient(cconn)
	c.CommandTimeout = 5 * time.Second

	quitDone := make(chan error, 1)
	go func() {
		io.WriteString(sconn, "220 mx\r\n")
		br := bufio.NewReader(sconn)
		if line, _ := br.ReadString('\n'); !strings.HasPrefix(line, "EHLO ") {
			quitDone <- errors.New("expected EHLO, got " + line)
			return
		}
		io.WriteString(sconn, "250 mx\r\n")
		if line, _ := br.ReadString('\n'); line != "QUIT\r\n" {
			quitDone <- errors.New("expected QUIT, got " + line)
			return
		}
		// Hold the reply back: the client must still be waiting.
		select {
		case err := <-quitDone:
			quitDone <- err
			return
		case <-time.After(100 * time.Millisecond):
		}
		io.WriteString(sconn, "221 bye\r\n")
		// Only now may the client close; the read sees EOF.
		sconn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := br.ReadByte(); err != io.EOF {
			quitDone <- errors.New("client did not close after 221")
		}
	}()

	err := c.Quit()
	select {
	case serr := <-quitDone:
		t.Fatalf("Quit returned before the 221 was sent (server: %v, quit: %v)", serr, err)
	default:
	}
	if err != nil {
		t.Fatalf("Quit: %v", err)
	}
}
