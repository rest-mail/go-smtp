package client

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/rest-mail/go-smtp/pkg/smtp"
	"github.com/rest-mail/go-smtp/pkg/smtp/server"
)

// checklist: LMTP-HELLO-03
func TestRFC2033ClientNoSMTPFallback(t *testing.T) {
	for _, code := range []int{500, 502} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var wrote bytes.Buffer
			fake := faker{ReadWriter: struct {
				io.Reader
				io.Writer
			}{
				strings.NewReader(fmt.Sprintf("220 ready\r\n%d not LMTP\r\n250 SMTP hello\r\n250 sender\r\n", code)), &wrote,
			}}
			c := NewLMTP(fake)
			defer c.Close()
			err := c.Mail("chris@bar.com", nil)
			var se *smtp.SMTPError
			if !errors.As(err, &se) || se.Code != code {
				t.Fatalf("Mail = %v, want LHLO %d", err, code)
			}
			if err := c.Noop(); err == nil {
				t.Fatal("failed LHLO not retained")
			}
			if got := wrote.String(); got != "LHLO localhost\r\n" {
				t.Fatalf("sent %q", got)
			}
		})
	}
}

// checklist: LMTP-HELLO-01 LMTP-HELLO-02 LMTP-DATA-01 LMTP-EXT-01 LMTP-EXT-02 LMTP-EXT-03
func TestRFC2033GreetingAndSequence(t *testing.T) {
	for _, lmtp := range []bool{false, true} {
		t.Run(fmt.Sprint(lmtp), func(t *testing.T) {
			_, c, br, _ := newFlushTestConn(t, func(s *server.Server) { s.LMTP = lmtp })
			command := func(cmd, want string) []string {
				t.Helper()
				writeFlushBatch(t, c, cmd+"\r\n")
				got := readFlushReply(t, br)
				if !strings.HasPrefix(got[0], want) {
					t.Fatalf("%s: %q, want %s", cmd, got, want)
				}
				return got
			}
			if !lmtp {
				command("LHLO foo.edu", "500")
				command("EHLO foo.edu", "250")
				return
			}
			command("HELO foo.edu", "500")
			command("EHLO foo.edu", "500")
			command("MAIL FROM:<chris@bar.com>", "503")
			command("LHLO", "501")
			caps := strings.Join(command("lHlO foo.edu", "250"), "\n")
			for _, cap := range []string{"PIPELINING", "ENHANCEDSTATUSCODES", "8BITMIME"} {
				if !strings.Contains(caps, cap) {
					t.Fatalf("missing %s: %s", cap, caps)
				}
			}
			command("DATA", "503")
			command("MAIL FROM:<chris@bar.com>", "250")
			command("DATA", "503")
			command("RSET", "250")
			writeFlushBatch(t, c, "MAIL FROM:<chris@bar.com>\r\nRCPT TO:<pat@foo.edu>\r\nRCPT TO:<green@foo.edu>\r\n")
			if got := strings.Join(readFlushCodes(t, br, 3), ","); got != "250,250,250" {
				t.Fatalf("pipeline replies=%s", got)
			}
			command("RSET", "250")
			command("QUIT", "221")
		})
	}
}

// checklist: LMTP-CLIENT-06 LMTP-CLIENT-02
func TestRFC2033ClientPositiveCompletion(t *testing.T) {
	// RFC 2033 defines positive completion by the first digit, including
	// unrecognized 2xx codes. Exercise the complete class and its boundaries.
	codes := []int{199, 300, 354, 399, 400, 451, 499, 500, 550, 599}
	for code := 200; code < 300; code++ {
		codes = append(codes, code)
	}
	for _, code := range codes {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var wrote bytes.Buffer
			fake := faker{ReadWriter: struct {
				io.Reader
				io.Writer
			}{strings.NewReader(fmt.Sprintf("220 ready\r\n250 hello\r\n250 sender\r\n"+
				"250 recipient\r\n250 recipient\r\n250 recipient\r\n250 recipient\r\n354 send data\r\n"+
				"%d-first line\r\n%d final line\r\n451 4.2.2 quota\r\n550 5.1.1 no mailbox\r\n250 delivered\r\n250 noop\r\n", code, code)), &wrote}}
			c := NewLMTP(fake)
			defer c.Close()
			if err := c.Mail("chris@bar.com", nil); err != nil {
				t.Fatal(err)
			}
			for _, rcpt := range []string{"pat@foo.edu", "quota@foo.edu", "missing@foo.edu", "green@foo.edu"} {
				if err := c.Rcpt(rcpt, nil); err != nil {
					t.Fatal(err)
				}
			}
			cmd, err := c.Data()
			if err != nil {
				t.Fatal(err)
			}
			resp, err := cmd.CloseWithLMTPResponse()
			var failures LMTPDataError
			if !errors.As(err, &failures) {
				t.Fatalf("error=%v, want per-recipient failures", err)
			}
			wantSuccesses, wantFailures := 1, 3
			if code >= 200 && code < 300 {
				wantSuccesses, wantFailures = 2, 2
				if got := resp["pat@foo.edu"]; got == nil || got.StatusText != "first line\nfinal line" {
					t.Fatalf("positive completion lost: responses=%v, failures=%v", resp, failures)
				}
			} else if got := failures["pat@foo.edu"]; got == nil || got.Code != code || got.Message != "first line\nfinal line" {
				t.Fatalf("unexpected reply accepted or changed: %v", failures)
			}
			if len(resp) != wantSuccesses || len(failures) != wantFailures || resp["green@foo.edu"] == nil {
				t.Fatalf("responses=%v, failures=%v", resp, failures)
			}
			for rcpt, want := range map[string]int{"quota@foo.edu": 451, "missing@foo.edu": 550} {
				if got := failures[rcpt]; got == nil || got.Code != want {
					t.Fatalf("%s failure=%v, want %d", rcpt, got, want)
				}
			}
			if err := c.Noop(); err != nil {
				t.Fatalf("reply stream lost synchronization: %v", err)
			}
		})
	}
}

// checklist: LMTP-CLIENT-06
func TestRFC2033ClientClosePositiveCompletion(t *testing.T) {
	var wrote bytes.Buffer
	fake := faker{ReadWriter: struct {
		io.Reader
		io.Writer
	}{strings.NewReader("251 forwarded\r\n299 delivered\r\n"), &wrote}}
	c := NewLMTP(fake)
	defer c.Close()
	c.rcpts = []string{"pat@foo.edu", "green@foo.edu"}
	cmd := &DataCommand{client: c}
	if err := cmd.Close(); err != nil {
		t.Fatalf("positive completion returned as failure: %v", err)
	}
}

// checklist: LMTP-DATA-04 LMTP-CLIENT-01 LMTP-CLIENT-02 LMTP-CLIENT-06
func TestRFC2033ClientPartialReplies(t *testing.T) {
	for _, tail := range []string{"", "550 5.1.1 no mailbox\r\n"} {
		var wrote bytes.Buffer
		fake := faker{ReadWriter: struct {
			io.Reader
			io.Writer
		}{strings.NewReader("251-2.0.0 delivered\r\n251 2.0.0 durable\r\n" + tail), &wrote}}
		c := NewLMTP(fake)
		defer c.Close()
		c.rcpts = []string{"pat@foo.edu", "green@foo.edu", "missing@foo.edu"}
		cmd := &DataCommand{client: c}
		resp, err := cmd.CloseWithLMTPResponse()
		if !errors.Is(err, io.EOF) {
			t.Fatalf("error=%v, want EOF", err)
		}
		if len(resp) != 1 || resp["pat@foo.edu"] == nil || !strings.Contains(resp["pat@foo.edu"].StatusText, "durable") {
			t.Fatalf("responses=%v", resp)
		}
		var failures LMTPDataError
		if tail != "" && (!errors.As(err, &failures) || failures["green@foo.edu"].Code != 550) {
			t.Fatalf("lost known failure: %v", err)
		}
		if wrote.String() != ".\r\n" {
			t.Fatalf("terminator=%q", wrote.String())
		}
	}
}

// checklist: LMTP-CLIENT-03
func TestRFC2033ClientUnansweredRecipientsTemporary(t *testing.T) {
	for _, tc := range []struct {
		name, replies string
		answered      []string
		unanswered    []string
	}{
		{"no replies", "", nil, []string{"pat@foo.edu", "green@foo.edu", "jones@foo.edu"}},
		{"after success", "250 2.0.0 ok\r\n", []string{"pat@foo.edu"}, []string{"green@foo.edu", "jones@foo.edu"}},
		{"after failure", "250 2.0.0 ok\r\n550 5.1.1 no mailbox\r\n", []string{"pat@foo.edu", "green@foo.edu"}, []string{"jones@foo.edu"}},
		{"truncated reply", "250 2.0.0 ok\r\n25", []string{"pat@foo.edu"}, []string{"green@foo.edu", "jones@foo.edu"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := faker{ReadWriter: struct {
				io.Reader
				io.Writer
			}{strings.NewReader(tc.replies), io.Discard}}
			c := NewLMTP(fake)
			defer c.Close()
			c.rcpts = []string{"pat@foo.edu", "green@foo.edu", "jones@foo.edu"}
			cmd := &DataCommand{client: c}
			resp, err := cmd.CloseWithLMTPResponse()
			if err == nil {
				t.Fatal("lost connection reported as success")
			}
			var failures LMTPDataError
			if !errors.As(err, &failures) {
				t.Fatalf("error=%v, want LMTPDataError", err)
			}
			if len(resp)+len(failures) != 3 {
				t.Fatalf("responses=%v failures=%v, want one outcome per recipient", resp, failures)
			}
			for _, rcpt := range tc.answered {
				if resp[rcpt] == nil && failures[rcpt].Code != 550 {
					t.Errorf("%s: received reply lost", rcpt)
				}
			}
			for _, rcpt := range tc.unanswered {
				failure := failures[rcpt]
				if failure == nil || !failure.Temporary() || failure.Code != 451 || failure.EnhancedCode != (smtp.EnhancedCode{4, 4, 2}) {
					t.Errorf("%s: failure=%v, want temporary 451 4.4.2", rcpt, failure)
				}
				if resp[rcpt] != nil {
					t.Errorf("%s: unanswered recipient reported as delivered", rcpt)
				}
			}
		})
	}
}
