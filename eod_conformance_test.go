package smtp_test

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp"
)

// End-of-data conformance (RFC 5321 §2.3.8, §4.1.1.4, §4.5.2; RFC 3030 §2).
//
// Only <CRLF>.<CRLF> ends DATA, and a bare CR or bare LF is not a line
// terminator. A receiver that also ends the message at <LF>.<LF>, <CR>.<CR>,
// <LF>.<CR><LF> or <CR><LF>.<LF> can be fed one message that a relay reads as
// one and it reads as two ("SMTP smuggling", CVE-2023-51764/51765/51766).
//
// Requirements exercised here:
//
//	EOD-1  DATA ends only at <CRLF>.<CRLF>
//	EOD-2  bare LF / bare CR never end the DATA stream, nor start a line
//	EOD-3  text after a non-standard sequence is never run as a command
//	EOD-4  BDAT chunk boundaries come from the size only (RFC 3030)
//	EOD-5  command lines end at <CRLF> only; a bare LF is not a separator
//	EOD-6  the client dot-stuffs and normalises bare LF so a receiver can't
//	       be made to end DATA early

// delivered returns every message the backend accepted, authenticated or not.
func delivered(be *backend) []*message {
	return append(append([]*message{}, be.messages...), be.anonmsgs...)
}

// replyCodes returns the status code of every reply line, in order.
func replyCodes(out string) []string {
	var codes []string
	for _, l := range strings.Split(out, "\r\n") {
		if len(l) >= 4 && (l[3] == ' ' || l[3] == '-') {
			codes = append(codes, l[:3])
		}
	}
	return codes
}

func countCode(out, code string) int {
	n := 0
	for _, l := range strings.Split(out, "\r\n") {
		if strings.HasPrefix(l, code+" ") {
			n++
		}
	}
	return n
}

// smuggledTail is what an attacker hides after a non-standard end-of-data
// sequence: a complete second transaction.
// It has no terminator of its own: the one real <CRLF>.<CRLF> follows it.
const smuggledTail = "MAIL FROM:<evil@example.org>\r\n" +
	"RCPT TO:<victim@example.com>\r\n" +
	"DATA\r\n" +
	"Subject: smuggled\r\n" +
	"\r\n" +
	"smuggled body\r\n"

// TestEODNonStandardSequencesDoNotEndData sends each non-standard sequence
// inside DATA, followed by a smuggled second transaction and then the real
// <CRLF>.<CRLF>. The message must either stay one message (the sequence being
// content) or be refused; the smuggled commands must never run.
func TestEODNonStandardSequencesDoNotEndData(t *testing.T) {
	cases := []struct {
		name string
		seq  string // as sent
		kept string // as the backend sees it: a dot after a real CRLF is un-stuffed
	}{
		{"LF.LF", "\n.\n", "\n.\n"},
		{"CR.CR", "\r.\r", "\r.\r"},
		{"LF.CRLF", "\n.\r\n", "\n.\r\n"},
		{"CRLF.LF", "\r\n.\n", "\r\n\n"},
		{"CR.CRLF", "\r.\r\n", "\r.\r\n"},
		{"CRLF.CR", "\r\n.\r", "\r\n\r"},
		{"LF.CR", "\n.\r", "\n.\r"},
		{"CRLF.CRCRLF", "\r\n.\r\r\n", "\r\n\r\r\n"},
		{"CRCR.CRLF", "\r\r.\r\n", "\r\r.\r\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be, s, c, scanner := testServerGreeted(t)
			defer s.Close()
			defer c.Close()

			io.WriteString(c, "EHLO localhost\r\n")
			drainEhlo(scanner)

			io.WriteString(c, "MAIL FROM:<alice@example.org>\r\n")
			io.WriteString(c, "RCPT TO:<bob@example.com>\r\n")
			io.WriteString(c, "DATA\r\n")
			io.WriteString(c, "Subject: one\r\n\r\nbefore"+tc.seq+smuggledTail)
			io.WriteString(c, ".\r\n")
			io.WriteString(c, "QUIT\r\n")

			// The scanner already consumed part of the stream; read the rest
			// through it so nothing is lost.
			var out strings.Builder
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			for scanner.Scan() {
				out.WriteString(scanner.Text() + "\r\n")
			}
			replies := out.String()

			if n := countCode(replies, "354"); n != 1 {
				t.Errorf("DATA was started %d times, want 1 (smuggled DATA ran); replies:\n%s", n, replies)
			}
			if len(delivered(be)) > 1 {
				t.Fatalf("backend received %d messages, want at most 1", len(delivered(be)))
			}
			if len(delivered(be)) == 1 {
				m := delivered(be)[0]
				if m.From != "alice@example.org" {
					t.Errorf("message envelope sender = %q, smuggled MAIL FROM took over", m.From)
				}
				if len(m.To) != 1 || m.To[0] != "bob@example.com" {
					t.Errorf("message recipients = %v", m.To)
				}
				// Stays content: everything up to the real terminator arrives.
				want := "Subject: one\r\n\r\nbefore" + tc.kept + smuggledTail
				if !bytes.Equal(m.Data, []byte(want)) {
					t.Errorf("message data = %q, want %q", m.Data, want)
				}
				if countCode(replies, "250") < 1 {
					t.Errorf("expected acceptance of the single message; replies:\n%s", replies)
				}
			}
		})
	}
}

// TestEODCRBeforeCRLFDotEndsData: "x\r" + <CRLF>.<CRLF> contains the real
// terminator, so the message must end there, even though the byte before the
// <CRLF> is a stray CR. Otherwise a sender that is exact about <CRLF> hangs
// waiting for a reply the server never sends, and the two ends disagree about
// where the message stops.
func TestEODCRBeforeCRLFDotEndsData(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"CR-CRLF-dot", "line\r\r\n.\r\n", "line\r\r\n"},
		{"CR-CR-CRLF-dot", "line\r\r\r\n.\r\n", "line\r\r\r\n"},
		{"dotted-line-with-CR", "a\r\n.\r\r\n.\r\n", "a\r\n\r\r\n"},
		{"dot-CR-then-text-keeps-the-CR", "a\r\n.\rb\r\n.\r\n", "a\r\n\rb\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be, s, c, scanner := testServerGreeted(t)
			defer s.Close()
			defer c.Close()

			io.WriteString(c, "EHLO localhost\r\n")
			drainEhlo(scanner)
			io.WriteString(c, "MAIL FROM:<alice@example.org>\r\nRCPT TO:<bob@example.com>\r\nDATA\r\n")
			io.WriteString(c, tc.body)
			io.WriteString(c, "QUIT\r\n")

			var out strings.Builder
			c.SetReadDeadline(time.Now().Add(3 * time.Second))
			for scanner.Scan() {
				out.WriteString(scanner.Text() + "\r\n")
			}
			if len(delivered(be)) != 1 {
				t.Fatalf("backend received %d messages, want 1; replies:\n%s", len(delivered(be)), out.String())
			}
			if got := string(delivered(be)[0].Data); got != tc.want {
				t.Errorf("message data = %q, want %q", got, tc.want)
			}
			if !strings.Contains(out.String(), "221 ") {
				t.Errorf("QUIT after the message was not answered; replies:\n%s", out.String())
			}
		})
	}
}

// TestEODBDATChunksIgnoreDotSequences: with BDAT the chunk boundary is the
// declared size alone; dot lines, bare-LF dots and a plain <CRLF>.<CRLF> inside
// a chunk are content, and a "command" inside a chunk is not executed.
func TestEODBDATChunksIgnoreDotSequences(t *testing.T) {
	chunks := []string{
		"Subject: bdat\r\n\r\nbefore\r\n.\r\nMAIL FROM:<evil@example.org>\r\n.\r\n",
		"\n.\n\r.\r\n.\r\r\n.\r\nDATA\r\nstill content\r\n.\r\n",
	}
	// The chunk size comes from the length of the bytes, not their content.
	be, s, c, scanner := testServerGreeted(t)
	defer s.Close()
	defer c.Close()

	io.WriteString(c, "EHLO localhost\r\n")
	drainEhlo(scanner)
	io.WriteString(c, "MAIL FROM:<alice@example.org>\r\nRCPT TO:<bob@example.com>\r\n")
	var want string
	for i, ch := range chunks {
		want += ch
		last := ""
		if i == len(chunks)-1 {
			last = " LAST"
		}
		io.WriteString(c, "BDAT "+itoa(len(ch))+last+"\r\n")
		io.WriteString(c, ch)
	}
	io.WriteString(c, "QUIT\r\n")

	var out strings.Builder
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for scanner.Scan() {
		out.WriteString(scanner.Text() + "\r\n")
	}
	replies := out.String()
	if len(delivered(be)) != 1 {
		t.Fatalf("backend received %d messages, want 1; replies:\n%s", len(delivered(be)), replies)
	}
	if got := string(delivered(be)[0].Data); got != want {
		t.Errorf("message data = %q, want %q", got, want)
	}
	if delivered(be)[0].From != "alice@example.org" {
		t.Errorf("sender = %q", delivered(be)[0].From)
	}
	if n := countCode(replies, "354"); n != 0 {
		t.Errorf("a DATA command inside a chunk ran (%d x 354)", n)
	}
	// One 250 per BDAT chunk, nothing extra.
	codes := replyCodes(replies)
	if len(codes) == 0 || codes[len(codes)-1] != "221" {
		t.Errorf("replies did not end with 221: %v", codes)
	}
}

func itoa(n int) string {
	var b [20]byte
	i := len(b)
	if n == 0 {
		return "0"
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// TestEODCommandLineBareLF: a command line ends at <CRLF> only. A bare LF
// is refused with a 500 and the connection is closed; the command after the
// bare LF never runs. A bare CR in the middle of a line is not a line ending
// either, so it never splits one line into two commands.
func TestEODCommandLineBareLF(t *testing.T) {
	cases := []struct {
		name  string
		input string
		// replies expected, in order, after the EHLO reply
		codes []string
	}{
		{"LF-between-MAIL-and-RCPT", "MAIL FROM:<a@example.org>\nRCPT TO:<b@example.com>\r\n", []string{"500"}},
		{"LF-then-DATA", "MAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.com>\r\nNOOP\nDATA\r\n", []string{"250", "250", "500"}},
		{"LF-only-terminator", "NOOP\n", []string{"500"}},
		{"CR-mid-line", "MAIL FROM:<a@example.org>\rRCPT TO:<b@example.com>\r\n", []string{"501"}},
		{"CR-then-CRLF", "NOOP\r\rNOOP\r\n", []string{"501"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be, s, c, scanner := testServerGreeted(t)
			defer s.Close()
			defer c.Close()

			io.WriteString(c, "EHLO localhost\r\n")
			drainEhlo(scanner)
			io.WriteString(c, tc.input)
			io.WriteString(c, "QUIT\r\n")

			var out strings.Builder
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			for scanner.Scan() {
				out.WriteString(scanner.Text() + "\r\n")
			}
			replies := out.String()

			if len(delivered(be)) != 0 {
				t.Errorf("a message was delivered from a malformed command stream")
			}
			if countCode(replies, "354") != 0 {
				t.Errorf("DATA ran after a bare-LF separated command:\n%s", replies)
			}
			got := replyCodes(replies)
			// Whatever follows the expected replies is the QUIT answer, or
			// nothing at all when the server closed the connection first.
			if len(got) < len(tc.codes) {
				t.Fatalf("replies = %v, want prefix %v\n%s", got, tc.codes, replies)
			}
			for i, want := range tc.codes {
				if got[i] != want {
					t.Errorf("reply %d = %s, want %s\n%s", i, got[i], want, replies)
				}
			}
			if len(got) > len(tc.codes) && strings.HasPrefix(tc.name, "LF") {
				t.Errorf("server kept talking after a bare LF: %v\n%s", got, replies)
			}
		})
	}
}

// capture is a listener that plays a minimal SMTP server and records the exact
// bytes of the DATA section the client puts on the wire.
type capture struct {
	l    net.Listener
	data chan []byte
}

func newCapture(t *testing.T) *capture {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cp := &capture{l: l, data: make(chan []byte, 1)}
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		br := bufio.NewReader(c)
		io.WriteString(c, "220 capture ESMTP\r\n")
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			switch strings.ToUpper(strings.TrimRight(line, "\r\n")[:min(4, len(strings.TrimRight(line, "\r\n")))]) {
			case "EHLO":
				io.WriteString(c, "250 capture\r\n")
			case "MAIL", "RCPT":
				io.WriteString(c, "250 OK\r\n")
			case "DATA":
				io.WriteString(c, "354 go\r\n")
				var buf bytes.Buffer
				// Read until the first <CRLF>.<CRLF>, exactly as RFC 5321 says.
				for !bytes.HasSuffix(buf.Bytes(), []byte("\r\n.\r\n")) {
					b, err := br.ReadByte()
					if err != nil {
						return
					}
					buf.WriteByte(b)
				}
				cp.data <- buf.Bytes()
				io.WriteString(c, "250 queued\r\n")
			case "QUIT":
				io.WriteString(c, "221 bye\r\n")
				return
			}
		}
	}()
	return cp
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestEODClientDotStuffsAndNormalises: bodies that contain a lone "." line, a
// line starting with ".", or bare LF terminators must reach the wire dot-stuffed
// and CRLF-normalised, so a receiver reading up to the first <CRLF>.<CRLF>
// (and nothing else) sees the whole message and no early end.
func TestEODClientDotStuffsAndNormalises(t *testing.T) {
	cases := []struct {
		name, body, wire string
	}{
		{"LF.LF", "a\n.\nb\n", "a\r\n..\r\nb\r\n"},
		{"leading-dot-line", "a\r\n.hidden\r\nb\r\n", "a\r\n..hidden\r\nb\r\n"},
		{"lone-dot-CRLF", "a\r\n.\r\nMAIL FROM:<evil@example.org>\r\n", "a\r\n..\r\nMAIL FROM:<evil@example.org>\r\n"},
		{"dot-first-line", ".\nrest\n", "..\r\nrest\r\n"},
		{"LF.CRLF", "a\n.\r\nb\r\n", "a\r\n..\r\nb\r\n"},
		{"CRLF.LF", "a\r\n.\nb\r\n", "a\r\n..\r\nb\r\n"},
		{"no-trailing-newline", "a\r\n.", "a\r\n..\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := newCapture(t)
			defer cp.l.Close()

			cl, err := smtp.Dial(cp.l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer cl.Close()
			if err := cl.Hello("localhost"); err != nil {
				t.Fatal(err)
			}
			if err := cl.SendMail("alice@example.org", []string{"bob@example.com"}, strings.NewReader(tc.body)); err != nil {
				t.Fatal(err)
			}
			cl.Quit()

			select {
			case got := <-cp.data:
				want := tc.wire + ".\r\n"
				if string(got) != want {
					t.Errorf("wire = %q, want %q", got, want)
				}
				if n := bytes.Count(got, []byte("\r\n.\r\n")); n != 1 || !bytes.HasSuffix(got, []byte("\r\n.\r\n")) {
					t.Errorf("end-of-data sequence appears %d times in %q, want only at the end", n, got)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no DATA captured")
			}
		})
	}
}
