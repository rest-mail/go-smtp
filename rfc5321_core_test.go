package smtp_test

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp"
)

// readReply reads one reply, multiline or not, and returns its lines.
func readReply(t *testing.T, scanner *bufio.Scanner) []string {
	t.Helper()
	var lines []string
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
		if len(line) < 4 || line[3] != '-' {
			return lines
		}
	}
	t.Fatalf("connection ended mid-reply after %q: %v", lines, scanner.Err())
	return nil
}

// RFC 5321 §4.1.1.1 and §4.3.1: the server identifies itself with its domain
// in the 220 greeting and as the first word of the HELO and EHLO replies
// (ehlo-ok-rsp = "250" SP Domain [SP ehlo-greet]).
//
// checklist: SMTP-REP-04
func TestRFC5321_ServerIdentifiesItself(t *testing.T) {
	_, s, c, scanner := testServer(t, func(s *smtp.Server) { s.Domain = "mx.example.net" })
	defer s.Close()
	defer c.Close()

	if got := readReply(t, scanner); got[0] != "220 mx.example.net ESMTP Service Ready" {
		t.Fatalf("greeting = %q", got)
	}
	io.WriteString(c, "EHLO client.example.org\r\n")
	ehlo := readReply(t, scanner)
	if len(ehlo) < 2 || ehlo[0] != "250-mx.example.net Hello client.example.org" {
		t.Fatalf("EHLO reply = %q, want the server domain first", ehlo)
	}
	io.WriteString(c, "HELO client.example.org\r\n")
	if got := readReply(t, scanner); len(got) != 1 || !strings.HasPrefix(got[0], "250 2.0.0 mx.example.net ") {
		t.Fatalf("HELO reply = %q, want the server domain first", got)
	}
}

// RFC 5321 §4.1.1.9: NOOP has no effect on the transaction, and a server
// SHOULD ignore a parameter string given with it.
//
// checklist: SMTP-CMD-10
func TestRFC5321_NoopIgnoresParameter(t *testing.T) {
	be, s, c, scanner, _ := testServerEhlo(t)
	defer s.Close()
	defer c.Close()
	next := func() string { scanner.Scan(); return scanner.Text() }

	expectReply(t, c, next, "NOOP\r\n", "250 ")
	expectReply(t, c, next, "NOOP ignored parameter string\r\n", "250 ")
	expectReply(t, c, next, "MAIL FROM:<a@example.org>\r\n", "250 ")
	expectReply(t, c, next, "noop x\r\n", "250 ")
	expectReply(t, c, next, "RCPT TO:<b@example.org>\r\n", "250 ")
	expectReply(t, c, next, "DATA\r\n", "354 ")
	expectReply(t, c, next, "Subject: t\r\n\r\nbody\r\n.\r\n", "250 ")

	if len(be.anonmsgs) != 1 || be.anonmsgs[0].From != "a@example.org" || len(be.anonmsgs[0].To) != 1 {
		t.Fatalf("delivered %+v, want one message from a@example.org to one recipient", be.anonmsgs)
	}
}

// RFC 5321 §4.1.4: NOOP, HELP, EXPN, VRFY and RSET may be used at any time:
// before HELO/EHLO, and inside a transaction without disturbing its sender or
// recipients (EXPN is answered 502 here, see SMTP-CMD-07).
//
// checklist: SMTP-ORD-06
func TestRFC5321_AnyTimeCommands(t *testing.T) {
	be, s, c, scanner := testServerGreeted(t)
	defer s.Close()
	defer c.Close()
	next := func() string { scanner.Scan(); return scanner.Text() }

	expectReply(t, c, next, "NOOP\r\n", "250 ")
	expectReply(t, c, next, "VRFY someone\r\n", "252 ")
	expectReply(t, c, next, "RSET\r\n", "250 ")
	expectReply(t, c, next, "HELP\r\n", "214 ")
	expectReply(t, c, next, "HELO client.example.org\r\n", "250 ")

	expectReply(t, c, next, "MAIL FROM:<a@example.org>\r\n", "250 ")
	expectReply(t, c, next, "RCPT TO:<b@example.org>\r\n", "250 ")
	expectReply(t, c, next, "NOOP\r\n", "250 ")
	expectReply(t, c, next, "VRFY b@example.org\r\n", "252 ")
	expectReply(t, c, next, "EXPN list\r\n", "502 ")
	expectReply(t, c, next, "HELP MAIL\r\n", "214 ")
	expectReply(t, c, next, "RCPT TO:<c@example.org>\r\n", "250 ")
	expectReply(t, c, next, "DATA\r\n", "354 ")
	expectReply(t, c, next, "\r\nbody\r\n.\r\n", "250 ")

	if len(be.anonmsgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(be.anonmsgs))
	}
	msg := be.anonmsgs[0]
	if msg.From != "a@example.org" || strings.Join(msg.To, ",") != "b@example.org,c@example.org" {
		t.Fatalf("delivered from %q to %q, want the transaction unchanged", msg.From, msg.To)
	}
}

// RFC 5321 §4.1.1.8: the server SHOULD support HELP without arguments and
// MAY take an argument. Both get a single-line 214 reply (§4.3.2), in any
// state and any case, and the reply names the greeting command for the
// protocol being served. HELP changes no session state.
//
// checklist: SMTP-AUDIT-36
func TestRFC5321_Help(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lmtp  bool
		greet string
	}{
		{"SMTP", false, "EHLO"},
		{"LMTP", true, "LHLO"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			be, s, c, scanner := testServer(t, func(s *smtp.Server) { s.LMTP = tc.lmtp })
			defer s.Close()
			defer c.Close()
			next := func() string { scanner.Scan(); return scanner.Text() }
			if got := next(); !strings.HasPrefix(got, "220 ") {
				t.Fatalf("greeting = %q", got)
			}

			want := "214 2.0.0 Send " + tc.greet + " to list the supported extensions"
			help := func(cmd string) {
				t.Helper()
				io.WriteString(c, cmd)
				if got := next(); got != want {
					t.Fatalf("%q: got %q, want %q", strings.TrimSpace(cmd), got, want)
				}
			}

			help("HELP\r\n")
			help("help\r\n")
			help("HELP MAIL\r\n")
			help("HELP \r\n")
			expectReply(t, c, next, tc.greet+" client.example.org\r\n", "250")
			for scanner.Text()[3] == '-' {
				next()
			}
			expectReply(t, c, next, "MAIL FROM:<a@example.org>\r\n", "250 ")
			help("HeLp\r\n")
			expectReply(t, c, next, "RCPT TO:<b@example.org>\r\n", "250 ")
			help("HELP RCPT\r\n")
			expectReply(t, c, next, "DATA\r\n", "354 ")
			io.WriteString(c, "\r\nbody\r\n.\r\n")
			if got := next(); !strings.HasPrefix(got, "250 ") {
				t.Fatalf("end of data: got %q", got)
			}

			if len(be.anonmsgs) != 1 || be.anonmsgs[0].From != "a@example.org" || len(be.anonmsgs[0].To) != 1 {
				t.Fatalf("delivered %+v, want one message from a@example.org to one recipient", be.anonmsgs)
			}
		})
	}
}

// RFC 5321 §2.4: the local-part of a mailbox MUST be treated as case
// sensitive, so the server passes it to the backend exactly as received.
// The domain is passed unchanged as well.
//
// checklist: SMTP-SYN-14
func TestRFC5321_LocalPartCasePreserved(t *testing.T) {
	be, s, c, scanner, _ := testServerEhlo(t)
	defer s.Close()
	defer c.Close()
	next := func() string { scanner.Scan(); return scanner.Text() }

	expectReply(t, c, next, "MAIL FROM:<John.Smith@Example.COM>\r\n", "250 ")
	expectReply(t, c, next, "RCPT TO:<MiXeD@Example.ORG>\r\n", "250 ")
	expectReply(t, c, next, "RCPT TO:<mixed@example.org>\r\n", "250 ")
	expectReply(t, c, next, "DATA\r\n", "354 ")
	expectReply(t, c, next, "\r\nbody\r\n.\r\n", "250 ")

	if len(be.anonmsgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(be.anonmsgs))
	}
	msg := be.anonmsgs[0]
	if msg.From != "John.Smith@Example.COM" {
		t.Errorf("From = %q, want the case as sent", msg.From)
	}
	if strings.Join(msg.To, ",") != "MiXeD@Example.ORG,mixed@example.org" {
		t.Errorf("To = %q, want two distinct recipients in the case sent", msg.To)
	}
}

// RFC 5321 §4.1.1.1 and §4.1.3: a client without a meaningful domain name
// greets with an address literal, IPv4 or IPv6; the server accepts it and
// hands it to the backend as the client's name.
//
// checklist: SMTP-SYN-15
func TestRFC5321_HelloAddressLiteral(t *testing.T) {
	for _, tc := range []struct{ verb, name string }{
		{"EHLO", "[192.0.2.1]"},
		{"HELO", "[192.0.2.1]"},
		{"EHLO", "[IPv6:2001:db8::1]"},
	} {
		hostnames := make(chan string, 1)
		_, s, c, scanner := testServerGreeted(t, func(s *smtp.Server) {
			be := s.Backend
			s.Backend = smtp.BackendFunc(func(conn *smtp.Conn) (smtp.Session, error) {
				hostnames <- conn.Hostname()
				return be.NewSession(conn)
			})
		})
		io.WriteString(c, tc.verb+" "+tc.name+"\r\n")
		if got := readReply(t, scanner); !strings.HasPrefix(got[len(got)-1], "250 ") {
			t.Errorf("%s %s: reply %q", tc.verb, tc.name, got)
		}
		select {
		case got := <-hostnames:
			if got != tc.name {
				t.Errorf("%s %s: backend saw hostname %q", tc.verb, tc.name, got)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("%s %s: no session was started", tc.verb, tc.name)
		}
		next := func() string { scanner.Scan(); return scanner.Text() }
		expectReply(t, c, next, "MAIL FROM:<a@example.org>\r\n", "250 ")
		c.Close()
		s.Close()
	}
}

// silentServer greets, answers each command line with the matching entry of
// replies, and then reads without answering.
func silentServer(t *testing.T, replies ...string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.WriteString(conn, "220 silent.example.net ESMTP\r\n")
		r := bufio.NewReader(conn)
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line != ".\r\n" {
					continue
				}
				inData = false
			}
			if len(replies) == 0 {
				continue // stop answering
			}
			if strings.HasPrefix(replies[0], "354") {
				inData = true
			}
			io.WriteString(conn, replies[0])
			replies = replies[1:]
		}
	}()
	return l.Addr().String()
}

// RFC 5321 §4.5.3.2: a client SHOULD time out a server that stops answering,
// for each command and for the reply after the final dot. The defaults are at
// least the RFC minimums (5 minutes per command, 10 minutes after the dot).
//
// checklist: SMTP-LIM-07
func TestRFC5321_ClientTimeouts(t *testing.T) {
	addr := silentServer(t)
	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.CommandTimeout < 5*time.Minute || c.SubmissionTimeout < 10*time.Minute {
		t.Fatalf("default timeouts %v/%v are under the RFC 5321 §4.5.3.2 minimums", c.CommandTimeout, c.SubmissionTimeout)
	}
	c.CommandTimeout = 100 * time.Millisecond
	start := time.Now()
	err = c.Hello("client.example.org")
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("Hello on a silent server: err = %v, want a timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Hello gave up after %v", elapsed)
	}

	// The server answers every command but never the final dot.
	addr = silentServer(t,
		"250 silent.example.net\r\n",
		"250 2.0.0 ok\r\n",
		"250 2.0.0 ok\r\n",
		"354 go ahead\r\n",
	)
	c, err = smtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.CommandTimeout = 5 * time.Second
	c.SubmissionTimeout = 100 * time.Millisecond
	if err := c.Hello("client.example.org"); err != nil {
		t.Fatal(err)
	}
	if err := c.Mail("a@example.org", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("b@example.org", nil); err != nil {
		t.Fatal(err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, "Subject: t\r\n\r\nbody\r\n")
	start = time.Now()
	err = w.Close()
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("Close with no reply after the dot: err = %v, want a timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Close gave up after %v", elapsed)
	}
}
