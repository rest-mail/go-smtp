package smtp_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp"
)

// checklist: SIZE-EHLO-01 SIZE-EHLO-02
func TestRFC1870Advertisement(t *testing.T) {
	for _, limit := range []int64{0, 1000000, 1 << 40} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			_, s, c, _, caps := testServerEhlo(t, func(s *smtp.Server) { s.MaxMessageBytes = limit })
			defer s.Close()
			defer c.Close()
			if !caps[fmt.Sprintf("SIZE %d", limit)] {
				t.Fatalf("missing explicit SIZE limit %d in %v", limit, caps)
			}
		})
	}
}

// checklist: SIZE-MAIL-01 SIZE-MAIL-02 SIZE-MAIL-03 SIZE-REPLY-01
func TestRFC1870Declarations(t *testing.T) {
	for _, tc := range []struct {
		value string
		limit int64
		code  string
	}{
		{"0", 0, "250 "}, {"00000000000000000000", 0, "250 "},
		{"4294967296", 1 << 40, "250 "}, {"9223372036854775807", 0, "250 "},
		{"00000000000000000001", 0, "250 "}, {"00000000000000000009", 0, "250 "},
		{"1000000", 1000000, "250 "}, {"1000001", 1000000, "552 "},
		{"9223372036854775808", 0, "552 "}, {"18446744073709551616", 0, "552 "},
		{"99999999999999999999", 1000000, "552 "},
		{"", 0, "501 "}, {"+1", 0, "501 "}, {"-1", 0, "501 "},
		{"1.0", 0, "501 "}, {"1e3", 0, "501 "}, {"１２", 0, "501 "},
		{"000000000000000000000", 0, "501 "}, {"1 SIZE=2", 0, "501 "},
	} {
		t.Run(tc.value+fmt.Sprint(tc.limit), func(t *testing.T) {
			be, s, c, scanner, _ := testServerEhlo(t, func(s *smtp.Server) { s.MaxMessageBytes = tc.limit })
			defer s.Close()
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			next := func() string { scanner.Scan(); return scanner.Text() }
			expectReply(t, c, next, "MAIL FROM:<a@example.org> SIZE="+tc.value+"\r\n", tc.code)
			if tc.code == "250 " {
				expectReply(t, c, next, "RCPT TO:<b@example.org>\r\n", "250 ")
				expectReply(t, c, next, "DATA\r\n", "354 ")
				expectReply(t, c, next, ".\r\n", "250 ")
				if len(be.anonmsgs) != 1 {
					t.Fatal("accepted declaration was not delivered")
				}
				var want int64
				if _, err := fmt.Sscanf(tc.value, "%d", &want); err != nil {
					t.Fatal(err)
				}
				if got := be.anonmsgs[0].Opts.Size; got != want {
					t.Fatalf("backend SIZE = %d, want %d", got, want)
				}
			} else {
				// A refusal must not start a transaction or poison the connection.
				expectReply(t, c, next, "MAIL FROM:<a@example.org>\r\n", "250 ")
			}
		})
	}
}

// The declared size is an estimate, never a DATA delimiter. Count delivered
// octets including CRLF but excluding the transparency dot and terminator.
// checklist: SIZE-DATA-01 SIZE-DATA-02 SIZE-DATA-03 SIZE-REPLY-04
func TestRFC1870DataOctets(t *testing.T) {
	want := "Subject: size\r\n\r\n.dot\r\nlast\r\n"
	for _, declared := range []int{0, 1, len(want), len(want) + 10} {
		t.Run(fmt.Sprint(declared), func(t *testing.T) {
			be, s, c, scanner, _ := testServerEhlo(t, func(s *smtp.Server) { s.MaxMessageBytes = int64(len(want)) })
			defer s.Close()
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			next := func() string { scanner.Scan(); return scanner.Text() }
			code := "250 "
			if declared > len(want) {
				code = "552 "
			}
			expectReply(t, c, next, fmt.Sprintf("MAIL FROM:<a@example.org> SIZE=%d\r\n", declared), code)
			if declared > len(want) {
				return
			}
			expectReply(t, c, next, "RCPT TO:<b@example.org>\r\n", "250 ")
			expectReply(t, c, next, "DATA\r\n", "354 ")
			expectReply(t, c, next, strings.Replace(want, ".dot", "..dot", 1)+".\r\n", "250 ")
			if len(be.anonmsgs) != 1 || string(be.anonmsgs[0].Data) != want {
				t.Fatalf("delivered content differs: %+v", be.anonmsgs)
			}
			expectReply(t, c, next, "NOOP\r\n", "250 ")
		})
	}
}

// checklist: SIZE-LINE-01
func TestRFC1870ExtendedMailLine(t *testing.T) {
	_, s, c, scanner, _ := testServerEhlo(t)
	defer s.Close()
	defer c.Close()
	// RFC 1870 extends the base 512-octet command allowance by 26.
	line := "MAIL FROM:<a@example.org>" + strings.Repeat(" ", 538-len("MAIL FROM:<a@example.org>SIZE=00000000000000000000\r\n")) + "SIZE=00000000000000000000\r\n"
	if len(line) != 538 {
		t.Fatal(len(line))
	}
	next := func() string { scanner.Scan(); return scanner.Text() }
	expectReply(t, c, next, line, "250 ")
}

type sizeExampleSession struct{ *session }

func (s *sizeExampleSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	switch to {
	case "ned@ymir.claremont.edu":
		return &smtp.SMTPError{Code: 552, EnhancedCode: smtp.EnhancedCode{5, 3, 4}, Message: "Channel size limit exceeded"}
	case "ned@hmcvax.claremont.edu":
		return &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 3, 1}, Message: "Insufficient channel storage"}
	}
	return s.session.Rcpt(to, opts)
}

// RFC 1870 §8's transaction: accept one recipient, permanently refuse a
// second, temporarily refuse a third, and deliver only to the accepted one.
// checklist: SIZE-EXAMPLE-01 SIZE-REPLY-02
func TestRFC1870Example(t *testing.T) {
	be := new(backend)
	_, s, c, scanner, _ := testServerEhlo(t, func(s *smtp.Server) {
		s.MaxMessageBytes = 1000000
		s.Backend = smtp.BackendFunc(func(_ *smtp.Conn) (smtp.Session, error) {
			return &sizeExampleSession{&session{backend: be, anonymous: true}}, nil
		})
	})
	defer s.Close()
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	next := func() string { scanner.Scan(); return scanner.Text() }
	expectReply(t, c, next, "MAIL FROM:<ned@thor.innosoft.com> SIZE=500000\r\n", "250 ")
	expectReply(t, c, next, "RCPT TO:<ned@innosoft.com>\r\n", "250 ")
	expectReply(t, c, next, "RCPT TO:<ned@ymir.claremont.edu>\r\n", "552 ")
	expectReply(t, c, next, "RCPT TO:<ned@hmcvax.claremont.edu>\r\n", "452 ")
	expectReply(t, c, next, "DATA\r\n", "354 ")
	expectReply(t, c, next, "Subject: example\r\n\r\nmessage\r\n.\r\n", "250 ")
	if len(be.anonmsgs) != 1 || len(be.anonmsgs[0].To) != 1 || be.anonmsgs[0].To[0] != "ned@innosoft.com" || be.anonmsgs[0].Opts.Size != 500000 {
		t.Fatalf("incorrect example delivery: %+v", be.anonmsgs)
	}
	expectReply(t, c, next, "QUIT\r\n", "221 ")
}
