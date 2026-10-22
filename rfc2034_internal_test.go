package smtp

import (
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

// statusLine is one RFC 2034 §4 reply line: the reply code, a separator, then
// status-code ::= class "." subject "." detail, followed by one or more spaces.
var statusLine = regexp.MustCompile(`^([245])[0-9]{2}[- ]([245])\.([0-9]{1,3})\.([0-9]{1,3}) +`)

// checklist: ESC-ADV-01
func TestRFC2034Advertisement(t *testing.T) {
	for _, lmtp := range []bool{false, true} {
		greet := "EHLO client.example.org"
		if lmtp {
			greet = "LHLO client.example.org"
		}
		t.Run(greet[:4], func(t *testing.T) {
			_, c, br, _ := newFlushTestConn(t, func(s *Server) { s.LMTP = lmtp })
			writeFlushBatch(t, c, greet+"\r\n")
			reply := readFlushReply(t, br)
			count := 0
			for _, line := range reply[1:] {
				if strings.HasPrefix(strings.ToUpper(line[4:]), "ENHANCEDSTATUSCODES") {
					count++
					if line[4:] != "ENHANCEDSTATUSCODES" {
						t.Fatalf("keyword carries a parameter: %q", line)
					}
				}
			}
			if count != 1 {
				t.Fatalf("ENHANCEDSTATUSCODES advertised %d times in %q", count, reply)
			}
		})
	}
}

// Every 2xx, 4xx and 5xx line after the greeting and HELO/EHLO carries a
// status code whose class matches the reply; 3xx replies carry none. A HELO
// client gets the codes too: the client cannot ask for or refuse them.
//
// checklist: ESC-REPLY-01 ESC-REPLY-02 ESC-REPLY-03 ESC-REPLY-04
func TestRFC2034EveryReplyLine(t *testing.T) {
	for _, greet := range []string{"EHLO", "HELO"} {
		t.Run(greet, func(t *testing.T) {
			_, c, br, _ := newFlushTestConn(t, func(s *Server) { s.MaxRecipients = 1 })
			command := func(cmd, code string) {
				t.Helper()
				writeFlushBatch(t, c, cmd+"\r\n")
				reply := readFlushReply(t, br)
				for _, line := range reply {
					if !strings.HasPrefix(line, code) {
						t.Fatalf("%q reply = %q, want %s", cmd, reply, code)
					}
					if code[0] == '3' {
						if statusLine.MatchString(strings.Replace(line, code, "250", 1)) {
							t.Fatalf("%q: 3xx reply carries a status code: %q", cmd, line)
						}
						continue
					}
					m := statusLine.FindStringSubmatch(line)
					if m == nil {
						t.Fatalf("%q: line without status code: %q (reply %q)", cmd, line, reply)
					}
					if m[1] != m[2] {
						t.Fatalf("%q: status class %s disagrees with reply %q", cmd, m[2], line)
					}
				}
			}
			command("RCPT TO:<early@example.org>", "503") // before HELO/EHLO
			writeFlushBatch(t, c, greet+" client.example.org\r\n")
			readFlushReply(t, br) // exempt from RFC 2034
			command("NOOP", "250")
			command("VRFY someone", "252")
			command("RSET", "250")
			command("XYZZ", "500")
			command("MAIL FROM:", "501")
			command("RCPT TO:<x@example.org>", "503")
			command("DATA", "503")
			command("MAIL FROM:<a@example.org>", "250")
			command("MAIL FROM:<a@example.org>", "503")
			command("RCPT TO:<b@example.org>", "250")
			command("RCPT TO:<c@example.org>", "452")
			command("DATA", "354")
			command("Subject: hi\r\n\r\nbody\r\n.", "250")
			if greet == "EHLO" {
				command("BDAT 0 LAST", "503")
				command("AUTH PLAIN", "334")
				command("*", "501")
				command("AUTH PLAIN AHVzZXJuYW1lAHdyb25n", "454")
				command("AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk", "235")
			}
			command("QUIT", "221")
		})
	}
}

type rfc2034Session struct {
	nopSession
	rcpt error
	data error
}

func (s rfc2034Session) Rcpt(string, *RcptOptions) error { return s.rcpt }
func (s rfc2034Session) Data(r io.Reader) error {
	io.Copy(io.Discard, r)
	return s.data
}

// A multiline host reply repeats one status code on every line, an SMTPError
// without one gets X.0.0 and a plain error gets 554 5.0.0.
//
// checklist: ESC-MULTI-01 ESC-REPLY-02
func TestRFC2034MultilineSameCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		rcpt error
		data error
		want []string
	}{
		{"coded rcpt", &SMTPError{Code: 550, EnhancedCode: EnhancedCode{5, 1, 1}, Message: "no such user\nsee postmaster\nbye"}, nil,
			[]string{"550-5.1.1 no such user", "550-5.1.1 see postmaster", "550 5.1.1 bye"}},
		{"uncoded rcpt", &SMTPError{Code: 451, Message: "try\nlater"}, nil,
			[]string{"451-4.0.0 try", "451 4.0.0 later"}},
		{"plain data error", nil, errors.New("disk\nfull"),
			[]string{"554-5.0.0 Error: transaction failed: disk", "554 5.0.0 full"}},
		{"coded success", nil, &SMTPError{Code: 250, EnhancedCode: EnhancedCode{2, 6, 0}, Message: "queued\nas 42"},
			[]string{"250-2.6.0 queued", "250 2.6.0 as 42"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, c, br, _ := newFlushTestConn(t, func(s *Server) {
				s.Backend = BackendFunc(func(*Conn) (Session, error) {
					return rfc2034Session{rcpt: tc.rcpt, data: tc.data}, nil
				})
			})
			writeFlushBatch(t, c, "EHLO client.example.org\r\nMAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.org>\r\n")
			readFlushReply(t, br)
			readFlushReply(t, br)
			reply := readFlushReply(t, br)
			if tc.rcpt == nil {
				writeFlushBatch(t, c, "DATA\r\n")
				readFlushReply(t, br)
				writeFlushBatch(t, c, "x\r\n.\r\n")
				reply = readFlushReply(t, br)
			}
			if strings.Join(reply, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("reply = %q, want %q", reply, tc.want)
			}
		})
	}
}

// The client takes the status code from the first line and strips the same
// code from every line, so a host's multiline SMTPError survives a round trip.
//
// checklist: ESC-CLIENT-01
func TestRFC2034ClientRoundTrip(t *testing.T) {
	srvSide, cliSide := net.Pipe()
	s := NewServer(BackendFunc(func(*Conn) (Session, error) {
		return rfc2034Session{rcpt: &SMTPError{Code: 550, EnhancedCode: EnhancedCode{5, 7, 1}, Message: "relay denied\nauthenticate first"}}, nil
	}))
	s.Domain = "localhost"
	go s.handleConn(newConn(srvSide, s))
	t.Cleanup(func() { cliSide.Close(); s.Close() })
	cliSide.SetDeadline(time.Now().Add(5 * time.Second))

	cl := NewClient(cliSide)
	defer cl.Close()
	if err := cl.Mail("a@example.org", nil); err != nil {
		t.Fatal(err)
	}
	var smtpErr *SMTPError
	if err := cl.Rcpt("b@example.org", nil); !errors.As(err, &smtpErr) {
		t.Fatalf("Rcpt error = %v, want *SMTPError", err)
	}
	if smtpErr.Code != 550 || smtpErr.EnhancedCode != (EnhancedCode{5, 7, 1}) || smtpErr.Message != "relay denied\nauthenticate first" {
		t.Fatalf("Rcpt error = %+v", smtpErr)
	}
}
