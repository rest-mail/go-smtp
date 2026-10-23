package server

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/rest-mail/go-smtp/pkg/smtp"
)

type rfc2033Session struct {
	nopSession
	recipients []string
	statuses   []error
	fallback   error
	body       chan string
}

func (s *rfc2033Session) Reset() { s.recipients = nil }
func (s *rfc2033Session) Rcpt(to string, _ *smtp.RcptOptions) error {
	if to == "jones@foo.edu" {
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "No such user here"}
	}
	s.recipients = append(s.recipients, to)
	return nil
}
func (s *rfc2033Session) LMTPData(r io.Reader, status StatusCollector) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.body <- string(b)
	// Complete recipients in reverse order to prove wire order is independent
	// of backend completion order. Duplicate paths receive successive statuses.
	for i := len(s.statuses) - 1; i >= 0; i-- {
		status.SetStatus(s.recipients[i], s.statuses[i])
	}
	return s.fallback
}

// checklist: LMTP-EXT-01 LMTP-EXT-02
// checklist: LMTP-DATA-01 LMTP-DATA-02 LMTP-DATA-03 LMTP-DATA-04 LMTP-EXAMPLE-01 LMTP-BDAT-01 LMTP-BDAT-02 LMTP-BDAT-03
func TestRFC2033RecipientReplies(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		for _, duplicates := range []bool{false, true} {
			t.Run(fmt.Sprintf("BDAT=%v/duplicate=%v", chunked, duplicates), func(t *testing.T) {
				body := make(chan string, 2)
				statuses := []error{nil, &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 2, 2}, Message: "temporarily\nover quota"}}
				paths := []string{"pat@foo.edu", "green@foo.edu"}
				wantCodes := []string{"250", "452"}
				if duplicates {
					paths = append(paths, "pat@foo.edu")
					statuses = append(statuses, &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 2, 0}, Message: "duplicate refused"})
					wantCodes = []string{"550", "452", "250"}
				}
				_, c, br, _ := newFlushTestConn(t, func(s *Server) {
					s.LMTP = true
					s.Backend = BackendFunc(func(*Conn) (Session, error) { return &rfc2033Session{statuses: statuses, body: body}, nil })
				})
				command := func(cmd, want string) {
					t.Helper()
					writeFlushBatch(t, c, cmd+"\r\n")
					got := readFlushReply(t, br)
					if !strings.HasPrefix(got[0], want) {
						t.Fatalf("%s: %q", cmd, got)
					}
				}
				command("LHLO foo.edu", "250")
				command("MAIL FROM:<chris@bar.com>", "250")
				command("RCPT TO:<jones@foo.edu>", "550")
				command("DATA", "503") // A rejected RCPT does not count.
				for _, path := range paths {
					command("RCPT TO:<"+path+">", "250")
				}
				const message = "Blah blah blah...\r\n...etc. etc. etc.\r\n"
				if chunked {
					command(fmt.Sprintf("BDAT %d\r\n%s", len(message), message[:len(message)-2]), "250")
					writeFlushBatch(t, c, "BDAT 0 LAST\r\n")
				} else {
					command("DATA", "354")
					writeFlushBatch(t, c, "Blah blah blah...\r\n....etc. etc. etc.\r\n.\r\n")
				}
				for i, code := range wantCodes {
					reply := readFlushReply(t, br)
					if !strings.HasPrefix(reply[0], code+" ") && !strings.HasPrefix(reply[0], code+"-") {
						t.Fatalf("recipient %d: %q, want %s", i, reply, code)
					}
					if !strings.Contains(reply[0], "<"+paths[i]+">") {
						t.Fatalf("recipient %d: %q", i, reply)
					}
					if code == "452" && len(reply) != 2 {
						t.Fatalf("multiline recipient reply = %q", reply)
					}
				}
				if got := <-body; got != message {
					t.Fatalf("body=%q, want %q", got, message)
				}
				command("NOOP", "250") // No reply for jones, no extra aggregate DATA reply.
				command("DATA", "503") // Transaction was reset.
				command("MAIL FROM:<chris@bar.com>", "250")
				command("DATA", "503") // Previous recipients cannot leak.
			})
		}
	}
}

type rfc2033Fallback struct {
	nopSession
	err error
}

func (s rfc2033Fallback) Data(r io.Reader) error {
	if _, err := io.Copy(io.Discard, r); err != nil {
		return err
	}
	return s.err
}

// checklist: LMTP-DATA-05 LMTP-BDAT-04
func TestRFC2033FallbackAndUnsetStatuses(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		for _, perRecipient := range []bool{false, true} {
			for _, reject := range []bool{false, true} {
				t.Run(fmt.Sprintf("BDAT=%v/LMTPData=%v/reject=%v", chunked, perRecipient, reject), func(t *testing.T) {
					var result error
					code := "250"
					if reject {
						code = "451"
						result = &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "storage unavailable"}
					}
					_, c, br, _ := newFlushTestConn(t, func(s *Server) {
						s.LMTP = true
						s.Backend = BackendFunc(func(*Conn) (Session, error) {
							if perRecipient {
								return &rfc2033Session{body: make(chan string, 1), fallback: result}, nil
							}
							return rfc2033Fallback{err: result}, nil
						})
					})
					command := func(cmd, want string) {
						t.Helper()
						writeFlushBatch(t, c, cmd+"\r\n")
						got := readFlushReply(t, br)
						if !strings.HasPrefix(got[0], want) {
							t.Fatalf("%s: %q", cmd, got)
						}
					}
					command("LHLO foo.edu", "250")
					command("MAIL FROM:<chris@bar.com>", "250")
					command("RCPT TO:<pat@foo.edu>", "250")
					command("RCPT TO:<green@foo.edu>", "250")
					if chunked {
						writeFlushBatch(t, c, "BDAT 0 LAST\r\n")
					} else {
						command("DATA", "354")
						writeFlushBatch(t, c, ".\r\n")
					}
					for i := 0; i < 2; i++ {
						if got := readFlushReply(t, br); !strings.HasPrefix(got[0], code+" ") {
							t.Fatalf("reply=%q, want %s", got, code)
						}
					}
					command("NOOP", "250")
				})
			}
		}
	}
}

// checklist: LMTP-DEFAULT-01
func TestRFC2033DefaultNetwork(t *testing.T) {
	s := New(nopBackend{})
	s.LMTP = true
	if got := s.network(); got != "unix" {
		t.Fatalf("default network=%s", got)
	}
}
