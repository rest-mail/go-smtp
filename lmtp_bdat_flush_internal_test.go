package smtp

import (
	"fmt"
	"io"
	"reflect"
	"testing"
)

// Each gate is opened only after the preceding recipient's complete wire reply
// has arrived. Holding LMTP replies until the backend returns therefore cannot
// pass, even if all the replies would eventually be correct.
type bdatFlushSession struct {
	nopSession
	advance [3]chan struct{}
	body    chan string
	finish  string
}

func (s *bdatFlushSession) LMTPData(r io.Reader, status StatusCollector) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.body <- string(b)
	status.SetStatus("fast@example.org", nil)
	<-s.advance[0]
	status.SetStatus("slow@example.org", &SMTPError{
		Code: 452, EnhancedCode: EnhancedCode{4, 2, 2}, Message: "temporarily\nover quota",
	})
	<-s.advance[1]
	switch s.finish {
	case "explicit":
		// The third RCPT repeats the first address, but gets its own status.
		status.SetStatus("fast@example.org", &SMTPError{
			Code: 550, EnhancedCode: EnhancedCode{5, 2, 0}, Message: "duplicate refused",
		})
		<-s.advance[2]
	case "error":
		return &SMTPError{Code: 451, EnhancedCode: EnhancedCode{4, 3, 0}, Message: "storage unavailable"}
	case "panic":
		panic("delivery failed")
	}
	return nil
}

// checklist: LMTP-FLUSH-02 LMTP-BDAT-01 LMTP-BDAT-02 LMTP-BDAT-04
func TestRFC2033BDATRecipientRepliesFlushed(t *testing.T) {
	for _, lastSize := range []int{0, 3} {
		for _, finish := range []string{"explicit", "success", "error", "panic"} {
			t.Run(fmt.Sprintf("LAST=%d/%s", lastSize, finish), func(t *testing.T) {
				session := &bdatFlushSession{body: make(chan string, 1), finish: finish}
				for i := range session.advance {
					session.advance[i] = make(chan struct{}, 1)
				}
				_, c, br, done := newFlushTestConn(t, func(s *Server) {
					s.LMTP = true
					s.Backend = BackendFunc(func(*Conn) (Session, error) { return session, nil })
				})
				// Release a blocked backend even if a bounded read fails.
				t.Cleanup(func() {
					for _, gate := range session.advance {
						close(gate)
					}
				})
				command := func(wire string, want []string) {
					t.Helper()
					writeFlushBatch(t, c, wire)
					if got := readFlushReply(t, br); !reflect.DeepEqual(got, want) {
						t.Fatalf("%q: reply = %q, want %q", wire, got, want)
					}
				}
				writeFlushBatch(t, c, "LHLO localhost\r\n")
				readFlushReply(t, br)
				command("MAIL FROM:<sender@example.org>\r\n", []string{"250 2.0.0 Roger, accepting mail from <sender@example.org>"})
				for _, rcpt := range []string{"fast@example.org", "slow@example.org", "fast@example.org"} {
					command("RCPT TO:<"+rcpt+">\r\n", []string{"250 2.0.0 I'll make sure <" + rcpt + "> gets this"})
				}
				command("BDAT 3\r\nold", []string{"250 2.0.0 Continue"})
				payload := ""
				if lastSize != 0 {
					payload = "new"
				}
				command(fmt.Sprintf("BDAT %d LAST\r\n%s", lastSize, payload), []string{"250 2.0.0 <fast@example.org> OK: queued"})
				if got := <-session.body; got != "old"+payload {
					t.Fatalf("body = %q, want %q", got, "old"+payload)
				}
				session.advance[0] <- struct{}{}
				if got, want := readFlushReply(t, br), []string{
					"452-<slow@example.org> temporarily", "452 4.2.2 over quota",
				}; !reflect.DeepEqual(got, want) {
					t.Fatalf("second recipient = %q, want %q", got, want)
				}
				session.advance[1] <- struct{}{}
				want := "250 2.0.0 <fast@example.org> OK: queued"
				switch finish {
				case "explicit":
					want = "550 5.2.0 <fast@example.org> duplicate refused"
				case "error":
					want = "451 4.3.0 <fast@example.org> storage unavailable"
				case "panic":
					want = "421 4.0.0 <fast@example.org> Internal server error"
				}
				if got := readFlushReply(t, br); !reflect.DeepEqual(got, []string{want}) {
					t.Fatalf("third recipient = %q, want %q", got, want)
				}
				session.advance[2] <- struct{}{}
				if finish != "panic" {
					// There must be no aggregate/extra reply, and the old envelope
					// must be cleared before the next command runs.
					command("NOOP\r\n", []string{"250 2.0.0 I have successfully done nothing"})
					command("DATA\r\n", []string{"503 5.5.1 Missing RCPT TO command."})
					command("QUIT\r\n", []string{"221 2.0.0 Bye"})
				} else if _, err := br.ReadByte(); err != io.EOF {
					t.Fatalf("panic left connection open: %v", err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
