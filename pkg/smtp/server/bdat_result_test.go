package server

import (
	"io"
	"strings"
	"testing"
	"time"
)

type bdatResultSession struct {
	nopSession
	conn         *Conn
	started      chan chan error
	release      chan struct{}
	panicOnReset bool
}

func (s *bdatResultSession) Data(r io.Reader) error {
	s.started <- s.conn.dataResult
	_, err := io.Copy(io.Discard, r)
	if err == ErrDataReset {
		<-s.release
		if s.panicOnReset {
			panic("aborted BDAT backend")
		}
	}
	return err
}

// A reset may finish before the old backend returns. Its result must stay on
// its original channel, even after the next transaction has started.
// checklist: CHUNK-STATE-02
func TestBDATResultAfterReset(t *testing.T) {
	for _, panicOnReset := range []bool{false, true} {
		name := "return"
		if panicOnReset {
			name = "panic"
		}
		t.Run(name, func(t *testing.T) {
			session := &bdatResultSession{
				started: make(chan chan error, 2), release: make(chan struct{}),
				panicOnReset: panicOnReset,
			}
			defer close(session.release)
			_, c, br, _ := newFlushTestConn(t, func(s *Server) {
				s.Backend = BackendFunc(func(c *Conn) (Session, error) {
					session.conn = c
					return session, nil
				})
			})
			command := func(wire, code string) {
				t.Helper()
				writeFlushBatch(t, c, wire+"\r\n")
				lines := readFlushReply(t, br)
				if got := lines[len(lines)-1]; !strings.HasPrefix(got, code+" ") {
					t.Fatalf("%s: %s", wire, got)
				}
			}
			command("EHLO localhost", "250")
			command("MAIL FROM:<a@example.org>", "250")
			command("RCPT TO:<b@example.org>", "250")
			command("BDAT 0", "250")
			original := <-session.started
			command("RSET", "250")
			command("MAIL FROM:<a@example.org>", "250")
			command("RCPT TO:<b@example.org>", "250")
			command("BDAT 0", "250")
			<-session.started
			session.release <- struct{}{}
			want := error(ErrDataReset)
			if panicOnReset {
				want = errPanic
			}
			select {
			case err := <-original:
				if err != want {
					t.Fatalf("old result = %v, want %v", err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("old backend result was sent to the next transaction")
			}
			command("BDAT 0 LAST", "250")
		})
	}
}
