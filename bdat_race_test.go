package smtp_test

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"

	smtp "github.com/rest-mail/go-smtp"
)

// raceBackend parks Session.Data (the BDAT pipe reader) so the connection
// goroutine blocks inside io.Copy(c.bdatPipe, chunk) with the pipe still
// installed. That is the exact window in which Server.Close() reaches in from
// another goroutine and rewrites c.bdatPipe — the data race in #11.
type raceBackend struct {
	dataEntered chan struct{}
	release     chan struct{}
}

func (b *raceBackend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	return &raceSession{b: b}, nil
}

type raceSession struct{ b *raceBackend }

func (s *raceSession) Mail(string, *smtp.MailOptions) error { return nil }
func (s *raceSession) Rcpt(string, *smtp.RcptOptions) error { return nil }
func (s *raceSession) Data(r io.Reader) error {
	close(s.b.dataEntered) // signal we are in Data...
	<-s.b.release          // ...but do not read the pipe, so the sender blocks.
	return nil
}
func (s *raceSession) Reset()        {}
func (s *raceSession) Logout() error { return nil }

// TestBDATShutdownRace exercises Server.Close() while a BDAT chunk is mid-flight.
// Run with -race: on the unfixed code the connection goroutine's unsynchronised
// read of c.bdatPipe (in handleBdat) races the Close goroutine's write, and the
// race detector fails the test.
func TestBDATShutdownRace(t *testing.T) {
	be := &raceBackend{dataEntered: make(chan struct{}), release: make(chan struct{})}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := smtp.NewServer(be)
	s.Domain = "localhost"
	go s.Serve(l)
	defer s.Close()

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	scanner := bufio.NewScanner(c)

	scanner.Scan() // 220 greeting
	io.WriteString(c, "HELO localhost\r\n")
	scanner.Scan()
	io.WriteString(c, "MAIL FROM:<a@example.com>\r\n")
	scanner.Scan()
	io.WriteString(c, "RCPT TO:<b@example.com>\r\n")
	scanner.Scan()

	// A non-LAST BDAT chunk: handleBdat installs the pipe, spawns the reader
	// (raceSession.Data), then blocks in io.Copy because Data never reads.
	io.WriteString(c, "BDAT 6\r\n")
	io.WriteString(c, "hello!")

	select {
	case <-be.dataEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("Data was never entered; BDAT pipe not established")
	}
	// Give the connection goroutine a moment to reach the io.Copy read.
	time.Sleep(20 * time.Millisecond)

	// Close from this (separate) goroutine while the connection goroutine holds
	// the in-flight BDAT pipe.
	s.Close()

	close(be.release)
}
