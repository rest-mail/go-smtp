package server

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp/pkg/smtp/client"
)

// RFC 5321 §4.1.1.10 and §3.8: the client does not close the channel before
// it has sent QUIT, and waits for the reply before closing.
//
// checklist: SMTP-CLI-10
func TestRFC5321_ClientQuitWaitsForReply(t *testing.T) {
	cconn, sconn := net.Pipe()
	defer sconn.Close()
	c := client.New(cconn)
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
