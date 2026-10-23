package client

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// checklist: SMTP-LIM-09 SMTP-LIM-10
func TestRFC5321DataWriteDeadlinePerBuffer(t *testing.T) {
	for _, lmtp := range []bool{false, true} {
		for _, body := range []string{"", "small\r\n", strings.Repeat(".dot\r\n", 4000)} {
			t.Run(fmt.Sprintf("LMTP=%v/bytes=%d", lmtp, len(body)), func(t *testing.T) {
				conn := &dataDeadlineConn{replies: strings.NewReader("220 peer.example\r\n250 peer.example\r\n250 sender\r\n250 recipient\r\n354 content\r\n250 queued\r\n250 noop\r\n")}
				c := New(conn)
				c.lmtp = lmtp
				if c.DataTransferTimeout != 3*time.Minute {
					t.Fatalf("default DATA timeout: %v", c.DataTransferTimeout)
				}
				c.DataTransferTimeout = 7 * time.Minute
				c.SubmissionTimeout = 11 * time.Minute
				if err := c.Mail("a@example.org", nil); err != nil {
					t.Fatal(err)
				}
				if err := c.Rcpt("b@example.org", nil); err != nil {
					t.Fatal(err)
				}
				cmd, err := c.Data()
				if err != nil {
					t.Fatal(err)
				}
				start := conn.wire.Len()
				conn.wantTimeout = c.DataTransferTimeout
				if _, err := io.WriteString(cmd, body); err != nil {
					t.Fatal(err)
				}
				if err := cmd.Close(); err != nil {
					t.Fatal(err)
				}
				if conn.bodyWrites < 1 || (len(body) > 4096 && conn.bodyWrites < 3) {
					t.Fatalf("did not exercise network buffers: %d", conn.bodyWrites)
				}
				want := strings.ReplaceAll(body, ".dot", "..dot") + ".\r\n"
				if got := conn.wire.String()[start:]; got != want {
					t.Fatal("DATA framing changed")
				}
				if remaining := time.Until(conn.lastResponseDeadline); remaining <= 10*time.Minute || remaining > c.SubmissionTimeout {
					t.Fatalf("final response did not get its independent timeout: %v", remaining)
				}
				if !conn.deadline.IsZero() || c.writingData {
					t.Fatal("DATA deadline or mode leaked")
				}
				conn.wantTimeout = c.CommandTimeout
				if err := c.Noop(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// checklist: SMTP-LIM-09
func TestRFC5321DataWriteStallTimeout(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	c := New(local)
	c.DataTransferTimeout = 30 * time.Millisecond
	cmd := &DataCommand{client: c}
	done := make(chan error, 1)
	go func() { _, err := io.WriteString(cmd, strings.Repeat("body\r\n", 4000)); done <- err }()
	select {
	case err := <-done:
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("Write = %v, want timeout", err)
		}
		if cmd.Close() != err {
			t.Fatal("Close did not preserve failed body write")
		}
		if c.writingData {
			t.Fatal("DATA mode leaked after failed Write")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DATA Write stalled without a deadline")
	}
}

// checklist: SMTP-LIM-09 SMTP-LIM-10
func TestRFC5321DataWriteDeadlineErrorsAndDisabled(t *testing.T) {
	for _, stage := range []string{"deadline", "write", "disabled", "negative"} {
		t.Run(stage, func(t *testing.T) {
			sentinel := errors.New("injected " + stage)
			conn := &dataDeadlineConn{replies: strings.NewReader("")}
			c := New(conn)
			switch stage {
			case "deadline":
				conn.deadlineErr = sentinel
			case "write":
				conn.writeErr = sentinel
			case "disabled":
				c.DataTransferTimeout = 0
				conn.deadlineErr = sentinel
			case "negative":
				c.DataTransferTimeout = -1
				conn.deadlineErr = sentinel
			}
			cmd := &DataCommand{client: c}
			_, err := io.WriteString(cmd, strings.Repeat("body\r\n", 4000))
			if stage == "disabled" || stage == "negative" {
				if err != nil {
					t.Fatal(err)
				}
				if err := cmd.close(); err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, sentinel) {
				t.Fatalf("Write = %v, want injected error", err)
			}
			before := conn.wire.Len()
			if _, err := cmd.Write([]byte("retry")); err != sentinel {
				t.Fatal("Write lost original error")
			}
			if err := cmd.close(); err != sentinel {
				t.Fatal("Close lost original error")
			}
			if conn.wire.Len() != before || c.writingData {
				t.Fatal("failed body was retried or mode leaked")
			}
			if stage == "write" && !conn.deadline.IsZero() {
				t.Fatal("deadline leaked on failed Write")
			}
		})
	}
}

// dataDeadlineConn makes every successful write expire its deadline. The next
// network buffer must receive a new deadline, even within one caller Write.
type dataDeadlineConn struct {
	net.Conn
	replies              io.Reader
	wire                 bytes.Buffer
	deadline             time.Time
	lastResponseDeadline time.Time
	wantTimeout          time.Duration
	bodyWrites           int
	deadlineErr          error
	writeErr             error
}

func (c *dataDeadlineConn) Read(b []byte) (int, error) { return c.replies.Read(b) }

func (c *dataDeadlineConn) Close() error { return nil }

func (c *dataDeadlineConn) SetDeadline(d time.Time) error {
	c.deadline = d
	if !d.IsZero() {
		c.lastResponseDeadline = d
	}
	return nil
}

func (c *dataDeadlineConn) SetWriteDeadline(d time.Time) error {
	if c.deadlineErr != nil {
		return c.deadlineErr
	}
	c.deadline = d
	return nil
}

func (c *dataDeadlineConn) Write(b []byte) (int, error) {
	if c.wantTimeout > 0 {
		remaining := time.Until(c.deadline)
		if remaining <= 0 || remaining > c.wantTimeout {
			return 0, errors.New("missing fresh DATA write deadline")
		}
		c.bodyWrites++
	}
	if c.writeErr != nil {
		n, _ := c.wire.Write(b[:len(b)/2])
		return n, c.writeErr
	}
	n, err := c.wire.Write(b)
	c.deadline = time.Unix(1, 0)
	return n, err
}
