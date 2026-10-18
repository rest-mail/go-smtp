package smtp_test

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp"
)

// boundedPipe returns the two ends of an in-memory connection whose directions
// hold at most toServer and toClient unread bytes: past that a Write blocks,
// like a TCP connection whose buffers are full. Deadlines are honoured, so an
// end that is stuck fails with a timeout instead of hanging the test.
func boundedPipe(toServer, toClient int) (client, server net.Conn) {
	c2s := make(chan byte, toServer)
	s2c := make(chan byte, toClient)
	done := make(chan struct{})
	var once sync.Once
	closeBoth := func() { once.Do(func() { close(done) }) }
	client = &boundedConn{r: s2c, w: c2s, done: done, closeBoth: closeBoth}
	server = &boundedConn{r: c2s, w: s2c, done: done, closeBoth: closeBoth}
	return client, server
}

type boundedConn struct {
	r         <-chan byte
	w         chan<- byte
	done      chan struct{}
	closeBoth func()

	mu       sync.Mutex
	rdl, wdl time.Time
}

// expiry returns a channel that fires at deadline d, or nil (never) for none.
func expiry(d time.Time) <-chan time.Time {
	if d.IsZero() {
		return nil
	}
	return time.After(time.Until(d))
}

func (c *boundedConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	dl := c.rdl
	c.mu.Unlock()
	select {
	case b[0] = <-c.r:
	default:
		select {
		case b[0] = <-c.r:
		case <-c.done:
			// Bytes written before the close are still delivered.
			select {
			case b[0] = <-c.r:
			default:
				return 0, io.EOF
			}
		case <-expiry(dl):
			return 0, os.ErrDeadlineExceeded
		}
	}
	n := 1
	for n < len(b) {
		select {
		case b[n] = <-c.r:
			n++
		default:
			return n, nil
		}
	}
	return n, nil
}

func (c *boundedConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	dl := c.wdl
	c.mu.Unlock()
	timeout := expiry(dl)
	for n, x := range b {
		select {
		case <-c.done:
			return n, io.ErrClosedPipe
		default:
		}
		select {
		case c.w <- x:
		case <-c.done:
			return n, io.ErrClosedPipe
		case <-timeout:
			return n, os.ErrDeadlineExceeded
		}
	}
	return len(b), nil
}

func (c *boundedConn) Close() error {
	c.closeBoth()
	return nil
}

func (c *boundedConn) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *boundedConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func (c *boundedConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.rdl, c.wdl = t, t
	c.mu.Unlock()
	return nil
}

func (c *boundedConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rdl = t
	c.mu.Unlock()
	return nil
}

func (c *boundedConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wdl = t
	c.mu.Unlock()
	return nil
}

// serveEager plays an SMTP (or, with lmtp, LMTP) server on conn that answers
// each command as soon as it reads it, never waiting for the client to read
// earlier replies, so a client that stops reading fills the reply direction.
// RCPT of an address containing "reject" gets 550; every reply to RCPT names
// its address. After answering limit MAIL/RCPT/RSET commands (0 = no limit) it
// goes silent, still reading, or with hangup closes the connection.
func serveEager(conn net.Conn, lmtp bool, limit int, hangup bool) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer conn.Close()
		r := bufio.NewReader(conn)
		reply := func(s string) bool {
			_, err := io.WriteString(conn, s+"\r\n")
			return err == nil
		}
		if !reply("220 localhost ESMTP") {
			return
		}
		var accepted []string
		answered := 0
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
			if verb == "MAIL" || verb == "RCPT" || verb == "RSET" {
				if limit > 0 && answered == limit {
					if hangup {
						return
					}
					continue
				}
				answered++
			}
			ok := true
			switch verb {
			case "EHLO", "LHLO":
				ok = reply("250-localhost\r\n250 PIPELINING")
			case "MAIL", "RSET":
				accepted = nil
				ok = reply("250 2.0.0 OK")
			case "RCPT":
				addr := line[strings.Index(line, "<")+1 : strings.Index(line, ">")]
				if strings.Contains(addr, "reject") {
					ok = reply("550 5.1.1 <" + addr + "> rejected")
				} else {
					accepted = append(accepted, addr)
					ok = reply("250 2.1.5 <" + addr + "> OK")
				}
			case "DATA":
				ok = reply("354 go ahead")
				for ok {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if l == ".\r\n" {
						break
					}
				}
				if lmtp {
					for _, addr := range accepted {
						ok = ok && reply("250 2.0.0 <"+addr+"> delivered")
					}
				} else {
					ok = ok && reply("250 2.0.0 queued")
				}
				accepted = nil
			case "QUIT":
				reply("221 bye")
				return
			default:
				ok = reply("500 5.5.1 unknown command")
			}
			if !ok {
				return
			}
		}
	}()
	return done
}

// startEager wires a client to serveEager over a bounded pipe whose command
// direction holds exactly the 4 KiB window RFC 2920 assumes and whose reply
// direction holds 64 bytes, far less than the replies to a large group. The
// connection is closed and the server goroutine reaped at cleanup.
func startEager(t *testing.T, lmtp bool, limit int, hangup bool) net.Conn {
	t.Helper()
	cconn, sconn := boundedPipe(4096, 64)
	done := serveEager(sconn, lmtp, limit, hangup)
	t.Cleanup(func() {
		cconn.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("scripted server did not exit")
		}
	})
	return cconn
}

// testRecipients returns n distinct, longish addresses; every rejectEvery-th
// one contains "reject" so serveEager refuses it.
func testRecipients(prefix string, n, rejectEvery int) []string {
	rcpts := make([]string, n)
	for i := range rcpts {
		kind := "user"
		if rejectEvery > 0 && i%rejectEvery == rejectEvery-1 {
			kind = "reject"
		}
		rcpts[i] = fmt.Sprintf("%s-%s-%04d@pipelining.example.com", prefix, kind, i)
	}
	return rcpts
}

// checkRcptResults asserts errs (Wait's RCPT results, in queue order) match
// rcpts: nil for an accepted one, a 550 naming that very address for a rejected
// one, which proves the results are not shifted.
func checkRcptResults(t *testing.T, errs []error, rcpts []string) {
	t.Helper()
	if len(errs) != len(rcpts) {
		t.Fatalf("got %d RCPT results, want %d", len(errs), len(rcpts))
	}
	for i, rcpt := range rcpts {
		if !strings.Contains(rcpt, "reject") {
			if errs[i] != nil {
				t.Fatalf("RCPT %d (%s): %v, want success", i, rcpt, errs[i])
			}
			continue
		}
		var smtpErr *smtp.SMTPError
		if !errors.As(errs[i], &smtpErr) || smtpErr.Code != 550 || !strings.Contains(smtpErr.Message, rcpt) {
			t.Fatalf("RCPT %d (%s): %v, want its own 550", i, rcpt, errs[i])
		}
	}
}

func acceptedOf(rcpts []string) []string {
	var out []string
	for _, r := range rcpts {
		if !strings.Contains(r, "reject") {
			out = append(out, r)
		}
	}
	return out
}

// TestPipeline_LargeGroupDoesNotDeadlock is the client half of issue #78: a
// group much larger than the buffers, against a server that answers every
// command at once. A client that only reads replies in Wait blocks writing
// once the server, blocked on replies nobody reads, stops reading commands;
// here that shows as a Rcpt failing with its write timeout.
//
// checklist: SMTP-EXT-01
func TestPipeline_LargeGroupDoesNotDeadlock(t *testing.T) {
	c := smtp.NewClient(startEager(t, false, 0, false))
	c.CommandTimeout = 2 * time.Second

	p, err := c.Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	rcpts := testRecipients("big", 600, 7)
	if err := p.Mail("from@example.com", nil); err != nil {
		t.Fatalf("Mail: %v", err)
	}
	for i, rcpt := range rcpts {
		if err := p.Rcpt(rcpt, nil); err != nil {
			t.Fatalf("Rcpt %d of %d: %v (the group deadlocked once the replies filled the buffers)", i, len(rcpts), err)
		}
	}
	errs := p.Wait()
	if len(errs) == 0 || errs[0] != nil {
		t.Fatalf("MAIL result: %v", errs)
	}
	checkRcptResults(t, errs[1:], rcpts)

	w, err := c.Data()
	if err != nil {
		t.Fatalf("Data: %v", err)
	}
	if _, err := io.WriteString(w, "Subject: hi\r\n\r\nbody\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("DATA close: %v", err)
	}
}

// TestPipeline_LMTPSeesOnlyAcceptedRecipients splits large groups at the window
// and checks the recipient set the reads build up: LMTP expects one reply per
// accepted recipient after DATA, so a rejected or stale recipient left in the
// set would show up in (or hang) CloseWithLMTPResponse. The second group reuses
// the Pipeliner after RSET and must not inherit the first group's recipients.
//
// checklist: SMTP-EXT-01
func TestPipeline_LMTPSeesOnlyAcceptedRecipients(t *testing.T) {
	c := smtp.NewClientLMTP(startEager(t, true, 0, false))
	c.CommandTimeout = 2 * time.Second

	p, err := c.Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	for round, n := range []int{400, 3} {
		var queued int
		if round > 0 {
			if err := p.Reset(); err != nil {
				t.Fatalf("round %d Reset: %v", round, err)
			}
			queued++
		}
		if err := p.Mail("from@example.com", nil); err != nil {
			t.Fatalf("round %d Mail: %v", round, err)
		}
		queued++
		rcpts := testRecipients(fmt.Sprintf("round%d", round), n, 3)
		for i, rcpt := range rcpts {
			if err := p.Rcpt(rcpt, nil); err != nil {
				t.Fatalf("round %d Rcpt %d: %v", round, i, err)
			}
		}
		errs := p.Wait()
		if len(errs) < queued {
			t.Fatalf("round %d: %d results, want %d", round, len(errs), queued+len(rcpts))
		}
		for i := 0; i < queued; i++ {
			if errs[i] != nil {
				t.Fatalf("round %d command %d: %v", round, i, errs[i])
			}
		}
		checkRcptResults(t, errs[queued:], rcpts)

		w, err := c.Data()
		if err != nil {
			t.Fatalf("round %d Data: %v", round, err)
		}
		if _, err := io.WriteString(w, "Subject: hi\r\n\r\nbody\r\n"); err != nil {
			t.Fatal(err)
		}
		resp, err := w.CloseWithLMTPResponse()
		if err != nil {
			t.Fatalf("round %d CloseWithLMTPResponse: %v", round, err)
		}
		var got []string
		for rcpt := range resp {
			got = append(got, rcpt)
		}
		sort.Strings(got)
		want := acceptedOf(rcpts)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("round %d LMTP recipients:\n got %v\nwant %v", round, got, want)
		}
	}
}

// TestPipeline_StalledServerTimesOut has the server answer MAIL and four RCPTs
// and then read on without replying. The read at the window must time out
// within one CommandTimeout, refuse every later command without writing it,
// and leave Wait one result per queued command: the answered ones, then the
// timeout.
//
// checklist: SMTP-EXT-01
func TestPipeline_StalledServerTimesOut(t *testing.T) {
	c := smtp.NewClient(startEager(t, false, 5, false))
	c.CommandTimeout = 300 * time.Millisecond

	p, err := c.Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	start := time.Now()
	if err := p.Mail("from@example.com", nil); err != nil {
		t.Fatalf("Mail: %v", err)
	}
	queued, failedAt := 1, -1
	var firstErr error
	for i, rcpt := range testRecipients("stall", 300, 0) {
		err := p.Rcpt(rcpt, nil)
		switch {
		case err == nil && failedAt >= 0:
			t.Fatalf("Rcpt %d succeeded after Rcpt %d failed with %v", i, failedAt, firstErr)
		case err == nil:
			queued++
		case failedAt < 0:
			failedAt, firstErr = i, err
		case err != firstErr:
			t.Fatalf("Rcpt %d: %v, want the sticky %v", i, err, firstErr)
		}
	}
	if failedAt < 0 {
		t.Fatal("no Rcpt reported the stalled server")
	}
	var netErr net.Error
	if !errors.As(firstErr, &netErr) || !netErr.Timeout() {
		t.Fatalf("Rcpt %d: %v, want a timeout", failedAt, firstErr)
	}

	errs := p.Wait()
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("stalled group took %v", elapsed)
	}
	if len(errs) != queued {
		t.Fatalf("Wait returned %d results, want one per queued command (%d)", len(errs), queued)
	}
	for i, err := range errs {
		if i < 5 && err != nil {
			t.Fatalf("command %d: %v, want the server's success", i, err)
		}
		if i >= 5 && (!errors.As(err, &netErr) || !netErr.Timeout()) {
			t.Fatalf("command %d: %v, want a timeout", i, err)
		}
	}
	if err := p.Rcpt("late@example.com", nil); err != firstErr {
		t.Fatalf("Rcpt after Wait: %v, want the sticky %v", err, firstErr)
	}
}

// TestPipeline_ServerHangupMidGroup has the server answer MAIL and 49 RCPTs
// (rejecting some) and then close the connection mid-group. Wait still reports
// those answers in place, every later queued command fails with the
// connection's error rather than a server reply, and no command is queued after
// the failure.
//
// checklist: SMTP-EXT-01
func TestPipeline_ServerHangupMidGroup(t *testing.T) {
	c := smtp.NewClient(startEager(t, false, 50, true))
	c.CommandTimeout = 2 * time.Second

	p, err := c.Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if err := p.Mail("from@example.com", nil); err != nil {
		t.Fatalf("Mail: %v", err)
	}
	rcpts := testRecipients("hangup", 300, 4)
	queued, failed := 1, false
	for i, rcpt := range rcpts {
		if err := p.Rcpt(rcpt, nil); err != nil {
			failed = true
			continue
		}
		if failed {
			t.Fatalf("Rcpt %d succeeded after an earlier Rcpt failed", i)
		}
		queued++
	}
	if !failed {
		t.Fatal("no Rcpt reported the closed connection")
	}

	errs := p.Wait()
	if len(errs) != queued {
		t.Fatalf("Wait returned %d results, want one per queued command (%d)", len(errs), queued)
	}
	if queued < 50 {
		t.Fatalf("only %d commands queued before the failure, want at least the 50 answered", queued)
	}
	if errs[0] != nil {
		t.Fatalf("MAIL: %v", errs[0])
	}
	checkRcptResults(t, errs[1:50], rcpts[:49])
	for i, err := range errs[50:] {
		var smtpErr *smtp.SMTPError
		if err == nil || errors.As(err, &smtpErr) {
			t.Fatalf("command %d after the hangup: %v, want a connection error", 50+i, err)
		}
	}
}
