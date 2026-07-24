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

// mustReadLine reads a single CRLF-terminated line from the scripted server
// side of a net.Pipe, failing the test on error (including a deadline, which
// indicates the client did not send the expected command).
func mustReadLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

// TestPipeline_NoRoundTripDeadlock proves the client actually pipelines: the
// scripted server reads MAIL and both RCPTs BEFORE sending any response. A
// synchronous client (one that waits for each reply before sending the next
// command) would block forever here, since it would wait for MAIL's reply while
// the server is still waiting to read RCPT. The pipelined client sends the whole
// group, then reads the replies.
func TestPipeline_NoRoundTripDeadlock(t *testing.T) {
	cconn, sconn := net.Pipe()
	defer cconn.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer sconn.Close()
		sconn.SetDeadline(time.Now().Add(10 * time.Second))
		br := bufio.NewReader(sconn)

		io.WriteString(sconn, "220 localhost ESMTP\r\n")
		if got := mustReadLine(t, br); !strings.HasPrefix(got, "EHLO") {
			t.Errorf("expected EHLO, got %q", got)
		}
		io.WriteString(sconn, "250-localhost\r\n250 PIPELINING\r\n")

		// Read the entire pipelined group before replying to any of it.
		if got := mustReadLine(t, br); got != "MAIL FROM:<from@example.com>" {
			t.Errorf("MAIL line = %q", got)
		}
		if got := mustReadLine(t, br); got != "RCPT TO:<a@example.com>" {
			t.Errorf("RCPT a line = %q", got)
		}
		if got := mustReadLine(t, br); got != "RCPT TO:<b@example.com>" {
			t.Errorf("RCPT b line = %q", got)
		}

		// Now send the three replies together: MAIL ok, RCPT a ok, RCPT b rejected.
		io.WriteString(sconn, "250 2.1.0 Sender ok\r\n250 2.1.5 Recipient ok\r\n550 5.1.1 No such user\r\n")
	}()

	cl := smtp.NewClient(cconn)
	cl.CommandTimeout = 5 * time.Second // fail fast if a regression deadlocks

	p, err := cl.Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if err := p.Mail("from@example.com", nil); err != nil {
		t.Fatalf("queue MAIL: %v", err)
	}
	if err := p.Rcpt("a@example.com", nil); err != nil {
		t.Fatalf("queue RCPT a: %v", err)
	}
	if err := p.Rcpt("b@example.com", nil); err != nil {
		t.Fatalf("queue RCPT b: %v", err)
	}

	errs := p.Wait()
	if len(errs) != 3 {
		t.Fatalf("Wait returned %d results, want 3", len(errs))
	}
	if errs[0] != nil {
		t.Errorf("MAIL result = %v, want nil", errs[0])
	}
	if errs[1] != nil {
		t.Errorf("RCPT a result = %v, want nil", errs[1])
	}
	var smtpErr *smtp.SMTPError
	if !errors.As(errs[2], &smtpErr) || smtpErr.Code != 550 {
		t.Errorf("RCPT b result = %v, want 550 SMTPError", errs[2])
	}

	<-serverDone
}

// TestPipeline_Integration drives a pipelined MAIL + two RCPT against a real
// server, then sends the message and confirms it was delivered to both
// recipients — exercising the recipient tracking that Wait performs.
func TestPipeline_Integration(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	be := new(backend)
	s := smtp.NewServer(be)
	s.Domain = "localhost"
	s.AllowInsecureAuth = true
	go s.Serve(l)
	defer s.Close()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cl := smtp.NewClient(conn)
	defer cl.Close()

	p, err := cl.Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if err := p.Mail("from@example.com", nil); err != nil {
		t.Fatal(err)
	}
	if err := p.Rcpt("a@example.com", nil); err != nil {
		t.Fatal(err)
	}
	if err := p.Rcpt("b@example.com", nil); err != nil {
		t.Fatal(err)
	}
	for i, e := range p.Wait() {
		if e != nil {
			t.Fatalf("pipelined command %d failed: %v", i, e)
		}
	}

	w, err := cl.Data()
	if err != nil {
		t.Fatalf("Data: %v", err)
	}
	if _, err := io.WriteString(w, "Subject: hi\r\n\r\nbody\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Data close: %v", err)
	}
	if err := cl.Quit(); err != nil {
		t.Fatalf("Quit: %v", err)
	}

	if len(be.anonmsgs) != 1 {
		t.Fatalf("delivered %d messages, want 1", len(be.anonmsgs))
	}
	if got := be.anonmsgs[0].To; len(got) != 2 || got[0] != "a@example.com" || got[1] != "b@example.com" {
		t.Fatalf("recipients = %v, want [a@example.com b@example.com]", got)
	}
}

// TestPipeline_Reset pipelines RSET + MAIL + RCPT and confirms the RSET clears
// any prior recipient state so the new transaction's recipient is the only one.
func TestPipeline_Reset(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	be := new(backend)
	s := smtp.NewServer(be)
	s.Domain = "localhost"
	s.AllowInsecureAuth = true
	go s.Serve(l)
	defer s.Close()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cl := smtp.NewClient(conn)
	defer cl.Close()

	// A stray recipient from an earlier (aborted) attempt.
	if err := cl.Mail("old@example.com", nil); err != nil {
		t.Fatal(err)
	}
	if err := cl.Rcpt("stray@example.com", nil); err != nil {
		t.Fatal(err)
	}

	p, err := cl.Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if err := p.Reset(); err != nil {
		t.Fatal(err)
	}
	if err := p.Mail("from@example.com", nil); err != nil {
		t.Fatal(err)
	}
	if err := p.Rcpt("real@example.com", nil); err != nil {
		t.Fatal(err)
	}
	for i, e := range p.Wait() {
		if e != nil {
			t.Fatalf("pipelined command %d failed: %v", i, e)
		}
	}

	w, err := cl.Data()
	if err != nil {
		t.Fatalf("Data: %v", err)
	}
	io.WriteString(w, "Subject: hi\r\n\r\nbody\r\n")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	cl.Quit()

	if len(be.anonmsgs) != 1 {
		t.Fatalf("delivered %d messages, want 1", len(be.anonmsgs))
	}
	if got := be.anonmsgs[0].To; len(got) != 1 || got[0] != "real@example.com" {
		t.Fatalf("recipients = %v, want [real@example.com] (RSET should have cleared stray)", got)
	}
}

// TestPipeline_NotSupported: Pipeline returns an error when the server does not
// advertise PIPELINING, so callers can fall back to the synchronous API.
func TestPipeline_NotSupported(t *testing.T) {
	cconn, sconn := net.Pipe()
	defer cconn.Close()

	go func() {
		defer sconn.Close()
		sconn.SetDeadline(time.Now().Add(10 * time.Second))
		br := bufio.NewReader(sconn)
		io.WriteString(sconn, "220 localhost ESMTP\r\n")
		mustReadLine(t, br) // EHLO
		io.WriteString(sconn, "250 SIZE 100\r\n")
		mustReadLine(t, br) // QUIT (from cl.Quit below)
		io.WriteString(sconn, "221 bye\r\n")
	}()

	cl := smtp.NewClient(cconn)
	cl.CommandTimeout = 5 * time.Second

	if _, err := cl.Pipeline(); err == nil {
		t.Fatal("Pipeline should error when PIPELINING is not advertised")
	}
	cl.Quit()
}
