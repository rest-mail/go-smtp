package smtp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type lmtpFailureSession struct {
	nopSession
	reject bool
	calls  chan string
}

func (s lmtpFailureSession) Rcpt(to string, _ *RcptOptions) error {
	if to == "refused@example.org" {
		return &SMTPError{Code: 550, EnhancedCode: EnhancedCode{5, 1, 1}, Message: "unknown"}
	}
	return nil
}
func (s lmtpFailureSession) Data(r io.Reader) error {
	s.calls <- "data"
	if s.reject {
		return &SMTPError{Code: 452, EnhancedCode: EnhancedCode{4, 2, 2}, Message: "full"}
	}
	_, err := io.Copy(io.Discard, r)
	return err
}

func lmtpFailureEnvelope(t *testing.T, c net.Conn, br *bufio.Reader, recipients []string) {
	t.Helper()
	writeFlushBatch(t, c, "LHLO client.example.org\r\nMAIL FROM:<a@example.org>\r\n")
	for i := 0; i < 2; i++ {
		if r := readFlushReply(t, br); !strings.HasPrefix(r[0], "250") {
			t.Fatal(r)
		}
	}
	for _, to := range recipients {
		writeFlushBatch(t, c, "RCPT TO:<"+to+">\r\n")
		code := "250"
		if to == "refused@example.org" {
			code = "550"
		}
		if r := readFlushReply(t, br); !strings.HasPrefix(r[0], code) {
			t.Fatal(r)
		}
	}
}

// A following NOOP is a wire sentinel: any extra LAST reply is observed before
// it, without a sleep or a read timeout being used as evidence of no reply.
// checklist: LMTP-BDAT-05
func TestRFC2033LastWithoutRecipients(t *testing.T) {
	for _, lmtp := range []bool{true, false} {
		for _, state := range []string{"no mail", "no rcpt", "all refused", "after reset", "after last"} {
			for _, body := range []string{"", "NOOP\r\n"} {
				t.Run(fmt.Sprintf("lmtp=%v/%s/body=%d", lmtp, state, len(body)), func(t *testing.T) {
					calls := make(chan string, 2)
					_, c, br, _ := newFlushTestConn(t, func(s *Server) {
						s.LMTP = lmtp
						s.Backend = BackendFunc(func(*Conn) (Session, error) { return lmtpFailureSession{calls: calls}, nil })
					})
					hello := "LHLO"
					if !lmtp {
						hello = "EHLO"
					}
					writeFlushBatch(t, c, hello+" client.example.org\r\n")
					readFlushReply(t, br)
					command := func(cmd, code string) {
						t.Helper()
						writeFlushBatch(t, c, cmd+"\r\n")
						if r := readFlushReply(t, br); !strings.HasPrefix(r[0], code) {
							t.Fatalf("%s: %q", cmd, r)
						}
					}
					if state != "no mail" {
						command("MAIL FROM:<a@example.org>", "250")
					}
					switch state {
					case "all refused":
						command("RCPT TO:<refused@example.org>", "550")
					case "after reset":
						command("RCPT TO:<b@example.org>", "250")
						command("RSET", "250")
					case "after last":
						command("RCPT TO:<b@example.org>", "250")
						command("BDAT 0 LAST", "250")
						if got := <-calls; got != "data" {
							t.Fatal(got)
						}
					}
					writeFlushBatch(t, c, fmt.Sprintf("BDAT %d LAST\r\n%sNOOP\r\n", len(body), body))
					if !lmtp {
						if r := readFlushReply(t, br); !strings.HasPrefix(r[0], "503 ") {
							t.Fatal(r)
						}
					}
					if r := readFlushReply(t, br); len(r) != 1 || r[0] != "250 2.0.0 I have successfully done nothing" {
						t.Fatalf("expected only following NOOP, got %q", r)
					}
					if len(calls) != 0 {
						t.Fatal("empty recipient set reached backend")
					}
					// LAST ends even an empty transaction; MAIL can start a fresh one.
					if !lmtp {
						command("RSET", "250")
					}
					command("BDAT 0", "503") // non-LAST keeps exactly one reply
					command("MAIL FROM:<next@example.org>", "250")
				})
			}
		}
	}
}

// checklist: LMTP-BDAT-06
func TestRFC2033LastSizeFailureReplies(t *testing.T) {
	for _, split := range []bool{false, true} {
		t.Run(fmt.Sprint(split), func(t *testing.T) {
			calls := make(chan string, 2)
			_, c, br, _ := newFlushTestConn(t, func(s *Server) {
				s.LMTP = true
				s.MaxMessageBytes = 3
				s.Backend = BackendFunc(func(*Conn) (Session, error) { return lmtpFailureSession{calls: calls}, nil })
			})
			paths := []string{"b@example.org", "refused@example.org", "c@example.org", "b@example.org"}
			lmtpFailureEnvelope(t, c, br, paths)
			if split {
				writeFlushBatch(t, c, "BDAT 2\r\nab")
				if r := readFlushReply(t, br); !strings.HasPrefix(r[0], "250 ") {
					t.Fatal(r)
				}
			}
			body := "NOOP\r\n" // Must be drained as opaque data, never dispatched.
			writeFlushBatch(t, c, fmt.Sprintf("BDAT %d LAST\r\n%sNOOP\r\n", len(body), body))
			for _, to := range []string{paths[0], paths[2], paths[3]} {
				if r := readFlushReply(t, br); len(r) != 1 || r[0] != "552 5.3.4 <"+to+"> Max message size exceeded" {
					t.Fatalf("recipient %s: %q", to, r)
				}
			}
			if r := readFlushReply(t, br); r[0] != "250 2.0.0 I have successfully done nothing" {
				t.Fatalf("following NOOP: %q", r)
			}
			writeFlushBatch(t, c, "MAIL FROM:<next@example.org>\r\n")
			if r := readFlushReply(t, br); !strings.HasPrefix(r[0], "250 ") {
				t.Fatal(r)
			}
			if !split && len(calls) != 0 {
				t.Fatal("oversize first chunk reached backend")
			}
		})
	}
}

type lmtpEarlyStatusSession struct{ lmtpFailureSession }

func (s lmtpEarlyStatusSession) LMTPData(_ io.Reader, status StatusCollector) error {
	s.calls <- "data"
	// Duplicate b gets two independent outcomes, despite early refusal of
	// the remaining chunk. Returning the fallback must not flatten these.
	status.SetStatus("b@example.org", nil)
	status.SetStatus("c@example.org", &SMTPError{Code: 550, EnhancedCode: EnhancedCode{5, 2, 0}, Message: "disabled"})
	return &SMTPError{Code: 452, EnhancedCode: EnhancedCode{4, 2, 2}, Message: "full"}
}

// checklist: LMTP-BDAT-07
func TestRFC2033LastEarlyBackendFailureReplies(t *testing.T) {
	for _, perRecipient := range []bool{false, true} {
		t.Run(fmt.Sprint(perRecipient), func(t *testing.T) {
			calls := make(chan string, 1)
			session := lmtpFailureSession{reject: true, calls: calls}
			_, c, br, _ := newFlushTestConn(t, func(s *Server) {
				s.LMTP = true
				s.Backend = BackendFunc(func(*Conn) (Session, error) {
					if perRecipient {
						return lmtpEarlyStatusSession{session}, nil
					}
					return session, nil
				})
			})
			paths := []string{"b@example.org", "refused@example.org", "c@example.org", "b@example.org"}
			lmtpFailureEnvelope(t, c, br, paths)
			body := strings.Repeat("x", 128) + "NOOP\r\n"
			writeFlushBatch(t, c, fmt.Sprintf("BDAT %d LAST\r\n", len(body)))
			select {
			case <-calls:
			case <-time.After(5 * time.Second):
				t.Fatal("backend did not start before chunk bytes")
			}
			writeFlushBatch(t, c, body+"NOOP\r\n")
			want := []string{"452 4.2.2 <b@example.org> full", "452 4.2.2 <c@example.org> full", "452 4.2.2 <b@example.org> full"}
			if perRecipient {
				want[0] = "250 2.0.0 <b@example.org> OK: queued"
				want[1] = "550 5.2.0 <c@example.org> disabled"
			}
			for _, expected := range want {
				if r := readFlushReply(t, br); len(r) != 1 || r[0] != expected {
					t.Fatalf("got %q, want %q", r, expected)
				}
			}
			if r := readFlushReply(t, br); r[0] != "250 2.0.0 I have successfully done nothing" {
				t.Fatalf("following NOOP: %q", r)
			}
			writeFlushBatch(t, c, "MAIL FROM:<next@example.org>\r\n")
			if r := readFlushReply(t, br); !strings.HasPrefix(r[0], "250 ") {
				t.Fatal(r)
			}
		})
	}
}

// checklist: LMTP-BDAT-08
func TestRFC2033LastShortReadReplies(t *testing.T) {
	// TCP half-close supplies a real EOF while retaining the reply direction.
	// A fully lost connection cannot guarantee delivery of any status to a peer.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	calls := make(chan string, 1)
	s := NewServer(BackendFunc(func(*Conn) (Session, error) { return lmtpFailureSession{calls: calls}, nil }))
	s.LMTP = true
	s.Domain = "localhost"
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	t.Cleanup(func() {
		s.Close()
		if err := <-done; err != nil && err != ErrServerClosed {
			t.Error(err)
		}
	})
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(raw)
	readFlushReply(t, br)
	paths := []string{"b@example.org", "c@example.org", "b@example.org"}
	lmtpFailureEnvelope(t, raw, br, paths)
	writeFlushBatch(t, raw, "BDAT 100 LAST\r\nshort")
	if err := raw.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	for _, to := range paths {
		if r := readFlushReply(t, br); len(r) != 1 || r[0] != "451 4.4.2 <"+to+"> Connection error during chunk transfer" {
			t.Fatalf("recipient %s: %q", to, r)
		}
	}
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("after replies: %v, want closed connection", err)
	}
}

type lmtpEarlyTerminalSession struct {
	lmtpFailureSession
	panicNow bool
}

func (s lmtpEarlyTerminalSession) LMTPData(_ io.Reader, status StatusCollector) error {
	s.calls <- "data"
	status.SetStatus("b@example.org", nil)
	if s.panicNow {
		panic("private backend panic detail")
	}
	return CloseConnection(&SMTPError{Code: 451, EnhancedCode: EnhancedCode{4, 3, 0}, Message: "storage unavailable"})
}

// checklist: LMTP-BDAT-07
func TestRFC2033LastEarlyTerminalReplies(t *testing.T) {
	for _, panicNow := range []bool{false, true} {
		t.Run(fmt.Sprint(panicNow), func(t *testing.T) {
			calls := make(chan string, 1)
			_, c, br, _ := newFlushTestConn(t, func(s *Server) {
				s.LMTP = true
				s.Backend = BackendFunc(func(*Conn) (Session, error) {
					return lmtpEarlyTerminalSession{lmtpFailureSession{calls: calls}, panicNow}, nil
				})
			})
			lmtpFailureEnvelope(t, c, br, []string{"b@example.org", "c@example.org", "b@example.org"})
			writeFlushBatch(t, c, "BDAT 3 LAST\r\n")
			select {
			case <-calls:
			case <-time.After(5 * time.Second):
				t.Fatal("backend did not start before chunk bytes")
			}
			writeFlushBatch(t, c, "abc")
			if r := readFlushReply(t, br); len(r) != 1 || r[0] != "250 2.0.0 <b@example.org> OK: queued" {
				t.Fatal(r)
			}
			code, message := "451 4.3.0 ", "storage unavailable"
			if panicNow {
				code, message = "421 4.0.0 ", "Internal server error"
			}
			for _, to := range []string{"c@example.org", "b@example.org"} {
				if r := readFlushReply(t, br); len(r) != 1 || r[0] != code+"<"+to+"> "+message {
					t.Fatal(r)
				}
			}
			if _, err := br.ReadByte(); err != io.EOF {
				t.Fatalf("after terminal results: %v", err)
			}
		})
	}
}
