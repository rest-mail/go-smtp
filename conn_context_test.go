package smtp_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	smtp "github.com/rest-mail/go-smtp"
)

type ctxBackend struct {
	ch chan context.Context
}

func (b *ctxBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	b.ch <- c.Context()
	return ctxSession{}, nil
}

type ctxSession struct{}

func (ctxSession) Mail(string, *smtp.MailOptions) error { return nil }
func (ctxSession) Rcpt(string, *smtp.RcptOptions) error { return nil }
func (ctxSession) Data(io.Reader) error                 { return nil }
func (ctxSession) Reset()                               {}
func (ctxSession) Logout() error                        { return nil }

// TestConnContextCancelledOnShutdown verifies Conn.Context() is a live context
// that is cancelled when the server is closed, so a backend can observe shutdown.
func TestConnContextCancelledOnShutdown(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	be := &ctxBackend{ch: make(chan context.Context, 1)}
	s := smtp.NewServer(be)
	s.Domain = "localhost"
	go s.Serve(l)
	defer s.Close()

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// EHLO triggers NewSession, which captures the connection's context.
	buf := make([]byte, 256)
	c.Read(buf) // greeting
	io.WriteString(c, "EHLO localhost\r\n")

	var ctx context.Context
	select {
	case ctx = <-be.ch:
	case <-time.After(3 * time.Second):
		t.Fatal("NewSession was not called")
	}
	if ctx.Err() != nil {
		t.Fatalf("connection context already cancelled: %v", ctx.Err())
	}

	s.Close() // shutting the server down must cancel the connection context

	select {
	case <-ctx.Done():
		// expected
	case <-time.After(3 * time.Second):
		t.Fatal("connection context was not cancelled on server shutdown")
	}
}
