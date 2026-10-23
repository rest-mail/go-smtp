package client

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp/pkg/smtp/server"
)

// checklist: TLS-CLIENT-01 TLS-CLIENT-02 TLS-STATE-02 TLS-STATE-03 TLS-STATE-04 TLS-EXAMPLE-01
func TestRFC3207ClientUpgrade(t *testing.T) {
	_, raw, _, _ := newFlushTestConn(t, func(s *server.Server) {
		s.TLSConfig = rfc3207TLSConfig(t)
	})
	// newFlushTestConn already consumed the server's greeting.
	c := New(raw)
	c.didGreet = true
	if ok, value := c.Extension("STARTTLS"); !ok || value != "" {
		t.Fatalf("STARTTLS advertisement = %v, %q", ok, value)
	}
	c.rcpts = []string{"old@example.org"}
	if err := c.startTLS(&tls.Config{InsecureSkipVerify: true}); err != nil { //nolint:gosec // self-signed test certificate
		t.Fatal(err)
	}
	if state, ok := c.TLSConnectionState(); !ok || !state.HandshakeComplete {
		t.Fatalf("upgrade returned before handshake: ok=%v state=%+v", ok, state)
	}
	if c.ext != nil || len(c.rcpts) != 0 {
		t.Fatalf("pre-TLS knowledge retained: extensions=%v recipients=%v", c.ext, c.rcpts)
	}
	// Extension must issue a fresh EHLO over TLS and use only its new reply.
	if ok, _ := c.Extension("STARTTLS"); ok {
		t.Fatal("STARTTLS advertised after TLS")
	}
	if ok, _ := c.Extension("8BITMIME"); !ok {
		t.Fatal("post-TLS EHLO failed")
	}
	if err := c.startTLS(nil); err == nil {
		t.Fatal("client attempted a nested TLS upgrade")
	}
	if err := c.Noop(); err != nil {
		t.Fatalf("connection after refused nested TLS: %v", err)
	}
}

// checklist: TLS-CLIENT-01 TLS-CLIENT-03
func TestRFC3207ClientHandshakeFailure(t *testing.T) {
	// The legacy client tests install a global hook that trusts this test CA.
	hook := testHookStartTLS
	testHookStartTLS = nil
	t.Cleanup(func() { testHookStartTLS = hook })
	_, raw, _, done := newFlushTestConn(t, func(s *server.Server) {
		s.TLSConfig = rfc3207TLSConfig(t)
	})
	c := New(raw)
	c.didGreet = true
	// The self-signed certificate is not trusted by this client.
	if err := c.startTLS(&tls.Config{ServerName: "example.com"}); err == nil {
		t.Fatal("STARTTLS succeeded with an untrusted certificate")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed client handshake did not close the connection")
	}
}

// checklist: TLS-CLIENT-01 TLS-CLIENT-03
func TestRFC3207ClientHandshakeTimeout(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() { clientSide.Close(); serverSide.Close() })
	done := make(chan error, 1)
	go func() {
		defer serverSide.Close()
		br := bufio.NewReader(serverSide)
		for _, step := range []struct{ command, reply string }{
			{"EHLO localhost\r\n", "250-localhost\r\n250 STARTTLS\r\n"},
			{"STARTTLS\r\n", "220 ready\r\n"},
		} {
			line, err := br.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			if line != step.command {
				done <- fmt.Errorf("command = %q, want %q", line, step.command)
				return
			}
			if _, err := io.WriteString(serverSide, step.reply); err != nil {
				done <- err
				return
			}
		}
		// Consume ClientHello but never send a ServerHello.
		_, err := io.Copy(io.Discard, br)
		done <- err
	}()
	c := New(clientSide)
	c.didGreet = true
	c.CommandTimeout = 50 * time.Millisecond
	if err := c.startTLS(&tls.Config{InsecureSkipVerify: true}); err == nil { //nolint:gosec // no certificate is sent
		t.Fatal("STARTTLS succeeded with a stalled handshake")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("client did not close after handshake timeout")
	}
}

// checklist: TLS-CLIENT-01 TLS-CLIENT-03
func TestRFC3207ConstructorsVerifyHandshake(t *testing.T) {
	hook := testHookStartTLS
	testHookStartTLS = nil
	t.Cleanup(func() { testHookStartTLS = hook })
	for _, constructor := range []string{"DialStartTLS", "NewStartTLS"} {
		t.Run(constructor, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			s := server.New(nopBackend{})
			s.Domain = "localhost"
			s.TLSConfig = rfc3207TLSConfig(t)
			s.ReadTimeout = time.Second
			s.WriteTimeout = time.Second
			go s.Serve(ln) //nolint:errcheck // closed by cleanup
			t.Cleanup(func() { s.Close() })
			cfg := &tls.Config{ServerName: "example.com"}
			var client *Client
			if constructor == "DialStartTLS" {
				client, err = DialStartTLS(ln.Addr().String(), cfg)
			} else {
				raw, dialErr := net.Dial("tcp", ln.Addr().String())
				if dialErr != nil {
					t.Fatal(dialErr)
				}
				defer raw.Close()
				client, err = NewStartTLS(raw, cfg)
			}
			if client != nil {
				client.Close()
			}
			if err == nil || client != nil {
				t.Fatalf("%s returned (%v, %v) with an untrusted certificate", constructor, client, err)
			}
		})
	}
}
