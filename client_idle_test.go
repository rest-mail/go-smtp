package smtp

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// newIdleClient returns a Client wrapping the given net.Conn with no I/O
// performed yet (so its read buffer is empty), as a pooled connection sitting
// idle would be.
func newIdleClient(conn net.Conn) *Client {
	return NewClient(conn)
}

// A healthy idle plaintext connection: no data pending, the probe times out and
// reports the connection usable.
func TestCheckConn_HealthyPlaintext(t *testing.T) {
	cconn, sconn := net.Pipe()
	defer cconn.Close()
	defer sconn.Close()

	c := newIdleClient(cconn)
	if err := c.CheckConn(100 * time.Millisecond); err != nil {
		t.Fatalf("healthy idle connection reported unusable: %v", err)
	}
}

// The server closed the connection while it was idle: the probe must detect it.
func TestCheckConn_ServerClosedPlaintext(t *testing.T) {
	cconn, sconn := net.Pipe()
	defer cconn.Close()

	c := newIdleClient(cconn)
	sconn.Close()

	err := c.CheckConn(time.Second)
	if err == nil {
		t.Fatal("expected an error after the server closed the connection")
	}
}

// Unsolicited data on an idle connection means it is not cleanly reusable.
func TestCheckConn_UnsolicitedData(t *testing.T) {
	cconn, sconn := net.Pipe()
	defer cconn.Close()
	defer sconn.Close()

	go func() { io.WriteString(sconn, "220 surprise\r\n") }()

	c := newIdleClient(cconn)
	if err := c.CheckConn(time.Second); err == nil {
		t.Fatal("expected an error when the server sent unsolicited data")
	}
}

// Bytes already buffered from a prior read are treated as a non-idle connection.
func TestCheckConn_BufferedData(t *testing.T) {
	cconn, sconn := net.Pipe()
	defer cconn.Close()
	defer sconn.Close()

	c := newIdleClient(cconn)

	// Push a line and let the client's textproto buffer it via a peek.
	go func() { io.WriteString(sconn, "250 leftover\r\n") }()
	if _, err := c.text.R.Peek(1); err != nil {
		t.Fatalf("peek: %v", err)
	}

	if err := c.CheckConn(time.Second); !errors.Is(err, errIdleData) {
		t.Fatalf("buffered data: got %v, want errIdleData", err)
	}
}

// STARTTLS-safety: the probe reads through the *tls.Conn. A timed-out healthy
// probe must leave the TLS stream intact (a following command still reads
// correctly), and a server close must still be detected.
func TestCheckConn_TLS(t *testing.T) {
	ln := newLocalListener(t)
	defer ln.Close()

	serverReady := make(chan net.Conn, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
			serverReady <- nil
			return
		}
		keypair, err := tls.X509KeyPair(localhostCert, localhostKey)
		if err != nil {
			t.Errorf("keypair: %v", err)
			serverReady <- nil
			return
		}
		sc := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{keypair}})
		if err := sc.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			serverReady <- nil
			return
		}
		serverReady <- sc
	}()

	cfg := &tls.Config{ServerName: "example.com"}
	testHookStartTLS(cfg) // set RootCAs to trust localhostCert

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tconn := tls.Client(raw, cfg)
	if err := tconn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	c := newIdleClient(tconn)

	sc := <-serverReady
	if sc == nil {
		t.Fatal("server setup failed")
	}
	defer sc.Close()

	// Healthy idle TLS connection: probe times out, reports usable.
	if err := c.CheckConn(100 * time.Millisecond); err != nil {
		t.Fatalf("healthy idle TLS connection reported unusable: %v", err)
	}

	// The timed-out probe must not have corrupted the TLS stream: a real read
	// following it still returns the server's next line intact.
	if _, err := io.WriteString(sc, "250 still-alive\r\n"); err != nil {
		t.Fatal(err)
	}
	line, err := c.text.ReadLine()
	if err != nil {
		t.Fatalf("read after probe: %v", err)
	}
	if line != "250 still-alive" {
		t.Fatalf("stream corrupted by probe: read %q", line)
	}

	// After the server closes, the probe detects it.
	sc.Close()
	if err := c.CheckConn(time.Second); err == nil {
		t.Fatal("expected an error after the server closed the TLS connection")
	}
}
