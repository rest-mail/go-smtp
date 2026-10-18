package smtp_test

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	smtp "github.com/rest-mail/go-smtp"
)

// checklist: SMTP-SRV-04
func TestConnStateString(t *testing.T) {
	for state, want := range map[smtp.ConnState]string{
		smtp.StateNew:        "new",
		smtp.StateClosed:     "closed",
		smtp.ConnState(1000): "unknown",
	} {
		if got := state.String(); got != want {
			t.Errorf("ConnState(%d).String() = %q, want %q", int(state), got, want)
		}
	}
}

// checklist: SMTP-REP-03
func TestSMTPErrorTemporary(t *testing.T) {
	for code, want := range map[int]bool{250: false, 421: true, 450: true, 499: true, 500: false, 554: false} {
		if got := (&smtp.SMTPError{Code: code}).Temporary(); got != want {
			t.Errorf("SMTPError{Code: %d}.Temporary() = %v, want %v", code, got, want)
		}
	}
}

// checklist: SMTP-SRV-01
func TestCloseConnectionError(t *testing.T) {
	inner := errors.New("go away")
	err := smtp.CloseConnection(inner)
	if err.Error() != "go away" {
		t.Errorf("CloseConnection(err).Error() = %q, want %q", err.Error(), "go away")
	}
	if !errors.Is(err, inner) {
		t.Error("CloseConnection(err) does not unwrap to err")
	}
}

// checklist: SMTP-EXT-09
func TestLMTPDataErrorMessages(t *testing.T) {
	lmtpErr := smtp.LMTPDataError{
		"b@example.org": &smtp.SMTPError{Code: 550, Message: "no such user"},
		"a@example.org": &smtp.SMTPError{Code: 451, Message: "try later"},
	}
	want := "<a@example.org>: SMTP error 451: try later\n<b@example.org>: SMTP error 550: no such user"
	if got := lmtpErr.Error(); got != want {
		t.Errorf("LMTPDataError.Error() = %q, want %q", got, want)
	}
	unwrapped := lmtpErr.Unwrap()
	if len(unwrapped) != 2 {
		t.Fatalf("LMTPDataError.Unwrap() has %d errors, want 2", len(unwrapped))
	}
	var smtpErr *smtp.SMTPError
	if !errors.As(unwrapped[0], &smtpErr) || smtpErr.Code != 451 {
		t.Errorf("first unwrapped error = %v, want the 451 for a@example.org", unwrapped[0])
	}
}

// BackendFunc adapts a function to a Backend, and the connection hands that
// function its own accessors: the server, the client's EHLO name and the
// underlying net.Conn.
//
// checklist: SMTP-SRV-06
func TestBackendFuncAndConnAccessors(t *testing.T) {
	type seen struct {
		server   *smtp.Server
		hostname string
		local    net.Addr
	}
	got := make(chan seen, 1)
	var s *smtp.Server
	s = smtp.NewServer(smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
		got <- seen{c.Server(), c.Hostname(), c.Conn().LocalAddr()}
		return &session{backend: new(backend)}, nil
	}))
	s.Domain = "localhost"

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(l)
	defer s.Close()

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	scanner := bufio.NewScanner(c)
	scanner.Scan() // greeting
	io := func(cmd string) { c.Write([]byte(cmd + "\r\n")) }
	io("EHLO client.example.org")
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "250 ") {
			break
		}
	}

	select {
	case v := <-got:
		if v.server != s {
			t.Error("Conn.Server() is not the serving *Server")
		}
		if v.hostname != "client.example.org" {
			t.Errorf("Conn.Hostname() = %q, want %q", v.hostname, "client.example.org")
		}
		if v.local == nil || v.local.String() != l.Addr().String() {
			t.Errorf("Conn.Conn().LocalAddr() = %v, want %v", v.local, l.Addr())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the backend was never asked for a session")
	}
}

// A backend turns a connection away with Conn.Reject: 421, then the connection
// closes.
//
// checklist: SMTP-REP-02
func TestConnReject(t *testing.T) {
	s := smtp.NewServer(smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
		c.Reject()
		return nil, errors.New("too busy")
	}))
	s.Domain = "localhost"
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(l)
	defer s.Close()

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	scanner := bufio.NewScanner(c)
	scanner.Scan() // greeting
	c.Write([]byte("EHLO client.example.org\r\n"))
	if !scanner.Scan() || !strings.HasPrefix(scanner.Text(), "421 4.4.5 Too busy") {
		t.Fatalf("response to EHLO = %q, want 421 4.4.5 Too busy", scanner.Text())
	}
}

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// dialEventually retries until the server started in another goroutine listens.
func dialEventually(t *testing.T, dial func() (*smtp.Client, error)) *smtp.Client {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := dial()
		if err == nil {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never came up: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// selfSignedCert is a throwaway certificate for 127.0.0.1.
func selfSignedCert(t *testing.T) tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func testTLSServer(t *testing.T, addr string) *smtp.Server {
	keypair := selfSignedCert(t)
	s := smtp.NewServer(new(backend))
	s.Domain = "localhost"
	s.Addr = addr
	s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{keypair}}
	return s
}

// checklist: SMTP-SRV-05
func TestListenAndServe(t *testing.T) {
	s := testTLSServer(t, freeAddr(t))
	done := make(chan error, 1)
	go func() { done <- s.ListenAndServe() }()

	c := dialEventually(t, func() (*smtp.Client, error) { return smtp.Dial(s.Addr) })
	if err := c.Hello("client.example.org"); err != nil {
		t.Fatal(err)
	}
	c.Close()

	s.Close()
	if err := <-done; err != nil {
		t.Errorf("ListenAndServe after Close = %v, want nil", err)
	}
}

// checklist: SMTP-SRV-05
func TestListenAndServeBadAddr(t *testing.T) {
	s := testTLSServer(t, "not an address")
	if err := s.ListenAndServe(); err == nil {
		t.Error("ListenAndServe on a bad address succeeded")
	}
	if err := s.ListenAndServeTLS(); err == nil {
		t.Error("ListenAndServeTLS on a bad address succeeded")
	}
}

// checklist: SMTP-SRV-05
func TestListenAndServeTLS(t *testing.T) {
	s := testTLSServer(t, freeAddr(t))
	done := make(chan error, 1)
	go func() { done <- s.ListenAndServeTLS() }()
	cfg := &tls.Config{InsecureSkipVerify: true}

	c := dialEventually(t, func() (*smtp.Client, error) { return smtp.DialTLS(s.Addr, cfg) })
	if _, ok := c.TLSConnectionState(); !ok {
		t.Error("DialTLS connection is not TLS")
	}
	if err := c.Hello("client.example.org"); err != nil {
		t.Fatal(err)
	}
	c.Close()

	// SendMailTLS verifies the certificate against the system roots, which do
	// not include the test certificate.
	if err := smtp.SendMailTLS(s.Addr, nil, "a@example.org", []string{"b@example.org"}, strings.NewReader("x")); err == nil {
		t.Error("SendMailTLS to a server with an untrusted certificate succeeded")
	}

	s.Close()
	if err := <-done; err != nil {
		t.Errorf("ListenAndServeTLS after Close = %v, want nil", err)
	}
}

// checklist: SMTP-EXT-07
func TestNewClientStartTLS(t *testing.T) {
	s := testTLSServer(t, freeAddr(t))
	done := make(chan error, 1)
	go func() { done <- s.ListenAndServe() }()
	defer func() { s.Close(); <-done }()
	cfg := &tls.Config{InsecureSkipVerify: true}

	c := dialEventually(t, func() (*smtp.Client, error) { return smtp.DialStartTLS(s.Addr, cfg) })
	if _, ok := c.TLSConnectionState(); !ok {
		t.Error("DialStartTLS connection is not TLS")
	}
	c.Close()

	conn, err := net.Dial("tcp", s.Addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err = smtp.NewClientStartTLS(conn, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.TLSConnectionState(); !ok {
		t.Error("NewClientStartTLS connection is not TLS")
	}
	c.Close()

	// A server without STARTTLS is an error, and NewClientStartTLS closes the
	// connection it was given.
	plain := smtp.NewServer(new(backend))
	plain.Domain = "localhost"
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go plain.Serve(l)
	defer plain.Close()
	conn, err = net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := smtp.NewClientStartTLS(conn, cfg); err == nil {
		t.Error("NewClientStartTLS against a server without STARTTLS succeeded")
	}
}

// checklist: SMTP-SRV-05
func TestServerNetworkDefaultsToUnixForLMTP(t *testing.T) {
	// A unix socket path stands in for LMTP's default network: the listener is
	// a unix socket and the server answers LMTP on it.
	path := t.TempDir() + "/lmtp.sock"
	s := smtp.NewServer(new(backend))
	s.Domain = "localhost"
	s.LMTP = true
	s.Addr = path
	done := make(chan error, 1)
	go func() { done <- s.ListenAndServe() }()
	defer func() { s.Close(); <-done }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.Dial("unix", path)
		if err == nil {
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			line, _ := bufio.NewReader(conn).ReadString('\n')
			conn.Close()
			if !strings.Contains(line, "LMTP") {
				t.Errorf("greeting on the unix socket = %q, want an LMTP greeting", line)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("LMTP server never came up on %s: %v", path, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
