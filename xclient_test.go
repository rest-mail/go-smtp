package smtp_test

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	smtp "github.com/rest-mail/go-smtp"
)

type xclientBackend struct {
	ch chan *smtp.XClientAttrs
}

func (b *xclientBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	b.ch <- c.XClient()
	return ctxSession{}, nil
}

// readEHLOCaps sends EHLO and returns the advertised capabilities.
func readEHLOCaps(t *testing.T, c net.Conn, scanner *bufio.Scanner) []string {
	t.Helper()
	io.WriteString(c, "EHLO relay\r\n")
	var caps []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "250-") {
			caps = append(caps, strings.TrimPrefix(line, "250-"))
			continue
		}
		if strings.HasPrefix(line, "250 ") {
			caps = append(caps, strings.TrimPrefix(line, "250 "))
			break
		}
		break
	}
	return caps
}

func hasXCLIENT(caps []string) bool {
	for _, c := range caps {
		if strings.HasPrefix(c, "XCLIENT") {
			return true
		}
	}
	return false
}

// TestServerXClientTrusted verifies that for a trusted peer XCLIENT is
// advertised, honored, and the asserted identity reaches the backend.
func TestServerXClientTrusted(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	be := &xclientBackend{ch: make(chan *smtp.XClientAttrs, 1)}
	s := smtp.NewServer(be)
	s.Domain = "localhost"
	s.EnableXCLIENT = true
	s.TrustXCLIENT = func(*smtp.Conn) bool { return true }
	go s.Serve(l)
	defer s.Close()

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	scanner := bufio.NewScanner(c)
	scanner.Scan() // 220

	io.WriteString(c, "XCLIENT ADDR=203.0.113.5 NAME=client.example PROTO=ESMTP LOGIN=alice\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "220 ") {
		t.Fatalf("XCLIENT should be honored with a fresh 220 greeting, got: %q", scanner.Text())
	}

	caps := readEHLOCaps(t, c, scanner)
	if !hasXCLIENT(caps) {
		t.Errorf("EHLO should advertise XCLIENT to a trusted peer; got %v", caps)
	}

	select {
	case attrs := <-be.ch:
		if attrs == nil {
			t.Fatal("Conn.XClient() was nil after a trusted XCLIENT")
		}
		if attrs.Addr != "203.0.113.5" {
			t.Errorf("Addr = %q, want 203.0.113.5", attrs.Addr)
		}
		if attrs.Name != "client.example" {
			t.Errorf("Name = %q, want client.example", attrs.Name)
		}
		if attrs.Login != "alice" {
			t.Errorf("Login = %q, want alice", attrs.Login)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("NewSession was not called after EHLO")
	}
}

// TestServerXClientUntrusted verifies that for an untrusted peer XCLIENT is
// neither advertised nor honored.
func TestServerXClientUntrusted(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	be := &xclientBackend{ch: make(chan *smtp.XClientAttrs, 1)}
	s := smtp.NewServer(be)
	s.Domain = "localhost"
	s.EnableXCLIENT = true
	s.TrustXCLIENT = func(*smtp.Conn) bool { return false }
	go s.Serve(l)
	defer s.Close()

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	scanner := bufio.NewScanner(c)
	scanner.Scan() // 220

	io.WriteString(c, "XCLIENT ADDR=203.0.113.5\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "550 ") {
		t.Errorf("XCLIENT from an untrusted peer must be rejected 550, got: %q", scanner.Text())
	}

	caps := readEHLOCaps(t, c, scanner)
	if hasXCLIENT(caps) {
		t.Errorf("an untrusted peer must not see XCLIENT advertised; got %v", caps)
	}
}
