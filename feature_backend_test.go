package smtp_test

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"

	smtp "github.com/rest-mail/go-smtp"
)

// featureBackend wraps the test backend and additionally implements
// FeatureBackend to advertise extra EHLO capabilities.
type featureBackend struct {
	*backend
	caps []string
}

func (b *featureBackend) Features(*smtp.Conn) []string { return b.caps }

var _ smtp.FeatureBackend = (*featureBackend)(nil)

// TestServerFeatureBackend verifies a Backend implementing FeatureBackend has
// its dynamically-computed capabilities advertised in the EHLO response.
func TestServerFeatureBackend(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	be := &featureBackend{backend: new(backend), caps: []string{"X-EXAMPLE", "X-FOO BAR"}}
	s := smtp.NewServer(be)
	s.Domain = "localhost"
	go s.Serve(l)
	defer s.Close()

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	scanner := bufio.NewScanner(c)
	scanner.Scan() // 220 greeting

	io.WriteString(c, "EHLO localhost\r\n")
	caps := map[string]bool{}
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "250-") {
			caps[strings.TrimPrefix(line, "250-")] = true
			continue
		}
		if strings.HasPrefix(line, "250 ") {
			caps[strings.TrimPrefix(line, "250 ")] = true
			break
		}
		break
	}

	if !caps["X-EXAMPLE"] {
		t.Errorf("EHLO missing X-EXAMPLE from Features(); got %v", caps)
	}
	if !caps["X-FOO BAR"] {
		t.Errorf("EHLO missing 'X-FOO BAR' from Features(); got %v", caps)
	}
}
