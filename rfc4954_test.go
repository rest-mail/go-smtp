package smtp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
)

type rfc4954Session struct{ nopSession }

func (rfc4954Session) AuthMechanisms() []string { return []string{"PLAIN", "EXTERNAL"} }
func (rfc4954Session) Auth(mech string) (sasl.Server, error) {
	switch mech {
	case "PLAIN":
		return sasl.NewPlainServer(func(identity, username, password string) error {
			if identity != "test" || username != "test" || password != "1234" {
				return ErrAuthFailed
			}
			return nil
		}), nil
	case "EXTERNAL":
		return &rfc4954External{}, nil
	case "CHALLENGE":
		return &rfc4954Challenge{}, nil
	case "TOKEN":
		return &rfc4954Token{}, nil
	default:
		return nil, ErrAuthUnknownMechanism
	}
}

type rfc4954External struct{}

func (*rfc4954External) Next(response []byte) ([]byte, bool, error) {
	if response == nil {
		return nil, false, nil
	}
	if len(response) != 0 {
		return nil, false, ErrAuthFailed
	}
	return nil, true, nil
}

// RFC 4954 §4.1 PLAIN vectors, with transport deliberately plaintext here;
// TLS negotiation is independently covered by TestTLSClient.
// checklist: SMTP-AUTH-01 SMTP-AUTH-02 SMTP-AUTH-03 SMTP-AUTH-04 SMTP-AUTH-05
func TestRFC4954_Examples(t *testing.T) {
	for _, initial := range []bool{true, false} {
		t.Run(fmt.Sprint(initial), func(t *testing.T) {
			_, c, br := newConformanceServer(t, func(s *Server) {
				s.AllowInsecureAuth = true
				s.Backend = BackendFunc(func(*Conn) (Session, error) { return rfc4954Session{}, nil })
			})
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			writeCmd(t, c, "EHLO client.example.com\r\n")
			advertised := false
			for {
				line := readSMTPLine(t, br)
				if strings.Contains(line, "AUTH PLAIN EXTERNAL") {
					advertised = true
				}
				if strings.HasPrefix(line, "250 ") {
					break
				}
			}
			if !advertised {
				t.Fatal("missing AUTH mechanism list")
			}
			if initial {
				writeCmd(t, c, "auth plain dGVzdAB0ZXN0ADEyMzQ=\r\n")
			} else {
				writeCmd(t, c, "AUTH PLAIN\r\n")
				if got := readSMTPLine(t, br); got != "334 " {
					t.Fatalf("empty challenge = %q", got)
				}
				writeCmd(t, c, "dGVzdAB0ZXN0ADEyMzQ=\r\n")
			}
			if got := readSMTPLine(t, br); got != "235 2.7.0 Authentication succeeded" {
				t.Fatal(got)
			}
			writeCmd(t, c, "AUTH PLAIN\r\n")
			if got := readSMTPLine(t, br); !strings.HasPrefix(got, "503 ") {
				t.Fatal(got)
			}
			writeCmd(t, c, "RSET\r\n")
			readSMTPLine(t, br)
			writeCmd(t, c, "AUTH PLAIN\r\n")
			if got := readSMTPLine(t, br); !strings.HasPrefix(got, "503 ") {
				t.Fatal(got)
			}
		})
	}
}

// checklist: SMTP-AUTH-06 SMTP-AUTH-07 SMTP-AUTH-08 SMTP-AUTH-09 SMTP-AUTH-10
func TestRFC4954_ServerFailuresAndRetry(t *testing.T) {
	for _, continuation := range []bool{false, true} {
		for _, invalid := range []string{"!!!!", "=AAA", "AAA=BBB", "YW Jj", "YWJj\rZGVm"} {
			t.Run(fmt.Sprintf("%t/%q", continuation, invalid), func(t *testing.T) {
				_, c, br := newConformanceServer(t, func(s *Server) {
					s.AllowInsecureAuth = true
					s.Backend = BackendFunc(func(*Conn) (Session, error) { return rfc4954Session{}, nil })
				})
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				drainEHLO(t, c, br)
				writeCmd(t, c, "AUTH\r\n")
				if got := readSMTPLine(t, br); !strings.HasPrefix(got, "501 ") {
					t.Fatal(got)
				}
				writeCmd(t, c, "AUTH UNKNOWN\r\n")
				if got := readSMTPLine(t, br); !strings.HasPrefix(got, "504 5.5.4 ") {
					t.Fatal(got)
				}
				if continuation {
					writeCmd(t, c, "AUTH PLAIN\r\n")
					readSMTPLine(t, br)
					writeCmd(t, c, invalid+"\r\n")
				} else {
					writeCmd(t, c, "AUTH PLAIN "+invalid+"\r\n")
				}
				// SP splits AUTH arguments, so that case is a grammar error instead.
				want := "501 5.5.2 "
				if !continuation && strings.Contains(invalid, " ") {
					want = "501 5.5.4 "
				}
				if got := readSMTPLine(t, br); !strings.HasPrefix(got, want) {
					t.Fatalf("got %q, want %s", got, want)
				}
				writeCmd(t, c, "AUTH PLAIN dGVzdAB0ZXN0AGJhZA==\r\n")
				if got := readSMTPLine(t, br); !strings.HasPrefix(got, "535 5.7.8 ") {
					t.Fatal(got)
				}
				writeCmd(t, c, "AUTH PLAIN dGVzdAB0ZXN0ADEyMzQ=\r\n")
				if got := readSMTPLine(t, br); !strings.HasPrefix(got, "235 ") {
					t.Fatal(got)
				}
			})
		}
	}
}

// checklist: SMTP-AUTH-11
func TestRFC4954_EmptyInitialResponse(t *testing.T) {
	_, c, br := newConformanceServer(t, func(s *Server) {
		s.AllowInsecureAuth = true
		s.Backend = BackendFunc(func(*Conn) (Session, error) { return rfc4954Session{}, nil })
	})
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	drainEHLO(t, c, br)
	writeCmd(t, c, "AUTH EXTERNAL =\r\n")
	if got := readSMTPLine(t, br); !strings.HasPrefix(got, "235 2.7.0 ") {
		t.Fatal(got)
	}
}

type rfc4954Client struct{ response []byte }

func (a rfc4954Client) Start() (string, []byte, error) { return "PLAIN", a.response, nil }
func (rfc4954Client) Next([]byte) ([]byte, error)      { return nil, fmt.Errorf("unexpected Next call") }

func authTranscript(t *testing.T, replies string, a sasl.Client) (string, error) {
	t.Helper()
	var wrote bytes.Buffer
	c := NewClient(faker{ReadWriter: struct {
		io.Reader
		io.Writer
	}{strings.NewReader(replies), &wrote}})
	if err := c.greet(); err != nil {
		t.Fatal(err)
	}
	c.didHello = true
	defer c.Close()
	err := c.Auth(a)
	return wrote.String(), err
}

// checklist: SMTP-AUTH-12 SMTP-AUTH-11
func TestRFC4954_ClientInitialResponseLimit(t *testing.T) {
	for _, n := range []int{0, 372, 375, 12000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			response := bytes.Repeat([]byte{'a'}, n)
			encoded := base64.StdEncoding.EncodeToString(response)
			if n == 0 {
				encoded = "="
			}
			want := "AUTH PLAIN " + encoded + "\r\n"
			replies := "220 ready\r\n235 2.7.0 ok\r\n"
			if len(want) > 512 {
				want = "AUTH PLAIN\r\n" + encoded + "\r\n"
				replies = "220 ready\r\n334 \r\n235 2.7.0 ok\r\n"
			}
			got, err := authTranscript(t, replies, rfc4954Client{response})
			if err != nil || got != want {
				t.Fatalf("err=%v, output length=%d want=%d", err, len(got), len(want))
			}
		})
	}
}

// checklist: SMTP-AUTH-13 SMTP-AUTH-14
func TestRFC4954_ClientCancelAndFailure(t *testing.T) {
	for _, challenge := range []string{"!!!!", "=AAA", "AAA=BBB", "YW Jj", "YWJj\nZGVm"} {
		t.Run(challenge, func(t *testing.T) {
			reply := "334 " + challenge + "\r\n"
			if strings.Contains(challenge, "\n") {
				reply = "334-YWJj\r\n334 ZGVm\r\n"
			}
			got, err := authTranscript(t, "220 ready\r\n"+reply+"501 cancelled\r\n", rfc4954Client{})
			if err == nil || got != "AUTH PLAIN\r\n*\r\n" {
				t.Fatalf("err=%v, wrote=%q", err, got)
			}
		})
	}
	got, err := authTranscript(t, "220 ready\r\n535 5.7.8 denied\r\n", rfc4954Client{})
	if err == nil || got != "AUTH PLAIN\r\n" {
		t.Fatalf("err=%v, wrote=%q", err, got)
	}
	// An unexpected nonempty challenge cannot consume a deferred response.
	got, err = authTranscript(t, "220 ready\r\n334 YQ==\r\n501 cancelled\r\n", rfc4954Client{bytes.Repeat([]byte{'x'}, 400)})
	if err == nil || got != "AUTH PLAIN\r\n*\r\n" {
		t.Fatalf("err=%v, wrote=%q", err, got)
	}
}

// checklist: SMTP-AUTH-15
func TestRFC4954_ContinuationTooLong(t *testing.T) {
	_, c, br := newConformanceServer(t, func(s *Server) {
		s.AllowInsecureAuth = true
		s.MaxAuthResponseLength = 512
		s.Backend = BackendFunc(func(*Conn) (Session, error) { return rfc4954Session{}, nil })
	})
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	drainEHLO(t, c, br)
	writeCmd(t, c, "AUTH PLAIN\r\n")
	readSMTPLine(t, br)
	// 511 octets plus CRLF exceed the 512-octet bound.
	writeCmd(t, c, strings.Repeat("a", 511)+"\r\n")
	if got := readSMTPLine(t, br); !strings.HasPrefix(got, "500 5.5.6 ") {
		t.Fatal(got)
	}
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("connection remains open")
	}
}

// rfc4954Token sends an empty challenge and accepts one response of
// rfc4954TokenSize 'x' octets, standing in for a large GSSAPI token.
type rfc4954Token struct{ started bool }

const rfc4954TokenSize = 40000

func (a *rfc4954Token) Next(response []byte) ([]byte, bool, error) {
	if !a.started {
		a.started = true
		return nil, false, nil
	}
	if !bytes.Equal(response, bytes.Repeat([]byte("x"), rfc4954TokenSize)) {
		return nil, false, ErrAuthFailed
	}
	return nil, true, nil
}

// RFC 4954 §4: the server accepts a response larger than its command line
// limit, while that limit still bounds commands before and after AUTH.
// checklist: SMTP-AUTH-22
func TestRFC4954_ResponseSizeIndependentOfLineLimit(t *testing.T) {
	token := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), rfc4954TokenSize))
	t.Run("default bound", func(t *testing.T) {
		_, c, br := newConformanceServer(t, func(s *Server) {
			s.AllowInsecureAuth = true
			s.MaxLineLength = 512
			s.Backend = BackendFunc(func(*Conn) (Session, error) { return rfc4954Session{}, nil })
		})
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		drainEHLO(t, c, br)
		writeCmd(t, c, "AUTH TOKEN\r\n")
		if got := readSMTPLine(t, br); got != "334 " {
			t.Fatalf("challenge = %q", got)
		}
		writeCmd(t, c, token+"\r\n")
		if got := readSMTPLine(t, br); !strings.HasPrefix(got, "235 2.7.0 ") {
			t.Fatalf("large response: %q", got)
		}
		writeCmd(t, c, "NOOP "+strings.Repeat("a", 512)+"\r\n")
		if got := readSMTPLine(t, br); !strings.HasPrefix(got, "500 5.4.0 ") {
			t.Fatalf("command line limit after AUTH: %q", got)
		}
	})
	t.Run("default exceeded", func(t *testing.T) {
		_, c, br := newConformanceServer(t, func(s *Server) {
			s.AllowInsecureAuth = true
			s.Backend = BackendFunc(func(*Conn) (Session, error) { return rfc4954Session{}, nil })
		})
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		drainEHLO(t, c, br)
		writeCmd(t, c, "AUTH TOKEN\r\n")
		readSMTPLine(t, br)
		writeCmd(t, c, strings.Repeat("a", defaultMaxAuthResponseLength-1)+"\r\n")
		if got := readSMTPLine(t, br); !strings.HasPrefix(got, "500 5.5.6 ") {
			t.Fatalf("over default bound: %q", got)
		}
	})
	t.Run("unlimited", func(t *testing.T) {
		_, c, br := newConformanceServer(t, func(s *Server) {
			s.AllowInsecureAuth = true
			s.MaxLineLength = 512
			s.MaxAuthResponseLength = -1
			s.Backend = BackendFunc(func(*Conn) (Session, error) { return rfc4954Session{}, nil })
		})
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		drainEHLO(t, c, br)
		writeCmd(t, c, "AUTH TOKEN\r\n")
		readSMTPLine(t, br)
		writeCmd(t, c, token+"\r\n")
		if got := readSMTPLine(t, br); !strings.HasPrefix(got, "235 2.7.0 ") {
			t.Fatalf("unlimited: %q", got)
		}
	})
}

// checklist: SMTP-AUTH-08
func FuzzDecodeSASLResponse(f *testing.F) {
	for _, s := range []string{"", "=", "dGVzdAB0ZXN0ADEyMzQ=", "!!!!", "=AAA", "AAA=BBB", "YW\r\nJj"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := decodeSASLResponse(s)
		if err != nil {
			return
		}
		if s == "=" {
			if got == nil || len(got) != 0 {
				t.Fatal("empty initial response lost")
			}
			return
		}
		for _, b := range []byte(s) {
			if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '+' || b == '/' || b == '=') {
				t.Fatalf("accepted non-base64 byte %x", b)
			}
		}
		want, decodeErr := base64.StdEncoding.DecodeString(s)
		if decodeErr != nil || !bytes.Equal(got, want) {
			t.Fatal("decoder mismatch")
		}
	})
}

// checklist: SMTP-AUTH-19
func TestRFC4954_NoPlaintextAdvertisement(t *testing.T) {
	_, c, br := newConformanceServer(t, func(s *Server) {
		s.Backend = BackendFunc(func(*Conn) (Session, error) { return rfc4954Session{}, nil })
	})
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	writeCmd(t, c, "EHLO localhost\r\n")
	for {
		line := readSMTPLine(t, br)
		if strings.Contains(line, "AUTH") {
			t.Fatalf("plaintext AUTH advertised: %q", line)
		}
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}
	writeCmd(t, c, "AUTH PLAIN dGVzdAB0ZXN0ADEyMzQ=\r\n")
	if got := readSMTPLine(t, br); !strings.HasPrefix(got, "530 5.7.0 ") {
		t.Fatal(got)
	}
}

type rfc4954Challenge struct{ started bool }

func (a *rfc4954Challenge) Next(response []byte) ([]byte, bool, error) {
	if !a.started {
		a.started = true
		return []byte{0, 255}, false, nil
	}
	if string(response) != "answer" {
		return nil, false, ErrAuthFailed
	}
	return nil, true, nil
}

// checklist: SMTP-AUTH-18 SMTP-AUTH-17
func TestRFC4954_ChallengeAndCancel(t *testing.T) {
	_, c, br := newConformanceServer(t, func(s *Server) {
		s.AllowInsecureAuth = true
		s.Backend = BackendFunc(func(*Conn) (Session, error) { return rfc4954Session{}, nil })
	})
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	drainEHLO(t, c, br)
	writeCmd(t, c, "AUTH CHALLENGE\r\n")
	if got := readSMTPLine(t, br); got != "334 AP8=" {
		t.Fatal(got)
	}
	writeCmd(t, c, "*\r\n")
	if got := readSMTPLine(t, br); !strings.HasPrefix(got, "501 ") {
		t.Fatal(got)
	}
	writeCmd(t, c, "NOOP\r\n")
	if got := readSMTPLine(t, br); !strings.HasPrefix(got, "250 ") {
		t.Fatal(got)
	}
	writeCmd(t, c, "AUTH CHALLENGE\r\n")
	if got := readSMTPLine(t, br); got != "334 AP8=" {
		t.Fatal(got)
	}
	writeCmd(t, c, "YW5zd2Vy\r\n")
	if got := readSMTPLine(t, br); !strings.HasPrefix(got, "235 ") {
		t.Fatal(got)
	}
}

// lineAtATimeReader returns at most one line per Read, as a server that
// answers each command only after reading it would.
type lineAtATimeReader struct{ r *strings.Reader }

func (l lineAtATimeReader) Read(b []byte) (int, error) {
	n := 0
	for n < len(b) {
		c, err := l.r.ReadByte()
		if err != nil {
			if n > 0 {
				return n, nil
			}
			return 0, err
		}
		b[n] = c
		n++
		if c == '\n' {
			break
		}
	}
	return n, nil
}

type rfc4954EchoClient struct{ challenge []byte }

func (*rfc4954EchoClient) Start() (string, []byte, error) { return "TOKEN", nil, nil }
func (a *rfc4954EchoClient) Next(challenge []byte) ([]byte, error) {
	a.challenge = challenge
	return []byte("ok"), nil
}

// checklist: SMTP-AUTH-32
func TestRFC4954_ClientChallengeIndependentOfLineLimit(t *testing.T) {
	run := func(t *testing.T, limit, size int, after string) (*rfc4954EchoClient, *Client, error) {
		t.Helper()
		challenge := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'c'}, size))
		replies := "220 ready\r\n334 " + challenge + "\r\n235 2.7.0 ok\r\n" + after
		var wrote bytes.Buffer
		c := NewClient(faker{ReadWriter: struct {
			io.Reader
			io.Writer
		}{lineAtATimeReader{strings.NewReader(replies)}, &wrote}})
		c.MaxAuthChallengeLength = limit
		if err := c.greet(); err != nil {
			t.Fatal(err)
		}
		c.didHello = true
		t.Cleanup(func() { c.Close() })
		a := &rfc4954EchoClient{}
		return a, c, c.Auth(a)
	}
	t.Run("default accepts a challenge beyond the reply limit", func(t *testing.T) {
		a, _, err := run(t, 0, 30000, "")
		if err != nil || len(a.challenge) != 30000 {
			t.Fatalf("err=%v, challenge=%d octets", err, len(a.challenge))
		}
	})
	t.Run("negative means no limit", func(t *testing.T) {
		a, _, err := run(t, -1, 100000, "")
		if err != nil || len(a.challenge) != 100000 {
			t.Fatalf("err=%v, challenge=%d octets", err, len(a.challenge))
		}
	})
	t.Run("own bound refuses a longer challenge", func(t *testing.T) {
		a, _, err := run(t, 3000, 3000, "")
		if err == nil || a.challenge != nil {
			t.Fatalf("err=%v, challenge=%d octets", err, len(a.challenge))
		}
	})
	t.Run("reply limit returns after AUTH", func(t *testing.T) {
		_, c, err := run(t, 0, 3000, "250 "+strings.Repeat("x", 3000)+"\r\n")
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Noop(); err == nil {
			t.Fatal("a reply longer than the reply line limit was accepted after AUTH")
		}
	})
}
