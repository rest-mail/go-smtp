package server

import (
	"bytes"
	"encoding/base64"
	"fmt"
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
