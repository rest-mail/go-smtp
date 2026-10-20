package smtp

import (
	"bytes"
	"io"
	"math/big"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

// checklist: CHUNK-SYNTAX-01 CHUNK-SYNTAX-02
func TestRFC3030Arguments(t *testing.T) {
	for _, tc := range []struct {
		arg  string
		size uint64
		last bool
		ok   bool
	}{
		{"0", 0, false, true}, {"0008 lAsT", 8, true, true}, {"4294967295 LAST", 4294967295, true, true},
		{"", 0, false, false}, {"-1", 0, false, false}, {"+1", 0, false, false},
		{"1 LAST extra", 0, false, false}, {"1 LAſT", 0, false, false}, {"1 LAST=1", 0, false, false},
		{"1\u0085LAST", 0, false, false}, {"4294967296", 0, false, false}, {"18446744073709551616", 0, false, false},
	} {
		n, last, err := parseBdatArgs(tc.arg)
		if (err == nil) != tc.ok || (tc.ok && (n != tc.size || last != tc.last)) {
			t.Errorf("%q = %d, %v, %v", tc.arg, n, last, err)
		}
	}
}

// An independent regexp/large integer oracle checks both syntax and the
// documented implementation limit, without duplicating strconv parsing.
// checklist: CHUNK-SYNTAX-01 CHUNK-SYNTAX-02
func FuzzRFC3030Arguments(f *testing.F) {
	for _, s := range []string{"0", "86 LAST", "100000", "324", "0 LAST", "1 LAſT", "-1", "+1", "4294967295 LAST", "4294967296", "8\u0085LAST", "00000\tlast"} {
		f.Add(s)
	}
	grammar := regexp.MustCompile(`^[ \t]*([0-9]+)(?:[ \t]+([Ll][Aa][Ss][Tt]))?[ \t]*$`)
	limit := new(big.Int).SetUint64(1<<32 - 1)
	f.Fuzz(func(t *testing.T, arg string) {
		if len(arg) > 4096 {
			return
		}
		m := grammar.FindStringSubmatch(arg)
		valid := false
		var want uint64
		if m != nil {
			n, ok := new(big.Int).SetString(m[1], 10)
			valid = ok && n.Cmp(limit) <= 0
			if valid {
				want = n.Uint64()
			}
		}
		size, last, err := parseBdatArgs(arg)
		if (err == nil) != valid {
			t.Fatalf("%q: parser=%v, grammar=%v", arg, err, valid)
		}
		if valid && (size != want || last != (m[2] != "")) {
			t.Fatalf("%q: %d/%v, want %d/%v", arg, size, last, want, m[2] != "")
		}
	})
}

// checklist: CHUNK-ERROR-01 CHUNK-ERROR-03
func TestRFC3030DiscardBeforeReply(t *testing.T) {
	for _, envelope := range []bool{false, true} {
		t.Run(map[bool]string{false: "no envelope", true: "size limit"}[envelope], func(t *testing.T) {
			_, c, br, _ := newFlushTestConn(t, func(s *Server) { s.MaxMessageBytes = 1; s.ReadTimeout = time.Second })
			writeFlushBatch(t, c, "EHLO localhost\r\n")
			readFlushReply(t, br)
			if envelope {
				writeFlushBatch(t, c, "MAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.org>\r\n")
				readFlushReply(t, br)
				readFlushReply(t, br)
			}
			writeFlushBatch(t, c, "BDAT 4 LAST\r\n")
			c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
			if b, err := br.ReadByte(); err == nil {
				t.Fatalf("premature reply starts with %q", b)
			} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				t.Fatal(err)
			}
			c.SetDeadline(time.Now().Add(5 * time.Second))
			writeFlushBatch(t, c, "abcd")
			code := "503 "
			if envelope {
				code = "552 "
			}
			if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, code) {
				t.Fatal(got)
			}
		})
	}
}

// checklist: CHUNK-ERROR-03
func TestRFC3030TruncatedChunkNotDelivered(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "over limit"}[reject], func(t *testing.T) {
			delivered := make(chan []byte, 1)
			_, c, br := newConformanceServer(t, func(s *Server) {
				if reject {
					s.MaxMessageBytes = 1
				}
				s.Backend = BackendFunc(func(*Conn) (Session, error) {
					return rfc6152Session{data: delivered, mail: func(string, *MailOptions) error { return nil }}, nil
				})
			})
			c.SetDeadline(time.Now().Add(5 * time.Second))
			drainEHLO(t, c, br)
			writeCmd(t, c, "MAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.org>\r\n")
			readSMTPLine(t, br)
			readSMTPLine(t, br)
			writeCmd(t, c, "BDAT 10 LAST\r\nshort")
			if err := c.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			line := readSMTPLine(t, br)
			if strings.HasPrefix(line, "250 ") || strings.HasPrefix(line, "552 ") {
				t.Fatalf("partial chunk acknowledged: %q", line)
			}
			if _, err := br.ReadByte(); err != io.EOF {
				t.Fatalf("connection remains open: %v", err)
			}
			select {
			case b := <-delivered:
				t.Fatalf("partial delivery %q", b)
			default:
			}
		})
	}
}

// Buffer a valid chunk together with a long opaque payload, then a command
// exceeding the limit. Only the command must be rejected.
// checklist: CHUNK-DATA-02 CHUNK-DATA-04
func TestRFC3030ReadAheadLimits(t *testing.T) {
	data := make(chan []byte, 1)
	_, c, br, _ := newFlushTestConn(t, func(s *Server) {
		s.MaxLineLength = 64
		s.Backend = BackendFunc(func(*Conn) (Session, error) {
			return rfc6152Session{data: data, mail: func(string, *MailOptions) error { return nil }}, nil
		})
	})
	writeFlushBatch(t, c, "EHLO localhost\r\n")
	readFlushReply(t, br)
	writeFlushBatch(t, c, "MAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.org>\r\n")
	readFlushReply(t, br)
	readFlushReply(t, br)
	body := bytes.Repeat([]byte{'x'}, 1000)
	writeFlushBatch(t, c, "BDAT 1000 LAST\r\n"+string(body)+"NOOP "+strings.Repeat("z", 100)+"\r\n")
	if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, "250 ") {
		t.Fatal(got)
	}
	if !bytes.Equal(<-data, body) {
		t.Fatal("body changed")
	}
	if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, "500 ") {
		t.Fatal(got)
	}
}

// checklist: CHUNK-DATA-03
func TestRFC3030NonLastDoesNotDeliver(t *testing.T) {
	delivered := make(chan []byte, 1)
	_, c, br, _ := newFlushTestConn(t, func(s *Server) {
		s.Backend = BackendFunc(func(*Conn) (Session, error) {
			return rfc6152Session{data: delivered, mail: func(string, *MailOptions) error { return nil }}, nil
		})
	})
	writeFlushBatch(t, c, "EHLO localhost\r\n")
	readFlushReply(t, br)
	writeFlushBatch(t, c, "MAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.org>\r\n")
	readFlushReply(t, br)
	readFlushReply(t, br)
	for _, chunk := range []string{"BDAT 3\r\nabc", "BDAT 0\r\n"} {
		writeFlushBatch(t, c, chunk)
		if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, "250 ") {
			t.Fatal(got)
		}
		select {
		case b := <-delivered:
			t.Fatalf("delivery before LAST: %q", b)
		default:
		}
	}
	writeFlushBatch(t, c, "BDAT 0 LAST\r\n")
	if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, "250 ") {
		t.Fatal(got)
	}
	if b := <-delivered; string(b) != "abc" {
		t.Fatalf("data=%q", b)
	}
}

// checklist: CHUNK-ERROR-03
func TestRFC3030DiscardTimeoutClosesConnection(t *testing.T) {
	_, c, br := newConformanceServer(t, func(s *Server) { s.ReadTimeout = 30 * time.Millisecond })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	drainEHLO(t, c, br)
	writeCmd(t, c, "BDAT 4 LAST\r\nab")
	if got := readSMTPLine(t, br); !strings.HasPrefix(got, "451 4.4.2 ") {
		t.Fatal(got)
	}
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("discard timeout left connection open: %v", err)
	}
}
