package smtp

import (
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

type rfc6710Session struct {
	nopSession
	got       chan *MailOptions
	mailError error
}

func (s rfc6710Session) Mail(_ string, opts *MailOptions) error {
	s.got <- opts
	return s.mailError
}

func (s rfc6710Session) Data(r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}

// checklist: PRI-EHLO-01 PRI-SYN-01 PRI-SRV-01 PRI-STATE-01 PRI-STATE-02
func TestRFC6710Server(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		profile PriorityProfile
	}{
		{"disabled", false, PriorityUnspecified},
		{"undisclosed", true, PriorityUnspecified},
		{"MIXER", true, PriorityMIXER},
		{"STANAG4406", true, PrioritySTANAG4406},
		{"NSEP", true, PriorityNSEP},
		{"custom", true, "Site_policy-1.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := make(chan *MailOptions, 32)
			_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
				s.EnableMTPRIORITY = tc.enabled
				s.MtPriorityProfile = tc.profile
				s.Backend = BackendFunc(func(*Conn) (Session, error) { return rfc6710Session{got: got}, nil })
			})
			command := func(cmd, want string) []string {
				t.Helper()
				writeFlushBatch(t, raw, cmd+"\r\n")
				reply := readFlushReply(t, br)
				if !strings.HasPrefix(reply[0], want) {
					t.Fatalf("%q = %q, want %s", cmd, reply, want)
				}
				return reply
			}
			count := 0
			for _, line := range command("EHLO mua.example.com", "250") {
				if strings.HasPrefix(line[4:], "MT-PRIORITY") {
					count++
					want := "MT-PRIORITY"
					if tc.profile != "" {
						want += " " + string(tc.profile)
					}
					if line[4:] != want {
						t.Fatalf("capability %q, want %q", line, want)
					}
				}
			}
			if count != map[bool]int{true: 1, false: 0}[tc.enabled] {
				t.Fatalf("capability count = %d", count)
			}
			if !tc.enabled {
				command("MAIL FROM:<eljefe@example.com> MT-PRIORITY=3", "504 5.5.4")
				if len(got) != 0 {
					t.Fatal("disabled priority reached backend")
				}
				return
			}
			for _, arg := range []string{"MT-PRIORITY", "MT-PRIORITY=", "MT-PRIORITY=+1", "MT-PRIORITY=-0", "MT-PRIORITY=00", "MT-PRIORITY=01", "MT-PRIORITY=-01", "MT-PRIORITY=10", "MT-PRIORITY=-10", "MT-PRIORITY=１", "MT-PRIORITY=1=", "MT-PRIORITY=9 mt-priority=8"} {
				want := "501 5.5.2"
				if strings.Contains(arg, " ") {
					want = "501 5.5.4"
				}
				command("MAIL FROM:<eljefe@example.com> "+arg, want)
			}
			if len(got) != 0 {
				t.Fatal("invalid priority reached backend")
			}
			// All 19 grammar values must be preserved even for a profile with fewer levels.
			for priority := -9; priority <= 9; priority++ {
				command(fmt.Sprintf("MAIL FROM:<eljefe@example.com> mt-priority=%d", priority), "250")
				if opts := <-got; opts.MTPriority == nil || *opts.MTPriority != priority {
					t.Fatalf("backend options = %+v, want %d", opts, priority)
				}
				command("MAIL FROM:<other@example.com> MT-PRIORITY=0", "503")
				command("RCPT TO:<topbanana@example.net> MT-PRIORITY=3", "500 5.5.4")
				command("RCPT TO:<topbanana@example.net>", "250")
				if len(got) != 0 {
					t.Fatal("nested MAIL reached backend")
				}
				command("RSET", "250")
			}
			// RSET, EHLO, and successful DATA each end the previous priority's lifetime.
			for _, reset := range []string{"RSET", "EHLO mua.example.com", "DATA"} {
				command("MAIL FROM:<eljefe@example.com> MT-PRIORITY=3", "250")
				<-got
				if reset == "DATA" {
					command("RCPT TO:<topbanana@example.net>", "250")
					command("DATA", "354")
					command("Subject: priority\r\n\r\nmessage\r\n.", "250")
				} else {
					command(reset, "250")
				}
				command("MAIL FROM:<eljefe@example.com>", "250")
				if opts := <-got; opts.MTPriority != nil {
					t.Fatalf("priority leaked after %s: %+v", reset, opts)
				}
				command("RSET", "250")
			}
		})
	}
}

// checklist: PRI-CLI-01 PRI-CLI-02 PRI-EXAMPLE-01
func TestRFC6710Client(t *testing.T) {
	for _, profile := range []string{"", "MIXER", "STANAG4406", "unknown-policy"} {
		for priority := -9; priority <= 9; priority++ {
			c, wrote := newMailParamClient("MT-PRIORITY")
			c.ext["MT-PRIORITY"] = profile
			err := c.Mail("eljefe@example.com", &MailOptions{MTPriority: &priority})
			c.Close()
			want := fmt.Sprintf("MAIL FROM:<eljefe@example.com> MT-PRIORITY=%d\r\n", priority)
			if err != nil || wrote.String() != want {
				t.Fatalf("profile %q priority %d: %v, %q", profile, priority, err, wrote.String())
			}
		}
	}
	for _, priority := range []int{-10, 10} {
		c, wrote := newMailParamClient("MT-PRIORITY")
		err := c.Mail("a@example.org", &MailOptions{MTPriority: &priority})
		c.Close()
		if err == nil || wrote.Len() != 0 {
			t.Fatalf("invalid priority %d: err=%v wire=%q", priority, err, wrote.String())
		}
	}
	p := 3
	c, wrote := newMailParamClient()
	defer c.Close()
	if err := c.Mail("a@example.org", &MailOptions{MTPriority: &p}); err == nil || wrote.Len() != 0 {
		t.Fatalf("unsupported option: err=%v wire=%q", err, wrote.String())
	}
	// A relay chooses fallback explicitly, removing the unsupported option.
	if err := c.Mail("a@example.org", nil); err != nil || wrote.String() != "MAIL FROM:<a@example.org>\r\n" {
		t.Fatalf("fallback: err=%v wire=%q", err, wrote.String())
	}
}

// checklist: PRI-EXAMPLE-01 PRI-CLI-01
func TestRFC6710ExampleEnvelope(t *testing.T) {
	// Section 8's submission and relay envelopes. Authentication, queue policy,
	// elapsed-time calculation and message contents are deliberately host work.
	for _, seconds := range []int{125, 120} {
		c, wrote := newMailParamClient("MT-PRIORITY", "DELIVERBY", "DSN")
		priority := 3
		err := c.Mail("eljefe@example.com", &MailOptions{MTPriority: &priority, DeliverBy: &DeliverByOptions{Time: time.Duration(seconds) * time.Second, Mode: DeliverByReturn}, EnvelopeID: "QQ314159"})
		c.Close()
		want := fmt.Sprintf("MAIL FROM:<eljefe@example.com> ENVID=QQ314159 BY=%d;R MT-PRIORITY=3\r\n", seconds)
		if err != nil || wrote.String() != want {
			t.Fatalf("example: err=%v wire=%q, want %q", err, wrote.String(), want)
		}
	}
}

// checklist: PRI-STATUS-01 PRI-STATUS-02
func TestRFC6710BackendStatuses(t *testing.T) {
	for _, tc := range []struct {
		code     int
		enhanced EnhancedCode
		message  string
	}{
		{250, EnhancedCode{2, 3, 6}, "3 is the new priority assigned to the message"},
		{450, EnhancedCode{4, 7, 15}, "Priority level is too low"},
		{550, EnhancedCode{5, 7, 15}, "Priority level is too low"},
		{552, EnhancedCode{5, 7, 16}, "Message is too big for the specified priority"},
		{550, EnhancedCode{5, 7, 1}, "Source is not authorized for positive priorities"},
	} {
		got := make(chan *MailOptions, 2)
		_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
			s.EnableMTPRIORITY = true
			s.Backend = BackendFunc(func(*Conn) (Session, error) {
				return rfc6710Session{got: got, mailError: &SMTPError{Code: tc.code, EnhancedCode: tc.enhanced, Message: tc.message}}, nil
			})
		})
		writeFlushBatch(t, raw, "EHLO mua.example.com\r\n")
		readFlushReply(t, br)
		writeFlushBatch(t, raw, "MAIL FROM:<eljefe@example.com> MT-PRIORITY=3\r\n")
		want := fmt.Sprintf("%d %d.%d.%d %s", tc.code, tc.enhanced[0], tc.enhanced[1], tc.enhanced[2], tc.message)
		if reply := readFlushReply(t, br); reply[0] != want {
			t.Fatalf("got %q, want %q", reply, want)
		}
		<-got
		// Only an accepted custom 2xx reply starts the transaction.
		writeFlushBatch(t, raw, "RCPT TO:<topbanana@example.net>\r\n")
		wantCode := "503"
		if tc.code == 250 {
			wantCode = "250"
		}
		if reply := readFlushReply(t, br); !strings.HasPrefix(reply[0], wantCode) {
			t.Fatalf("post-policy RCPT = %q", reply)
		}
	}
}

var priorityGrammar = regexp.MustCompile(`^(?:0|-?[1-9])$`)

// checklist: PRI-SYN-01
func FuzzRFC6710Priority(f *testing.F) {
	for value := -9; value <= 9; value++ {
		f.Add(strconv.Itoa(value))
	}
	for _, seed := range []string{"", "0", "-9", "9", "+1", "-0", "00", "01", "-01", "10", "-10", "１", "1\r\n", "1\x00", " 1", "1=", "999999999999999999999999"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire string) {
		if len(wire) > maxParserFuzzInput {
			t.Skip()
		}
		got, err := parseMTPriority(wire)
		valid := priorityGrammar.MatchString(wire)
		if valid != (err == nil) {
			t.Fatalf("parseMTPriority(%q)=%d,%v; grammar valid=%v", wire, got, err, valid)
		}
		if valid {
			want, _ := strconv.Atoi(wire)
			if got != want {
				t.Fatalf("value %d, want %d", got, want)
			}
		}
	})
}

// checklist: PRI-LEN-01 PRI-LMTP-01
func TestRFC6710LongMailAndLMTP(t *testing.T) {
	for _, lmtp := range []bool{false, true} {
		got := make(chan *MailOptions, 1)
		_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
			s.LMTP = lmtp
			s.EnableMTPRIORITY = true
			s.Backend = BackendFunc(func(*Conn) (Session, error) { return rfc6710Session{got: got}, nil })
		})
		hello := "EHLO mua.example.com"
		if lmtp {
			hello = "LHLO mua.example.com"
		}
		writeFlushBatch(t, raw, hello+"\r\n")
		caps := strings.Join(readFlushReply(t, br), "\n")
		if !strings.Contains(caps, "MT-PRIORITY") {
			t.Fatal(caps)
		}
		// 512 octets including CRLF before appending the 15-octet option.
		// Long domain labels are intentionally synthetic: this checks the
		// command reader's byte budget, not mailbox routing or DNS validity.
		base := "MAIL FROM:<a@" + strings.Repeat("b", 512-len("MAIL FROM:<a@>\r\n")) + ">"
		wire := base + " MT-PRIORITY=-9\r\n"
		if len(wire) != 527 {
			t.Fatalf("wire length %d, want 527", len(wire))
		}
		writeFlushBatch(t, raw, wire)
		if reply := readFlushReply(t, br); !strings.HasPrefix(reply[0], "250") {
			t.Fatal(reply)
		}
		if opts := <-got; opts.MTPriority == nil || *opts.MTPriority != -9 {
			t.Fatalf("LMTP=%v options=%+v", lmtp, opts)
		}
	}
}
