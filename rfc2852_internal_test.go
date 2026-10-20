package smtp

import (
	"strings"
	"testing"
	"time"
)

type rfc2852Session struct {
	nopSession
	got chan *DeliverByOptions
}

func (s rfc2852Session) Mail(_ string, opts *MailOptions) error {
	s.got <- opts.DeliverBy
	return nil
}

// checklist: BY-EHLO-01 BY-SRV-01 BY-SRV-02 BY-SYN-01 BY-SYN-02 BY-SYN-03 BY-STATE-01 BY-EXAMPLE-01
func TestRFC2852Server(t *testing.T) {
	for _, tc := range []struct {
		name       string
		enabled    bool
		minimum    time.Duration
		capability string
	}{
		{"disabled", false, 0, ""},
		{"unspecified minimum", true, 0, "DELIVERBY"},
		{"fixed minimum", true, 30 * time.Second, "DELIVERBY 30"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := make(chan *DeliverByOptions, 16)
			_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
				s.EnableDELIVERBY = tc.enabled
				s.MinimumDeliverByTime = tc.minimum
				s.Backend = BackendFunc(func(*Conn) (Session, error) { return rfc2852Session{got: got}, nil })
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
			for _, line := range command("EHLO bigbiz.com", "250") {
				if strings.HasPrefix(line[4:], "DELIVERBY") {
					count++
					if line[4:] != tc.capability {
						t.Fatalf("advertisement %q, want %q", line, tc.capability)
					}
				}
			}
			if count != map[bool]int{true: 1, false: 0}[tc.enabled] {
				t.Fatalf("DELIVERBY count = %d", count)
			}
			if !tc.enabled {
				command("MAIL FROM:<eljefe@bigbiz.com> BY=120;R", "504 5.5.4")
				if len(got) != 0 {
					t.Fatal("disabled BY reached backend")
				}
				return
			}
			for _, arg := range []string{"BY", "BY=", "BY=0;R", "BY=-1;RT", "BY=1;X", "BY=1;NTT", "BY=1000000000;N", "BY=1;N BY=2;N"} {
				command("MAIL FROM:<eljefe@bigbiz.com> "+arg, "501 5.5.4")
			}
			if tc.minimum != 0 {
				command("MAIL FROM:<eljefe@bigbiz.com> BY=29;RT", "555 5.5.4")
			}
			if len(got) != 0 {
				t.Fatal("refused BY reached backend")
			}
			// Section 6's initial envelope and subsequent relay envelope (22 seconds elapsed).
			for _, arg := range []struct {
				wire string
				want DeliverByOptions
			}{
				{"120;R", DeliverByOptions{Time: 120 * time.Second, Mode: DeliverByReturn}},
				{"98;R", DeliverByOptions{Time: 98 * time.Second, Mode: DeliverByReturn}},
				{"30;rT", DeliverByOptions{Time: 30 * time.Second, Mode: DeliverByReturn, Trace: true}},
				{"0;n", DeliverByOptions{Mode: DeliverByNotify}},
				{"-999999999;nT", DeliverByOptions{Time: -999999999 * time.Second, Mode: DeliverByNotify, Trace: true}},
			} {
				command("MAIL FROM:<eljefe@bigbiz.com> bY="+arg.wire, "250")
				if opts := <-got; opts == nil || *opts != arg.want {
					t.Fatalf("%q backend = %+v, want %+v", arg.wire, opts, arg.want)
				}
				command("RCPT TO:<topbanana@other.com> BY=120;R", "500 5.5.4")
				command("RCPT TO:<topbanana@other.com>", "250")
				command("RSET", "250")
			}
			command("MAIL FROM:<eljefe@bigbiz.com>", "250")
			if opts := <-got; opts != nil {
				t.Fatalf("deadline leaked after reset: %+v", opts)
			}
		})
	}
}

// checklist: BY-CLI-01 BY-CLI-02 BY-EXAMPLE-01
func TestRFC2852ClientMinimum(t *testing.T) {
	for _, tc := range []struct {
		cap     string
		seconds int
		mode    DeliverByMode
		fail    bool
	}{
		{"", 120, DeliverByReturn, false},
		{"240", 120, DeliverByReturn, true}, // RFC section 6's refused relay.
		{"30", 98, DeliverByReturn, false},  // RFC section 6's permitted relay.
		{"30", 30, DeliverByReturn, false},
		{"30,option", 29, DeliverByReturn, true},
		{",option", 1, DeliverByReturn, false},
		{"000000030", 29, DeliverByReturn, true},
		{"0", 1, DeliverByReturn, false},
		{"999999999", 999999999, DeliverByReturn, false},
		{"30", -1, DeliverByNotify, false},
		{"30", 0, DeliverByNotify, false},
		{"-1", 120, DeliverByReturn, true},
		{"+1", 120, DeliverByReturn, true},
		{"1000000000", 120, DeliverByReturn, true},
		{"１", 120, DeliverByReturn, true},
	} {
		c, wrote := newMailParamClient("DELIVERBY")
		c.ext["DELIVERBY"] = tc.cap
		err := c.Mail("eljefe@bigbiz.com", &MailOptions{DeliverBy: &DeliverByOptions{Time: time.Duration(tc.seconds) * time.Second, Mode: tc.mode}})
		if (err != nil) != tc.fail {
			t.Errorf("minimum=%q seconds=%d mode=%s: error=%v, want failure=%v", tc.cap, tc.seconds, tc.mode, err, tc.fail)
		}
		if tc.fail && wrote.Len() != 0 {
			t.Errorf("refused MAIL wrote %q", wrote.String())
		}
		c.Close()
	}
}

// checklist: BY-SYN-01 BY-SYN-02 BY-SYN-03
func TestRFC2852CaseInsensitive(t *testing.T) {
	for _, mode := range []string{"N", "n", "R", "r"} {
		for _, trace := range []string{"", "T", "t"} {
			got := parseDeliverByArgument("+000000001;" + mode + trace)
			if got == nil || got.Time != time.Second || string(got.Mode) != strings.ToUpper(mode) || got.Trace != (trace != "") {
				t.Fatalf("mode=%q trace=%q: %+v", mode, trace, got)
			}
		}
	}
}
