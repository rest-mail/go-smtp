package server

import (
	"strings"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp/pkg/smtp"
)

type rfc2852Session struct {
	nopSession
	got chan *smtp.DeliverByOptions
}

func (s rfc2852Session) Mail(_ string, opts *smtp.MailOptions) error {
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
			got := make(chan *smtp.DeliverByOptions, 16)
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
				want smtp.DeliverByOptions
			}{
				{"120;R", smtp.DeliverByOptions{Time: 120 * time.Second, Mode: smtp.DeliverByReturn}},
				{"98;R", smtp.DeliverByOptions{Time: 98 * time.Second, Mode: smtp.DeliverByReturn}},
				{"30;rT", smtp.DeliverByOptions{Time: 30 * time.Second, Mode: smtp.DeliverByReturn, Trace: true}},
				{"0;n", smtp.DeliverByOptions{Mode: smtp.DeliverByNotify}},
				{"-999999999;nT", smtp.DeliverByOptions{Time: -999999999 * time.Second, Mode: smtp.DeliverByNotify, Trace: true}},
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
