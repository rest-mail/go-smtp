package smtp

import (
	"strings"
	"testing"
	"time"
)

// checklist: RRVS-SYN-01 RRVS-SYN-02 RRVS-SYN-03
func TestRFC7293ParseArgument(t *testing.T) {
	utc := func(y int, mo time.Month, d, h, mi, s int) time.Time {
		return time.Date(y, mo, d, h, mi, s, 0, time.UTC)
	}
	valid := []struct {
		arg    string
		since  time.Time
		action RRVSAction
	}{
		{"2014-04-03T23:01:00Z", utc(2014, 4, 3, 23, 1, 0), ""},
		{"2014-04-03t23:01:00z", utc(2014, 4, 3, 23, 1, 0), ""},
		{"2014-04-03T23:01:00+02:30", utc(2014, 4, 3, 20, 31, 0), ""},
		{"2014-04-03T23:01:00-00:00", utc(2014, 4, 3, 23, 1, 0), ""},
		{"2014-04-03T23:01:00-23:59", utc(2014, 4, 4, 23, 0, 0), ""},
		{"2016-12-31T23:59:60Z", utc(2017, 1, 1, 0, 0, 0), ""},
		{"2014-04-03T23:01:00Z;C", utc(2014, 4, 3, 23, 1, 0), RRVSActionContinue},
		{"2014-04-03T23:01:00Z;R", utc(2014, 4, 3, 23, 1, 0), RRVSActionReject},
		{"2014-04-03T23:01:00Z;c", utc(2014, 4, 3, 23, 1, 0), RRVSActionContinue},
		{"2014-04-03T23:01:00Z;r", utc(2014, 4, 3, 23, 1, 0), RRVSActionReject},
	}
	for _, tc := range valid {
		since, action, ok := parseRRVSArgument(tc.arg)
		if !ok || !since.Equal(tc.since) || since.Location() != time.UTC || action != tc.action {
			t.Errorf("parseRRVSArgument(%q) = %v, %q, %v; want %v, %q, true", tc.arg, since, action, ok, tc.since, tc.action)
		}
	}
	invalid := []string{
		"",
		"1234",
		"2014-04-03T23:01:00.5Z",    // time-secfrac is forbidden
		"2014-04-03T23:01:00.000Z",  // even when zero
		"2014-04-03T23:01Z",         // seconds are required
		"2014-04-03 23:01:00Z",      // the T separator is required
		"2014-04-03T23:01:00",       // the offset is required
		"2014-04-03T23:01:00+0200",  // the offset has a colon
		"2014-04-03T23:01:00+24:00", // offset hour out of range
		"2014-04-03T23:01:00+02:60", // offset minute out of range
		"2014-02-30T23:01:00Z",      // no such day
		"2014-13-03T23:01:00Z",
		"2014-04-03T24:00:00Z",
		"2014-04-03T23:60:00Z",
		"2014-04-03T23:01:61Z",
		"14-04-03T23:01:00Z",
		"２014-04-03T23:01:00Z",
		"2014-04-03T23:01:00Z;",
		"2014-04-03T23:01:00Z;X",
		"2014-04-03T23:01:00Z;CR",
		"2014-04-03T23:01:00Z;C;R",
		"2020-03-19T11:13:00Z;ign0r3.th1s;othr_stuff",
		";C",
	}
	for _, arg := range invalid {
		if since, action, ok := parseRRVSArgument(arg); ok {
			t.Errorf("parseRRVSArgument(%q) = %v, %q, true; want malformed", arg, since, action)
		}
	}
}

type rfc7293Session struct {
	nopSession
	got chan *RcptOptions
}

func (s rfc7293Session) Rcpt(_ string, opts *RcptOptions) error {
	s.got <- opts
	return nil
}

// checklist: RRVS-EHLO-01 RRVS-SRV-01 RRVS-SRV-02 RRVS-SYN-01 RRVS-SYN-02
func TestRFC7293Server(t *testing.T) {
	for _, enable := range []bool{true, false} {
		got := make(chan *RcptOptions, 8)
		_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
			s.EnableRRVS = enable
			s.Backend = BackendFunc(func(*Conn) (Session, error) { return rfc7293Session{got: got}, nil })
		})
		command := func(command, want string) []string {
			t.Helper()
			writeFlushBatch(t, raw, command+"\r\n")
			reply := readFlushReply(t, br)
			if !strings.HasPrefix(reply[0], want) {
				t.Fatalf("enable=%v: %q reply = %q, want %s", enable, command, reply, want)
			}
			return reply
		}
		var rrvs int
		for _, cap := range command("EHLO client.example", "250") {
			if strings.HasPrefix(strings.ToUpper(cap[4:]), "RRVS") {
				rrvs++
				if cap[4:] != "RRVS" {
					t.Fatalf("parameter on RRVS advertisement: %q", cap)
				}
			}
		}
		if want := map[bool]int{true: 1, false: 0}[enable]; rrvs != want {
			t.Fatalf("enable=%v: RRVS advertisements = %d, want %d", enable, rrvs, want)
		}
		command("MAIL FROM:<a@example.org>", "250")
		if !enable {
			command("RCPT TO:<b@example.org> RRVS=2014-04-03T23:01:00Z", "504 5.5.4")
			continue
		}
		command("RCPT TO:<b@example.org> RRVS=2014-04-03T23:01:00.5Z", "501 5.5.4")
		command("RCPT TO:<b@example.org> RRVS=2014-04-03T23:01:00Z;X", "501 5.5.4")
		command("RCPT TO:<b@example.org> rrvs=2014-04-03T23:01:00+01:00;c", "250")
		opts := <-got
		if !opts.RequireRecipientValidSince.Equal(time.Date(2014, 4, 3, 22, 1, 0, 0, time.UTC)) ||
			opts.RequireRecipientValidSinceAction != RRVSActionContinue {
			t.Fatalf("backend saw %v, %q", opts.RequireRecipientValidSince, opts.RequireRecipientValidSinceAction)
		}
		// An absent action stays absent, so a relay can preserve it as sent.
		command("RCPT TO:<c@example.org> RRVS=2014-04-03T23:01:00Z", "250")
		if opts := <-got; opts.RequireRecipientValidSinceAction != "" {
			t.Fatalf("absent action reached the backend as %q", opts.RequireRecipientValidSinceAction)
		}
		command("RCPT TO:<d@example.org>", "250")
		if opts := <-got; !opts.RequireRecipientValidSince.IsZero() {
			t.Fatalf("RCPT without RRVS carried %v", opts.RequireRecipientValidSince)
		}
	}
}

// checklist: RRVS-CLI-01 RRVS-CLI-02 RRVS-CLI-03
func TestRFC7293Client(t *testing.T) {
	since := time.Date(2014, 4, 4, 1, 1, 0, 999999999, time.FixedZone("", 2*3600))
	c, _ := newMailParamClient("RRVS")
	for _, tc := range []struct {
		action RRVSAction
		want   string
	}{
		{"", "RCPT TO:<b@example.org> RRVS=2014-04-03T23:01:00Z"},
		{RRVSActionReject, "RCPT TO:<b@example.org> RRVS=2014-04-03T23:01:00Z;R"},
		{RRVSActionContinue, "RCPT TO:<b@example.org> RRVS=2014-04-03T23:01:00Z;C"},
	} {
		cmd, err := c.buildRcptCmd("b@example.org", &RcptOptions{
			RequireRecipientValidSince:       since,
			RequireRecipientValidSinceAction: tc.action,
		})
		if err != nil || cmd != tc.want {
			t.Errorf("action %q: %q, %v; want %q", tc.action, cmd, err, tc.want)
		}
		if _, _, ok := parseRRVSArgument(strings.TrimPrefix(cmd, "RCPT TO:<b@example.org> RRVS=")); !ok {
			t.Errorf("server refuses the client's own %q", cmd)
		}
	}
	if _, err := c.buildRcptCmd("b@example.org", &RcptOptions{
		RequireRecipientValidSince: since, RequireRecipientValidSinceAction: "X",
	}); err == nil {
		t.Error("unknown no-support action was sent")
	}
	if _, err := c.buildRcptCmd("b@example.org", &RcptOptions{
		RequireRecipientValidSince: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
	}); err == nil {
		t.Error("a five-digit year was sent")
	}
	c.Close()

	// Without RRVS on the next hop, only "C" lets the message go on, and
	// then without the parameter; otherwise nothing is written.
	c, wrote := newMailParamClient()
	for _, action := range []RRVSAction{"", RRVSActionReject} {
		err := c.Rcpt("b@example.org", &RcptOptions{
			RequireRecipientValidSince: since, RequireRecipientValidSinceAction: action,
		})
		if err == nil || !strings.Contains(err.Error(), "RRVS") {
			t.Errorf("action %q to a server without RRVS = %v", action, err)
		}
	}
	if wrote.Len() != 0 {
		t.Fatalf("refused RCPT wrote %q", wrote.String())
	}
	cmd, err := c.buildRcptCmd("b@example.org", &RcptOptions{
		RequireRecipientValidSince: since, RequireRecipientValidSinceAction: RRVSActionContinue,
	})
	if err != nil || cmd != "RCPT TO:<b@example.org>" {
		t.Errorf("continue to a server without RRVS: %q, %v", cmd, err)
	}
	c.Close()
}
