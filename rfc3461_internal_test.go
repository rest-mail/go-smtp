package smtp

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// checklist: DSN-CLIENT-01 DSN-SYNTAX-01 DSN-SYNTAX-02 DSN-SYNTAX-03 DSN-SYNTAX-04 DSN-SYNTAX-05
func TestRFC3461ClientParameters(t *testing.T) {
	for _, tc := range []struct {
		name string
		mail *MailOptions
		rcpt *RcptOptions
		want string
		bad  bool
	}{
		{name: "mail xtext", mail: &MailOptions{Return: DSNReturnHeaders, EnvelopeID: "id +="}, want: "MAIL FROM:<a@example.org> RET=HDRS ENVID=id+20+2B+3D"},
		{name: "full", mail: &MailOptions{Return: DSNReturnFull}, want: "MAIL FROM:<a@example.org> RET=FULL"},
		{name: "notify and original", rcpt: &RcptOptions{Notify: []DSNNotify{DSNNotifySuccess, DSNNotifyFailure, DSNNotifyDelayed}, OriginalRecipientType: DSNAddressTypeRFC822, OriginalRecipient: "old+tag@example.org"}, want: "RCPT TO:<a@example.org> NOTIFY=SUCCESS,FAILURE,DELAY ORCPT=RFC822;old+2Btag@example.org"},
		{name: "repeat condition", rcpt: &RcptOptions{Notify: []DSNNotify{DSNNotifySuccess, DSNNotifySuccess}}, want: "RCPT TO:<a@example.org> NOTIFY=SUCCESS,SUCCESS"},
		{name: "never", rcpt: &RcptOptions{Notify: []DSNNotify{DSNNotifyNever}}, want: "RCPT TO:<a@example.org> NOTIFY=NEVER"},
		{name: "unknown return", mail: &MailOptions{Return: "NONE"}, bad: true},
		{name: "control envid", mail: &MailOptions{EnvelopeID: "a\n"}, bad: true},
		{name: "nonASCII envid", mail: &MailOptions{EnvelopeID: "é"}, bad: true},
		{name: "unknown notify", rcpt: &RcptOptions{Notify: []DSNNotify{"BOGUS"}}, bad: true},
		{name: "mixed never", rcpt: &RcptOptions{Notify: []DSNNotify{DSNNotifyNever, DSNNotifyFailure}}, bad: true},
		{name: "repeat never", rcpt: &RcptOptions{Notify: []DSNNotify{DSNNotifyNever, DSNNotifyNever}}, bad: true},
		{name: "empty API condition", rcpt: &RcptOptions{Notify: []DSNNotify{""}}, bad: true},
		{name: "control original", rcpt: &RcptOptions{OriginalRecipientType: DSNAddressTypeRFC822, OriginalRecipient: "a\x00b"}, bad: true},
		{name: "nonASCII original", rcpt: &RcptOptions{OriginalRecipientType: DSNAddressTypeRFC822, OriginalRecipient: "é"}, bad: true},
		{name: "unknown address type", rcpt: &RcptOptions{OriginalRecipientType: "OTHER", OriginalRecipient: "a"}, bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, wrote := newMailParamClient("DSN")
			defer c.Close()
			var err error
			if tc.mail != nil {
				err = c.Mail("a@example.org", tc.mail)
			} else {
				err = c.Rcpt("a@example.org", tc.rcpt)
			}
			if tc.bad {
				if err == nil || wrote.Len() != 0 {
					t.Fatalf("invalid options: err=%v wire=%q", err, wrote.String())
				}
			} else if err != nil || wrote.String() != tc.want+"\r\n" {
				t.Fatalf("err=%v wire=%q want=%q", err, wrote.String(), tc.want)
			}
		})
	}
	// A non-DSN peer must never receive DSN parameters. Downgrade/report policy
	// belongs to the caller; the current client silently omits these options.
	c, wrote := newMailParamClient()
	defer c.Close()
	if err := c.Mail("a@example.org", &MailOptions{Return: DSNReturnHeaders, EnvelopeID: "id"}); err != nil {
		t.Fatal(err)
	}
	if got := wrote.String(); got != "MAIL FROM:<a@example.org>\r\n" {
		t.Fatal(got)
	}
	c2, wrote2 := newMailParamClient()
	defer c2.Close()
	if err := c2.Rcpt("a@example.org", &RcptOptions{Notify: []DSNNotify{DSNNotifyNever}, OriginalRecipientType: DSNAddressTypeRFC822, OriginalRecipient: "a@example.org"}); err != nil {
		t.Fatal(err)
	}
	if got := wrote2.String(); got != "RCPT TO:<a@example.org>\r\n" {
		t.Fatal(got)
	}
}

// RFC 3461 section 4.1 uses RFC 822 section 2.7's 1# list: conditions
// can repeat and null elements do not count. NEVER is a separate alternative.
const notifyConditionGrammar = `[Ss][Uu][Cc][Cc][Ee][Ss][Ss]|[Ff][Aa][Ii][Ll][Uu][Rr][Ee]|[Dd][Ee][Ll][Aa][Yy]`

// Spell ASCII case pairs explicitly: regexp's (?i) also accepts Unicode long s.
var notifyGrammar = regexp.MustCompile(`^(?:[Nn][Ee][Vv][Ee][Rr]|,*(?:` +
	notifyConditionGrammar + `)(?:,+(?:` + notifyConditionGrammar + `))*,*)$`)

// checklist: DSN-SYNTAX-01 DSN-SYNTAX-02
func FuzzRFC3461Notify(f *testing.F) {
	for _, seed := range []string{"NEVER", "never", "SUCCESS", "sUcCeSs,failure,DELAY", "SUCCESS,SUCCESS", ",SUCCESS,,FAILURE,", "", ",,,", "NEVER,", "NEVER,NEVER", "NEVER,FAILURE", "SUCCESS,BOGUS", "SUCCESS\x00", "SUCCESS,\tFAILURE", "ſUCCESS", "SUCCESS，FAILURE"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire string) {
		if len(wire) > maxParserFuzzInput {
			t.Skip()
		}
		got, err := parseDSNNotify(wire)
		if valid := notifyGrammar.MatchString(wire); valid != (err == nil) {
			t.Fatalf("parseDSNNotify(%q)=%v,%v; grammar valid=%v", wire, got, err, valid)
		}
		if err != nil {
			return
		}
		if err := checkNotifySet(got); err != nil {
			t.Fatalf("invalid normalized API flags %v: %v", got, err)
		}
		seen := map[DSNNotify]bool{}
		upper := strings.ToUpper(wire)
		for _, flag := range got {
			if seen[flag] || !strings.Contains(upper, string(flag)) {
				t.Fatalf("unexpected or duplicate flag %q in %v", flag, got)
			}
			seen[flag] = true
		}
		for _, flag := range []DSNNotify{DSNNotifyNever, DSNNotifySuccess, DSNNotifyFailure, DSNNotifyDelayed} {
			if strings.Contains(upper, string(flag)) != seen[flag] {
				t.Fatalf("lost flag %q in %q: %v", flag, wire, got)
			}
		}
		canonical := make([]string, len(got))
		for i, flag := range got {
			canonical[i] = string(flag)
		}
		again, err := parseDSNNotify(strings.Join(canonical, ","))
		if err != nil || !reflect.DeepEqual(got, again) {
			t.Fatalf("normalization not stable: %v -> %v, %v", got, again, err)
		}
	})
}
