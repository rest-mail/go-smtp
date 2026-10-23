package client

import (
	"testing"

	"github.com/rest-mail/go-smtp/pkg/smtp"
)

// checklist: DSN-CLIENT-01 DSN-SYNTAX-01 DSN-SYNTAX-02 DSN-SYNTAX-03 DSN-SYNTAX-04 DSN-SYNTAX-05
func TestRFC3461ClientParameters(t *testing.T) {
	for _, tc := range []struct {
		name string
		mail *smtp.MailOptions
		rcpt *smtp.RcptOptions
		want string
		bad  bool
	}{
		{name: "mail xtext", mail: &smtp.MailOptions{Return: smtp.DSNReturnHeaders, EnvelopeID: "id +="}, want: "MAIL FROM:<a@example.org> RET=HDRS ENVID=id+20+2B+3D"},
		{name: "full", mail: &smtp.MailOptions{Return: smtp.DSNReturnFull}, want: "MAIL FROM:<a@example.org> RET=FULL"},
		{name: "notify and original", rcpt: &smtp.RcptOptions{Notify: []smtp.DSNNotify{smtp.DSNNotifySuccess, smtp.DSNNotifyFailure, smtp.DSNNotifyDelayed}, OriginalRecipientType: smtp.DSNAddressTypeRFC822, OriginalRecipient: "old+tag@example.org"}, want: "RCPT TO:<a@example.org> NOTIFY=SUCCESS,FAILURE,DELAY ORCPT=RFC822;old+2Btag@example.org"},
		{name: "repeat condition", rcpt: &smtp.RcptOptions{Notify: []smtp.DSNNotify{smtp.DSNNotifySuccess, smtp.DSNNotifySuccess}}, want: "RCPT TO:<a@example.org> NOTIFY=SUCCESS,SUCCESS"},
		{name: "never", rcpt: &smtp.RcptOptions{Notify: []smtp.DSNNotify{smtp.DSNNotifyNever}}, want: "RCPT TO:<a@example.org> NOTIFY=NEVER"},
		{name: "unknown return", mail: &smtp.MailOptions{Return: "NONE"}, bad: true},
		{name: "control envid", mail: &smtp.MailOptions{EnvelopeID: "a\n"}, bad: true},
		{name: "nonASCII envid", mail: &smtp.MailOptions{EnvelopeID: "é"}, bad: true},
		{name: "unknown notify", rcpt: &smtp.RcptOptions{Notify: []smtp.DSNNotify{"BOGUS"}}, bad: true},
		{name: "mixed never", rcpt: &smtp.RcptOptions{Notify: []smtp.DSNNotify{smtp.DSNNotifyNever, smtp.DSNNotifyFailure}}, bad: true},
		{name: "repeat never", rcpt: &smtp.RcptOptions{Notify: []smtp.DSNNotify{smtp.DSNNotifyNever, smtp.DSNNotifyNever}}, bad: true},
		{name: "empty API condition", rcpt: &smtp.RcptOptions{Notify: []smtp.DSNNotify{""}}, bad: true},
		{name: "control original", rcpt: &smtp.RcptOptions{OriginalRecipientType: smtp.DSNAddressTypeRFC822, OriginalRecipient: "a\x00b"}, bad: true},
		{name: "nonASCII original", rcpt: &smtp.RcptOptions{OriginalRecipientType: smtp.DSNAddressTypeRFC822, OriginalRecipient: "é"}, bad: true},
		{name: "unknown address type", rcpt: &smtp.RcptOptions{OriginalRecipientType: "OTHER", OriginalRecipient: "a"}, bad: true},
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
	if err := c.Mail("a@example.org", &smtp.MailOptions{Return: smtp.DSNReturnHeaders, EnvelopeID: "id"}); err != nil {
		t.Fatal(err)
	}
	if got := wrote.String(); got != "MAIL FROM:<a@example.org>\r\n" {
		t.Fatal(got)
	}
	c2, wrote2 := newMailParamClient()
	defer c2.Close()
	if err := c2.Rcpt("a@example.org", &smtp.RcptOptions{Notify: []smtp.DSNNotify{smtp.DSNNotifyNever}, OriginalRecipientType: smtp.DSNAddressTypeRFC822, OriginalRecipient: "a@example.org"}); err != nil {
		t.Fatal(err)
	}
	if got := wrote2.String(); got != "RCPT TO:<a@example.org>\r\n" {
		t.Fatal(got)
	}
}
