package client

import (
	"testing"
	"time"

	"github.com/rest-mail/go-smtp/pkg/smtp"
)

// checklist: BY-CLI-01 BY-CLI-02 BY-EXAMPLE-01
func TestRFC2852ClientMinimum(t *testing.T) {
	for _, tc := range []struct {
		cap     string
		seconds int
		mode    smtp.DeliverByMode
		fail    bool
	}{
		{"", 120, smtp.DeliverByReturn, false},
		{"240", 120, smtp.DeliverByReturn, true}, // RFC section 6's refused relay.
		{"30", 98, smtp.DeliverByReturn, false},  // RFC section 6's permitted relay.
		{"30", 30, smtp.DeliverByReturn, false},
		{"30,option", 29, smtp.DeliverByReturn, true},
		{",option", 1, smtp.DeliverByReturn, false},
		{"000000030", 29, smtp.DeliverByReturn, true},
		{"0", 1, smtp.DeliverByReturn, false},
		{"999999999", 999999999, smtp.DeliverByReturn, false},
		{"30", -1, smtp.DeliverByNotify, false},
		{"30", 0, smtp.DeliverByNotify, false},
		{"-1", 120, smtp.DeliverByReturn, true},
		{"+1", 120, smtp.DeliverByReturn, true},
		{"1000000000", 120, smtp.DeliverByReturn, true},
		{"１", 120, smtp.DeliverByReturn, true},
	} {
		c, wrote := newMailParamClient("DELIVERBY")
		c.ext["DELIVERBY"] = tc.cap
		err := c.Mail("eljefe@bigbiz.com", &smtp.MailOptions{DeliverBy: &smtp.DeliverByOptions{Time: time.Duration(tc.seconds) * time.Second, Mode: tc.mode}})
		if (err != nil) != tc.fail {
			t.Errorf("minimum=%q seconds=%d mode=%s: error=%v, want failure=%v", tc.cap, tc.seconds, tc.mode, err, tc.fail)
		}
		if tc.fail && wrote.Len() != 0 {
			t.Errorf("refused MAIL wrote %q", wrote.String())
		}
		c.Close()
	}
}
