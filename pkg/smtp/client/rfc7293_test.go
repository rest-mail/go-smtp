package client

import (
	"strings"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp/pkg/smtp"
)

// checklist: RRVS-CLI-01 RRVS-CLI-02 RRVS-CLI-03
func TestRFC7293Client(t *testing.T) {
	since := time.Date(2014, 4, 4, 1, 1, 0, 999999999, time.FixedZone("", 2*3600))
	c, _ := newMailParamClient("RRVS")
	for _, tc := range []struct {
		action smtp.RRVSAction
		want   string
	}{
		{"", "RCPT TO:<b@example.org> RRVS=2014-04-03T23:01:00Z"},
		{smtp.RRVSActionReject, "RCPT TO:<b@example.org> RRVS=2014-04-03T23:01:00Z;R"},
		{smtp.RRVSActionContinue, "RCPT TO:<b@example.org> RRVS=2014-04-03T23:01:00Z;C"},
	} {
		cmd, err := c.buildRcptCmd("b@example.org", &smtp.RcptOptions{
			RequireRecipientValidSince:       since,
			RequireRecipientValidSinceAction: tc.action,
		})
		if err != nil || cmd != tc.want {
			t.Errorf("action %q: %q, %v; want %q", tc.action, cmd, err, tc.want)
		}
		// TestRFC7293ServerAcceptsClientForms in the server package parses
		// these exact values.
	}
	if _, err := c.buildRcptCmd("b@example.org", &smtp.RcptOptions{
		RequireRecipientValidSince: since, RequireRecipientValidSinceAction: "X",
	}); err == nil {
		t.Error("unknown no-support action was sent")
	}
	if _, err := c.buildRcptCmd("b@example.org", &smtp.RcptOptions{
		RequireRecipientValidSince: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
	}); err == nil {
		t.Error("a five-digit year was sent")
	}
	c.Close()

	// Without RRVS on the next hop, only "C" lets the message go on, and
	// then without the parameter; otherwise nothing is written.
	c, wrote := newMailParamClient()
	for _, action := range []smtp.RRVSAction{"", smtp.RRVSActionReject} {
		err := c.Rcpt("b@example.org", &smtp.RcptOptions{
			RequireRecipientValidSince: since, RequireRecipientValidSinceAction: action,
		})
		if err == nil || !strings.Contains(err.Error(), "RRVS") {
			t.Errorf("action %q to a server without RRVS = %v", action, err)
		}
	}
	if wrote.Len() != 0 {
		t.Fatalf("refused RCPT wrote %q", wrote.String())
	}
	cmd, err := c.buildRcptCmd("b@example.org", &smtp.RcptOptions{
		RequireRecipientValidSince: since, RequireRecipientValidSinceAction: smtp.RRVSActionContinue,
	})
	if err != nil || cmd != "RCPT TO:<b@example.org>" {
		t.Errorf("continue to a server without RRVS: %q, %v", cmd, err)
	}
	c.Close()
}
