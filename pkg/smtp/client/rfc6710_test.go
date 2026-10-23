package client

import (
	"fmt"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp/pkg/smtp"
)

// checklist: PRI-CLI-01 PRI-CLI-02 PRI-EXAMPLE-01
func TestRFC6710Client(t *testing.T) {
	for _, profile := range []string{"", "MIXER", "STANAG4406", "unknown-policy"} {
		for priority := -9; priority <= 9; priority++ {
			c, wrote := newMailParamClient("MT-PRIORITY")
			c.ext["MT-PRIORITY"] = profile
			err := c.Mail("eljefe@example.com", &smtp.MailOptions{MTPriority: &priority})
			c.Close()
			want := fmt.Sprintf("MAIL FROM:<eljefe@example.com> MT-PRIORITY=%d\r\n", priority)
			if err != nil || wrote.String() != want {
				t.Fatalf("profile %q priority %d: %v, %q", profile, priority, err, wrote.String())
			}
		}
	}
	for _, priority := range []int{-10, 10} {
		c, wrote := newMailParamClient("MT-PRIORITY")
		err := c.Mail("a@example.org", &smtp.MailOptions{MTPriority: &priority})
		c.Close()
		if err == nil || wrote.Len() != 0 {
			t.Fatalf("invalid priority %d: err=%v wire=%q", priority, err, wrote.String())
		}
	}
	p := 3
	c, wrote := newMailParamClient()
	defer c.Close()
	if err := c.Mail("a@example.org", &smtp.MailOptions{MTPriority: &p}); err == nil || wrote.Len() != 0 {
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
		err := c.Mail("eljefe@example.com", &smtp.MailOptions{MTPriority: &priority, DeliverBy: &smtp.DeliverByOptions{Time: time.Duration(seconds) * time.Second, Mode: smtp.DeliverByReturn}, EnvelopeID: "QQ314159"})
		c.Close()
		want := fmt.Sprintf("MAIL FROM:<eljefe@example.com> ENVID=QQ314159 BY=%d;R MT-PRIORITY=3\r\n", seconds)
		if err != nil || wrote.String() != want {
			t.Fatalf("example: err=%v wire=%q, want %q", err, wrote.String(), want)
		}
	}
}
