package smtp

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"strings"
	"testing"
)

// newScriptedClient returns a Client reading the given server replies in order
// and recording everything it writes.
func newScriptedClient(replies string) (*Client, *bytes.Buffer) {
	wrote := &bytes.Buffer{}
	var fake faker
	fake.ReadWriter = struct {
		io.Reader
		io.Writer
	}{
		strings.NewReader(replies),
		wrote,
	}
	return NewClient(fake), wrote
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

// A server that refuses the session in its greeting (RFC 5321 §3.1, 554) makes
// every later client call fail with that refusal; none of them sends a command.
//
// checklist: SMTP-CLI-03
func TestClientGreetingRefusedFailsEveryCall(t *testing.T) {
	c, wrote := newScriptedClient("554 5.3.2 no service\r\n")

	if ok, _ := c.Extension("PIPELINING"); ok {
		t.Error("Extension reported support after a refused greeting")
	}
	if c.SupportsAuth("PLAIN") {
		t.Error("SupportsAuth reported support after a refused greeting")
	}
	if _, ok := c.MaxMessageSize(); ok {
		t.Error("MaxMessageSize reported a size after a refused greeting")
	}
	calls := map[string]func() error{
		"Reset":    c.Reset,
		"Quit":     c.Quit,
		"Verify":   func() error { return c.Verify("user@example.org") },
		"Auth":     func() error { return c.Auth(toServerNoRespAuth{}) },
		"StartTLS": func() error { return c.startTLS(nil) },
		"Pipeline": func() error { _, err := c.Pipeline(); return err },
	}
	for name, call := range calls {
		var smtpErr *SMTPError
		if err := call(); !errors.As(err, &smtpErr) || smtpErr.Code != 554 {
			t.Errorf("%s: got %v, want the 554 greeting refusal", name, err)
		}
	}
	if wrote.Len() != 0 {
		t.Errorf("client sent %q after a refused greeting", wrote.String())
	}
}

// checklist: SMTP-CLI-03
func TestNewClientStartTLSGreetingRefused(t *testing.T) {
	var fake faker
	fake.ReadWriter = struct {
		io.Reader
		io.Writer
	}{strings.NewReader("554 no service\r\n"), ioutil.Discard}
	if c, err := NewClientStartTLS(fake, nil); err == nil || c != nil {
		t.Fatalf("NewClientStartTLS = %v, %v; want the greeting refusal", c, err)
	}
}

// checklist: SMTP-CLI-02 SIZE-EHLO-03
func TestClientSupportsAuthAndSizeFromEHLO(t *testing.T) {
	tests := []struct {
		name     string
		ehlo     string
		mech     string
		wantAuth bool
		wantSize int
		wantOK   bool
	}{
		{"no AUTH, no SIZE", "250 mx.example.org\r\n", "PLAIN", false, 0, false},
		{"other mechanism", "250-mx.example.org\r\n250 AUTH LOGIN PLAIN\r\n", "CRAM-MD5", false, 0, false},
		{"mechanism case-insensitive", "250-mx.example.org\r\n250 AUTH LOGIN PLAIN\r\n", "plain", true, 0, false},
		{"non-decimal SIZE", "250-mx.example.org\r\n250 SIZE 10M\r\n", "PLAIN", false, 0, false},
		{"SIZE overflows int", "250-mx.example.org\r\n250 SIZE 99999999999999999999999\r\n", "PLAIN", false, 0, false},
		{"SIZE 0 is unlimited", "250-mx.example.org\r\n250 SIZE 0\r\n", "PLAIN", false, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newScriptedClient("220 mx.example.org\r\n" + tt.ehlo)
			if got := c.SupportsAuth(tt.mech); got != tt.wantAuth {
				t.Errorf("SupportsAuth(%q) = %v, want %v", tt.mech, got, tt.wantAuth)
			}
			if size, ok := c.MaxMessageSize(); size != tt.wantSize || ok != tt.wantOK {
				t.Errorf("MaxMessageSize() = %d, %v; want %d, %v", size, ok, tt.wantSize, tt.wantOK)
			}
		})
	}
}

// A refused RSET or QUIT is returned as the server's error; Quit then leaves
// the connection to Close.
//
// checklist: SMTP-CLI-03
func TestClientResetAndQuitRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(*Client) error
		cmd  string
	}{
		{"RSET", (*Client).Reset, "RSET\r\n"},
		{"QUIT", (*Client).Quit, "QUIT\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, wrote := newScriptedClient("220 mx\r\n250 mx\r\n502 5.5.1 not today\r\n")
			var smtpErr *SMTPError
			err := tc.call(c)
			if !errors.As(err, &smtpErr) || smtpErr.Code != 502 || smtpErr.EnhancedCode != (EnhancedCode{5, 5, 1}) {
				t.Fatalf("got %v, want the 502 5.5.1 reply", err)
			}
			if !strings.HasSuffix(wrote.String(), tc.cmd) {
				t.Errorf("last command %q, want %q", wrote.String(), tc.cmd)
			}
		})
	}
}

// checklist: SMTP-CLI-03
func TestClientSendMailStopsAtFirstFailure(t *testing.T) {
	const hello = "220 mx\r\n250 mx\r\n"
	tests := []struct {
		name    string
		replies string
		body    io.Reader
		wantErr func(error) bool
		notSent string
	}{
		{
			name:    "RCPT refused",
			replies: hello + "250 ok\r\n550 5.1.1 no such user\r\n",
			body:    strings.NewReader("hi\r\n"),
			wantErr: isSMTPCode(550),
			notSent: "DATA",
		},
		{
			name:    "DATA refused",
			replies: hello + "250 ok\r\n250 ok\r\n554 5.5.0 no valid recipients\r\n",
			body:    strings.NewReader("hi\r\n"),
			wantErr: isSMTPCode(554),
			notSent: "hi",
		},
		{
			name:    "message read fails",
			replies: hello + "250 ok\r\n250 ok\r\n354 go ahead\r\n",
			body:    failingReader{errors.New("disk gone")},
			wantErr: func(err error) bool { return err != nil && err.Error() == "disk gone" },
			notSent: "\r\n.\r\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, wrote := newScriptedClient(tt.replies)
			err := c.SendMail("a@example.org", []string{"b@example.org"}, tt.body)
			if !tt.wantErr(err) {
				t.Fatalf("SendMail = %v", err)
			}
			if strings.Contains(wrote.String(), tt.notSent) {
				t.Errorf("client sent %q after the failure:\n%s", tt.notSent, wrote.String())
			}
		})
	}
}

func isSMTPCode(code int) func(error) bool {
	return func(err error) bool {
		var smtpErr *SMTPError
		return errors.As(err, &smtpErr) && smtpErr.Code == code
	}
}

// RFC 8689 §4.1: REQUIRETLS is only sent to a server that advertised it.
//
// checklist: SMTP-CLI-07
func TestClientMailRequireTLS(t *testing.T) {
	c, wrote := newMailParamClient("REQUIRETLS")
	if err := c.Mail("a@example.org", &MailOptions{RequireTLS: true}); err != nil {
		t.Fatalf("Mail: %v", err)
	}
	if got, want := wrote.String(), "MAIL FROM:<a@example.org> REQUIRETLS\r\n"; got != want {
		t.Errorf("sent %q, want %q", got, want)
	}

	c, wrote = newMailParamClient()
	if err := c.Mail("a@example.org", &MailOptions{RequireTLS: true}); err == nil {
		t.Error("Mail with REQUIRETLS succeeded against a server that did not advertise it")
	}
	if wrote.Len() != 0 {
		t.Errorf("sent %q, want nothing", wrote.String())
	}
}

// checklist: PIPE-CLIENT-01
func TestPipelinerRejectsBeforeSending(t *testing.T) {
	c, wrote := newMailParamClient()
	if _, err := c.Pipeline(); err == nil {
		t.Error("Pipeline succeeded without PIPELINING advertised")
	}

	c, wrote = newMailParamClient("PIPELINING")
	p, err := c.Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if errs := p.Wait(); errs != nil {
		t.Errorf("Wait with nothing queued = %v, want nil", errs)
	}
	if err := p.Mail("a@example.org\r\nRSET", nil); err == nil {
		t.Error("Mail accepted a CRLF in the reverse-path")
	}
	if err := p.Rcpt("b@example.org\nRSET", nil); err == nil {
		t.Error("Rcpt accepted a LF in the forward-path")
	}
	if wrote.Len() != 0 {
		t.Errorf("sent %q, want nothing", wrote.String())
	}
}

// RFC 3463 §2: an enhanced code is three dot-separated numbers; anything else
// is left in the message text rather than misparsed.
//
// checklist: SMTP-CLI-03
func TestToSMTPErrMalformedEnhancedCode(t *testing.T) {
	for _, code := range []string{"5.x.1", "5.1", "5.1.1.1"} {
		if _, err := parseEnhancedCode(code); err == nil {
			t.Errorf("parseEnhancedCode(%q) succeeded", code)
		}
	}
	c, _ := newScriptedClient("220 mx\r\n250 mx\r\n550 5.x.1 odd\r\n")
	err := c.Noop()
	var smtpErr *SMTPError
	if !errors.As(err, &smtpErr) || smtpErr.EnhancedCode != (EnhancedCode{}) || smtpErr.Message != "5.x.1 odd" {
		t.Fatalf("got %#v, want code 550 with the text kept verbatim", err)
	}
}
