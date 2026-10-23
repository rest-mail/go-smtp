package server

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/rest-mail/go-smtp/pkg/smtp"
	"github.com/rest-mail/go-smtp/pkg/smtp/client"
)

// rfc4954MailSession records the MAIL AUTH= value handed to the host.
type rfc4954MailSession struct {
	rfc4954Session
	calls int
	auth  *string
	set   bool
}

func (s *rfc4954MailSession) Mail(_ string, opts *smtp.MailOptions) error {
	s.calls++
	s.set = opts.Auth != nil
	if s.set {
		v := *opts.Auth
		s.auth = &v
	}
	return nil
}

func rfc4954MailServer(t *testing.T, sess *rfc4954MailSession) func(string) string {
	t.Helper()
	_, c, br := newConformanceServer(t, func(s *Server) {
		s.AllowInsecureAuth = true
		s.Backend = BackendFunc(func(*Conn) (Session, error) { return sess, nil })
	})
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	drainEHLO(t, c, br)
	return func(cmd string) string {
		t.Helper()
		writeCmd(t, c, cmd+"\r\n")
		return readSMTPLine(t, br)
	}
}

// RFC 4954 §5: the AUTH= value is xtext whose decoded form is an addr-spec or
// "<>". The host receives the decoded mailbox, an empty string for <>, and
// nil when the parameter is absent, whether or not the client authenticated.
// checklist: SMTP-AUTH-26 SMTP-AUTH-27
func TestRFC4954_MailAuthParameter(t *testing.T) {
	str := func(s string) *string { return &s }
	cases := []struct {
		param string
		want  *string
	}{
		{"", nil},
		{" AUTH=<>", str("")},
		{" auth=<>", str("")},
		{" AUTH=+3C+3E", str("")},
		{" AUTH=e+3Dmc2@example.com", str("e=mc2@example.com")},
		{" AUTH=user+2Btag@example.com", str("user+tag@example.com")},
		// Like the reverse-path, a quoted local-part reaches the host unquoted.
		{" AUTH=\"john+20doe\"@example.com", str("john doe@example.com")},
		{" AUTH=postmaster@[192.0.2.1]", str("postmaster@[192.0.2.1]")},
	}
	for _, authenticated := range []bool{false, true} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%t/%q", authenticated, tc.param), func(t *testing.T) {
				sess := &rfc4954MailSession{}
				send := rfc4954MailServer(t, sess)
				if authenticated {
					if got := send("AUTH PLAIN dGVzdAB0ZXN0ADEyMzQ="); !strings.HasPrefix(got, "235 ") {
						t.Fatal(got)
					}
				}
				if got := send("MAIL FROM:<a@example.org>" + tc.param); !strings.HasPrefix(got, "250 ") {
					t.Fatalf("MAIL = %q", got)
				}
				if sess.calls != 1 {
					t.Fatalf("Mail calls = %d", sess.calls)
				}
				switch {
				case tc.want == nil && sess.set:
					t.Fatalf("Auth = %q, want nil", *sess.auth)
				case tc.want != nil && !sess.set:
					t.Fatalf("Auth = nil, want %q", *tc.want)
				case tc.want != nil && *sess.auth != *tc.want:
					t.Fatalf("Auth = %q, want %q", *sess.auth, *tc.want)
				}
			})
		}
	}
}

// RFC 4954 §5 and RFC 5321 §4.2.2: an AUTH= value that is not xtext, or whose
// decoded form is neither an addr-spec nor "<>", is a parameter syntax error.
// It is refused with 501 before the host sees MAIL, and the session goes on.
// checklist: SMTP-AUTH-28
func TestRFC4954_MailAuthMalformed(t *testing.T) {
	for _, param := range []string{
		"AUTH=",
		"AUTH",
		"AUTH=+ZZ",
		"AUTH=+3",
		"AUTH=a+0",
		"AUTH=not-a-mailbox",
		"AUTH=<a@example.com>",
		"AUTH=a@example.com+20x",
		"AUTH=+3C+3E+3E",
		"AUTH=@example.com",
	} {
		t.Run(param, func(t *testing.T) {
			sess := &rfc4954MailSession{}
			send := rfc4954MailServer(t, sess)
			if got := send("MAIL FROM:<a@example.org> " + param); !strings.HasPrefix(got, "501 5.5.4 ") {
				t.Fatalf("MAIL = %q, want 501 5.5.4", got)
			}
			if sess.calls != 0 {
				t.Fatalf("Mail called %d times for a malformed AUTH=", sess.calls)
			}
			if got := send("MAIL FROM:<a@example.org> AUTH=<>"); !strings.HasPrefix(got, "250 ") {
				t.Fatalf("retry MAIL = %q", got)
			}
		})
	}
}

// rfc4954Failing is a host mechanism whose first step fails with err.
type rfc4954Failing struct{ err error }

func (m rfc4954Failing) Next([]byte) ([]byte, bool, error) { return nil, false, m.err }

type rfc4954FailSession struct {
	rfc4954Session
	start, step error
}

func (s rfc4954FailSession) Auth(mech string) (sasl.Server, error) {
	switch mech {
	case "START":
		return nil, s.start
	case "STEP":
		return rfc4954Failing{s.step}, nil
	}
	return s.rfc4954Session.Auth(mech)
}

// RFC 4954 §6: the host chooses the failure reply. A coded SMTPError from the
// mechanism factory or a SASL step reaches the wire unchanged (534 5.7.9,
// 538 5.7.11, 535 5.7.8, 530 5.7.0); an uncoded error is the temporary
// 454 4.7.0. Neither closes the session: a later AUTH still succeeds.
// checklist: SMTP-AUTH-29
func TestRFC4954_HostFailureCodes(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{&smtp.SMTPError{Code: 534, EnhancedCode: smtp.EnhancedCode{5, 7, 9}, Message: "Authentication mechanism is too weak"}, "534 5.7.9 Authentication mechanism is too weak"},
		{&smtp.SMTPError{Code: 538, EnhancedCode: smtp.EnhancedCode{5, 7, 11}, Message: "Encryption required for requested authentication mechanism"}, "538 5.7.11 Encryption required for requested authentication mechanism"},
		{ErrAuthFailed, "535 5.7.8 Authentication failed"},
		{ErrAuthRequired, "530 5.7.0 Please authenticate first"},
		{fmt.Errorf("wrapped: %w", &smtp.SMTPError{Code: 534, EnhancedCode: smtp.EnhancedCode{5, 7, 9}, Message: "weak"}), "534 5.7.9 weak"},
		{errors.New("directory unavailable"), "454 4.7.0 directory unavailable"},
	}
	for _, where := range []string{"START", "STEP"} {
		for _, tc := range cases {
			t.Run(where+"/"+tc.want, func(t *testing.T) {
				fs := rfc4954FailSession{}
				if where == "START" {
					fs.start = tc.err
				} else {
					fs.step = tc.err
				}
				_, c, br := newConformanceServer(t, func(s *Server) {
					s.AllowInsecureAuth = true
					s.Backend = BackendFunc(func(*Conn) (Session, error) { return fs, nil })
				})
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				drainEHLO(t, c, br)
				writeCmd(t, c, "AUTH "+where+" =\r\n")
				if got := readSMTPLine(t, br); got != tc.want {
					t.Fatalf("got %q, want %q", got, tc.want)
				}
				writeCmd(t, c, "AUTH PLAIN dGVzdAB0ZXN0ADEyMzQ=\r\n")
				if got := readSMTPLine(t, br); !strings.HasPrefix(got, "235 2.7.0 ") {
					t.Fatalf("retry = %q", got)
				}
			})
		}
	}
}

// RFC 4954 §5: the decoded AUTH= value round-trips from client to server:
// what the client asserts is exactly what the host receives.
// checklist: SMTP-AUTH-27 SMTP-AUTH-30
func TestRFC4954_MailAuthRoundTrip(t *testing.T) {
	for _, auth := range []string{"", "e=mc2@example.com", "user+tag@example.com", "o'brien.x@[192.0.2.1]"} {
		t.Run(auth, func(t *testing.T) {
			sess := &rfc4954MailSession{}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			s := New(BackendFunc(func(*Conn) (Session, error) { return sess, nil }))
			s.Domain = "localhost"
			s.AllowInsecureAuth = true
			go func() { _ = s.Serve(ln) }()
			t.Cleanup(func() { _ = s.Close() })
			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			cl := client.New(conn)
			defer cl.Close()
			a := auth
			if err := cl.Mail("a@example.org", &smtp.MailOptions{Auth: &a}); err != nil {
				t.Fatal(err)
			}
			if !sess.set || *sess.auth != auth {
				t.Fatalf("host got set=%t auth=%v, want %q", sess.set, sess.auth, auth)
			}
		})
	}
}
