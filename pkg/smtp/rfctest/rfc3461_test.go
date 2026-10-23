package rfctest

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp/pkg/smtp"
	"github.com/rest-mail/go-smtp/pkg/smtp/server"
)

// checklist: DSN-EHLO-01 DSN-SYNTAX-01 DSN-SYNTAX-02 DSN-SYNTAX-03 DSN-SYNTAX-04 DSN-SYNTAX-05 DSN-SYNTAX-06 DSN-REPLY-01 DSN-STATE-01
func TestRFC3461Parameters(t *testing.T) {
	for _, tc := range []struct {
		name, mail, rcpt, code string
		notify                 []smtp.DSNNotify
		envid, original        string
		ret                    smtp.DSNReturn
	}{
		{name: "defaults", code: "250 "},
		{name: "case and xtext", mail: " envID=(id)+20+2B+3D Ret=hDrS", rcpt: " ORcpt=rFc822;original+2Btag@example.org Notify=sUcCeSs,fAiLuRe,dElAy", code: "250 ", notify: []smtp.DSNNotify{smtp.DSNNotifySuccess, smtp.DSNNotifyFailure, smtp.DSNNotifyDelayed}, envid: "(id) +=", original: "original+tag@example.org", ret: smtp.DSNReturnHeaders},
		{name: "full and never", mail: " RET=FULL", rcpt: " NOTIFY=NEVER", code: "250 ", notify: []smtp.DSNNotify{smtp.DSNNotifyNever}, ret: smtp.DSNReturnFull},
		{name: "repeated conditions", rcpt: " NOTIFY=SUCCESS,SUCCESS,FAILURE,DELAY,FAILURE", code: "250 ", notify: []smtp.DSNNotify{smtp.DSNNotifySuccess, smtp.DSNNotifyFailure, smtp.DSNNotifyDelayed}},
		{name: "null list elements", rcpt: " NOTIFY=,SUCCESS,,FAILURE,", code: "250 ", notify: []smtp.DSNNotify{smtp.DSNNotifySuccess, smtp.DSNNotifyFailure}},
		{name: "opaque original", rcpt: " ORCPT=rfc822;not+20a+20mailbox", code: "250 ", original: "not a mailbox"},
		{name: "missing RET value", mail: " RET", code: "501 "},
		{name: "nonASCII RET", mail: " RET=HDRſ", code: "501 "},
		{name: "nonASCII NOTIFY", rcpt: " NOTIFY=ſUCCESS", code: "501 "},
		{name: "unknown RET", mail: " RET=NONE", code: "501 "},
		{name: "duplicate RET", mail: " RET=FULL ret=HDRS", code: "501 "},
		{name: "empty ENVID", mail: " ENVID=", code: "501 "},
		{name: "duplicate ENVID", mail: " ENVID=one envid=two", code: "501 "},
		{name: "malformed ENVID xtext", mail: " ENVID=abc+G0", code: "501 "},
		{name: "literal equals", mail: " ENVID=a=b", code: "501 "},
		{name: "decoded control ENVID", mail: " ENVID=id+09", code: "501 "},
		{name: "decoded nonASCII ENVID", mail: " ENVID=id+FF", code: "501 "},
		{name: "missing NOTIFY value", rcpt: " NOTIFY", code: "501 "},
		{name: "empty list", rcpt: " NOTIFY=,,,", code: "501 "},
		{name: "unknown NOTIFY", rcpt: " NOTIFY=SUCCESS,BOGUS", code: "501 "},
		{name: "NEVER with condition", rcpt: " NOTIFY=NEVER,FAILURE", code: "501 "},
		{name: "repeated NEVER", rcpt: " NOTIFY=NEVER,NEVER", code: "501 "},
		{name: "NEVER with null element", rcpt: " NOTIFY=NEVER,", code: "501 "},
		{name: "duplicate NOTIFY", rcpt: " NOTIFY=SUCCESS notify=FAILURE", code: "501 "},
		{name: "empty ORCPT", rcpt: " ORCPT=", code: "501 "},
		{name: "missing original address", rcpt: " ORCPT=rfc822;", code: "501 "},
		{name: "missing address type", rcpt: " ORCPT=;b@example.org", code: "501 "},
		{name: "missing separator", rcpt: " ORCPT=rfc822", code: "501 "},
		{name: "decoded control ORCPT", rcpt: " ORCPT=rfc822;a+00b", code: "501 "},
		{name: "decoded nonASCII ORCPT", rcpt: " ORCPT=rfc822;a+FFb", code: "501 "},
		{name: "malformed ORCPT xtext", rcpt: " ORCPT=rfc822;a+0", code: "501 "},
		{name: "duplicate ORCPT", rcpt: " ORCPT=rfc822;a orcpt=rfc822;b", code: "501 "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			be, s, c, scanner, caps := testServerEhlo(t, func(s *server.Server) { s.EnableDSN = true })
			defer s.Close()
			defer c.Close()
			if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if !caps["DSN"] {
				t.Fatal("missing parameterless DSN capability")
			}
			next := func() string { scanner.Scan(); return scanner.Text() }
			mailCode := "250 "
			if tc.mail != "" && tc.code != "250 " {
				mailCode = tc.code
			}
			expectReply(t, c, next, "MAIL FROM:<sender@example.org>"+tc.mail+"\r\n", mailCode)
			if mailCode != "250 " {
				expectReply(t, c, next, "MAIL FROM:<sender@example.org>\r\n", "250 ")
			} else {
				expectReply(t, c, next, "RCPT TO:<actual@example.org>"+tc.rcpt+"\r\n", tc.code)
				if tc.code != "250 " {
					expectReply(t, c, next, "RCPT TO:<actual@example.org>\r\n", "250 ")
				}
				expectReply(t, c, next, "DATA\r\n", "354 ")
				expectReply(t, c, next, "Subject: DSN\r\n\r\nbody\r\n.\r\n", "250 ")
				if len(be.anonmsgs) != 1 {
					t.Fatal("missing delivered message")
				}
				msg := be.anonmsgs[0]
				if msg.Opts.EnvelopeID != tc.envid || msg.Opts.Return != tc.ret {
					t.Fatalf("MAIL options = %+v", msg.Opts)
				}
				if len(msg.RcptOpts) != 1 {
					t.Fatalf("invalid recipients: %+v", msg.RcptOpts)
				}
				opts := msg.RcptOpts[0]
				if tc.code == "250 " && (!reflect.DeepEqual(opts.Notify, tc.notify) || opts.OriginalRecipient != tc.original) {
					t.Fatalf("RCPT options = %+v", opts)
				}
				if tc.original != "" && !strings.EqualFold(string(opts.OriginalRecipientType), string(smtp.DSNAddressTypeRFC822)) {
					t.Fatalf("address type = %s", opts.OriginalRecipientType)
				}
				// Start the next transaction directly, without RSET, to prove
				// that completed DATA itself clears the DSN options.
				expectReply(t, c, next, "MAIL FROM:<second@example.org>\r\n", "250 ")
				expectReply(t, c, next, "RCPT TO:<second@example.org>\r\n", "250 ")
				expectReply(t, c, next, "DATA\r\n", "354 ")
				expectReply(t, c, next, ".\r\n", "250 ")
				second := be.anonmsgs[len(be.anonmsgs)-1]
				if second.Opts.EnvelopeID != "" || second.Opts.Return != "" || len(second.RcptOpts[0].Notify) != 0 || second.RcptOpts[0].OriginalRecipient != "" {
					t.Fatalf("stale DSN options after DATA: %+v / %+v", second.Opts, second.RcptOpts[0])
				}
			}
			// DSN metadata must not survive RSET or completed DATA into another message.
			expectReply(t, c, next, "RSET\r\n", "250 ")
			expectReply(t, c, next, "MAIL FROM:<reset@example.org> RET=FULL ENVID=discard\r\n", "250 ")
			expectReply(t, c, next, "RCPT TO:<reset@example.org> NOTIFY=NEVER ORCPT=rfc822;discard\r\n", "250 ")
			expectReply(t, c, next, "RSET\r\n", "250 ")
			expectReply(t, c, next, "MAIL FROM:<>\r\n", "250 ")
			expectReply(t, c, next, "RCPT TO:<next@example.org>\r\n", "250 ")
			expectReply(t, c, next, "DATA\r\n", "354 ")
			expectReply(t, c, next, ".\r\n", "250 ")
			msg := be.anonmsgs[len(be.anonmsgs)-1]
			if msg.Opts.EnvelopeID != "" || msg.Opts.Return != "" || len(msg.RcptOpts[0].Notify) != 0 || msg.RcptOpts[0].OriginalRecipient != "" {
				t.Fatalf("stale DSN metadata: %+v / %+v", msg.Opts, msg.RcptOpts[0])
			}
		})
	}
}

// checklist: DSN-EHLO-01 DSN-REPLY-02
func TestRFC3461Disabled(t *testing.T) {
	_, s, c, scanner, caps := testServerEhlo(t)
	defer s.Close()
	defer c.Close()
	if caps["DSN"] {
		t.Fatal("DSN advertised without backend opt-in")
	}
	next := func() string { scanner.Scan(); return scanner.Text() }
	for _, param := range []string{"RET=HDRS", "ENVID=id"} {
		expectReply(t, c, next, "MAIL FROM:<a@example.org> "+param+"\r\n", "504 ")
	}
	expectReply(t, c, next, "MAIL FROM:<a@example.org>\r\n", "250 ")
	for _, param := range []string{"NOTIFY=NEVER", "ORCPT=rfc822;b@example.org"} {
		expectReply(t, c, next, "RCPT TO:<b@example.org> "+param+"\r\n", "504 ")
	}
	expectReply(t, c, next, "RCPT TO:<b@example.org>\r\n", "250 ")
}

// checklist: DSN-LIMIT-01 DSN-LIMIT-02
func TestRFC3461ParameterSizes(t *testing.T) {
	_, s, c, scanner, _ := testServerEhlo(t, func(s *server.Server) { s.EnableDSN = true })
	defer s.Close()
	defer c.Close()
	next := func() string { scanner.Scan(); return scanner.Text() }
	// Exercise at least the section 5.4 minima, including their encoded wire size.
	expectReply(t, c, next, "MAIL FROM:<a@example.org> RET=HDRS ENVID="+strings.Repeat("x", 100)+"\r\n", "250 ")
	command := "RCPT TO:<b@example.org> NOTIFY=SUCCESS,FAILURE,DELAY ORCPT=rfc822;" + strings.Repeat("x", 500)
	command += strings.Repeat(" ", 1036-len(command)-2) + "\r\n"
	if len(command) != 1036 {
		t.Fatal(len(command))
	}
	expectReply(t, c, next, command, "250 ")
}

// RFC 3461 section 10.1: preserve the six recipients' distinct requests.
// This proves the SMTP envelope, not the later report generation examples.
// checklist: DSN-EXAMPLE-01 DSN-STATE-01
func TestRFC3461SubmissionExample(t *testing.T) {
	be, s, c, scanner, _ := testServerEhlo(t, func(s *server.Server) { s.EnableDSN = true })
	defer s.Close()
	defer c.Close()
	next := func() string { scanner.Scan(); return scanner.Text() }
	expectReply(t, c, next, "MAIL FROM:<Alice@Example.ORG> RET=HDRS ENVID=QQ314159\r\n", "250 ")
	recipients := []string{"Bob@Example.COM", "Carol@Ivory.EDU", "Dana@Ivory.EDU", "Eric@Bombs.AF.MIL", "Fred@Bombs.AF.MIL", "George@Tax-ME.GOV"}
	notify := []string{"SUCCESS", "FAILURE", "SUCCESS,FAILURE", "FAILURE", "NEVER", "FAILURE"}
	for i, to := range recipients {
		cmd := fmt.Sprintf("RCPT TO:<%s> NOTIFY=%s", to, notify[i])
		if i != 4 {
			cmd += " ORCPT=rfc822;" + to
		}
		expectReply(t, c, next, cmd+"\r\n", "250 ")
	}
	expectReply(t, c, next, "DATA\r\n", "354 ")
	expectReply(t, c, next, "Subject: example\r\n\r\nmessage\r\n.\r\n", "250 ")
	msg := be.anonmsgs[0]
	if msg.From != "Alice@Example.ORG" || msg.Opts.EnvelopeID != "QQ314159" || msg.Opts.Return != smtp.DSNReturnHeaders || !reflect.DeepEqual(msg.To, recipients) {
		t.Fatalf("envelope = %+v", msg)
	}
	for i, opts := range msg.RcptOpts {
		var flags []string
		for _, flag := range opts.Notify {
			flags = append(flags, string(flag))
		}
		if strings.Join(flags, ",") != notify[i] {
			t.Fatalf("recipient %d notify = %v", i, opts.Notify)
		}
		original := recipients[i]
		if i == 4 {
			original = ""
		}
		if opts.OriginalRecipient != original {
			t.Fatalf("recipient %d original = %q", i, opts.OriginalRecipient)
		}
	}
	expectReply(t, c, next, "QUIT\r\n", "221 ")
}

// A host policy error must keep the same SMTP status with and without DSN.
// checklist: DSN-REPLY-01
func TestRFC3461BackendStatus(t *testing.T) {
	for _, code := range []int{450, 550} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			be, s, c, scanner, _ := testServerEhlo(t, func(s *server.Server) { s.EnableDSN = true })
			defer s.Close()
			defer c.Close()
			next := func() string { scanner.Scan(); return scanner.Text() }
			be.userErr = &smtp.SMTPError{Code: code, Message: "host sender policy"}
			for _, params := range []string{"", " RET=HDRS ENVID=id"} {
				expectReply(t, c, next, "MAIL FROM:<a@example.org>"+params+"\r\n", fmt.Sprint(code)+" ")
			}
			be.userErr = nil
			expectReply(t, c, next, "MAIL FROM:<a@example.org>\r\n", "250 ")
			be.rcptErr = &smtp.SMTPError{Code: code, Message: "host recipient policy"}
			for _, params := range []string{"", " NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;original@example.org"} {
				expectReply(t, c, next, "RCPT TO:<b@example.org>"+params+"\r\n", fmt.Sprint(code)+" ")
			}
			be.rcptErr = nil
			expectReply(t, c, next, "RCPT TO:<b@example.org>\r\n", "250 ")
		})
	}
}
