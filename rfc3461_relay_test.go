package smtp_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp"
)

// dsnRelayWire records only the client's writes to a real SMTP server.
type dsnRelayWire struct {
	net.Conn
	wire bytes.Buffer
}

func (c *dsnRelayWire) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.wire.Write(p[:n])
	return n, err
}

// relayDSN delivers an incoming SMTP transaction, then acts as the host relay:
// pass the received options unchanged to the outbound client, rewriting only
// the routing addresses. This tests the transport contract, not an automatic
// relay, durable queue, routing policy or notification generator.
func relayDSN(t *testing.T, pipeline, dsn bool, mail string, rcpts []string, amend func(*message)) (*message, *message, string) {
	t.Helper()
	be, source, conn, scanner, _ := testServerEhlo(t, func(s *smtp.Server) { s.EnableDSN = true })
	defer source.Close()
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	next := func() string {
		if !scanner.Scan() {
			t.Fatalf("source response: %v", scanner.Err())
		}
		return scanner.Text()
	}
	expectReply(t, conn, next, "MAIL FROM:<Sender@Example.ORG>"+mail+"\r\n", "250 ")
	for i, params := range rcpts {
		expectReply(t, conn, next, fmt.Sprintf("RCPT TO:<User%d@Example.ORG>%s\r\n", i, params), "250 ")
	}
	expectReply(t, conn, next, "DATA\r\n", "354 ")
	expectReply(t, conn, next, "Subject: relay\r\n\r\n..Payload\r\n.\r\n", "250 ")
	if len(be.anonmsgs) != 1 {
		t.Fatalf("source deliveries = %d", len(be.anonmsgs))
	}
	in := be.anonmsgs[0]
	if len(in.RcptOpts) != len(rcpts) || string(in.Data) != "Subject: relay\r\n\r\n.Payload\r\n" {
		t.Fatalf("incoming recipients/body: %+v", in)
	}
	if amend != nil {
		amend(in)
	}

	outBE, dest, outConn, _ := testServer(t, func(s *smtp.Server) { s.EnableDSN = dsn })
	defer dest.Close()
	wire := &dsnRelayWire{Conn: outConn}
	client := smtp.NewClient(wire)
	defer client.Close()
	client.CommandTimeout = 5 * time.Second
	client.SubmissionTimeout = 5 * time.Second
	if err := client.Hello("relay.example.org"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := client.Extension("DSN"); ok != dsn {
		t.Fatalf("next-hop DSN = %v, want %v", ok, dsn)
	}
	wire.wire.Reset()
	mailFn, rcptFn := client.Mail, client.Rcpt
	var group *smtp.Pipeliner
	if pipeline {
		var err error
		group, err = client.Pipeline()
		if err != nil {
			t.Fatal(err)
		}
		mailFn, rcptFn = group.Mail, group.Rcpt
	}
	if err := mailFn(in.From, in.Opts); err != nil {
		t.Fatal(err)
	}
	for i, opts := range in.RcptOpts {
		if err := rcptFn(fmt.Sprintf("route%d@next.example", i), opts); err != nil {
			t.Fatal(err)
		}
	}
	if group != nil {
		for _, err := range group.Wait() {
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	commands := wire.wire.String()
	w, err := client.Data()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(w, bytes.NewReader(in.Data)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if len(outBE.anonmsgs) != 1 {
		t.Fatalf("next-hop deliveries = %d", len(outBE.anonmsgs))
	}
	out := outBE.anonmsgs[0]
	if len(out.RcptOpts) != len(rcpts) || len(out.To) != len(rcpts) {
		t.Fatalf("next-hop recipients: %+v", out)
	}
	for i, to := range out.To {
		if want := fmt.Sprintf("route%d@next.example", i); to != want {
			t.Fatalf("next-hop recipient %d = %q, want %q", i, to, want)
		}
	}
	if out.From != in.From || !bytes.Equal(out.Data, in.Data) {
		t.Fatalf("relay changed sender/body: %+v -> %+v", in, out)
	}
	if err := client.Noop(); err != nil {
		t.Fatalf("reply stream after relay: %v", err)
	}
	return in, out, commands
}

// checklist: DSN-HOST-03
func TestRFC3461RelayEnvelopeID(t *testing.T) {
	for _, pipeline := range []bool{false, true} {
		for _, id := range []string{"", "MiXeD-id+20+2B+3D", strings.Repeat("X", 100)} {
			t.Run(fmt.Sprintf("pipeline=%v/id=%s", pipeline, id), func(t *testing.T) {
				param := ""
				if id != "" {
					param = " ENVID=" + id
				}
				in, out, wire := relayDSN(t, pipeline, true, param, []string{""}, nil)
				want := "MAIL FROM:<Sender@Example.ORG> BODY=8BITMIME" + param + "\r\nRCPT TO:<route0@next.example>\r\n"
				if wire != want || out.Opts.EnvelopeID != in.Opts.EnvelopeID {
					t.Fatalf("ENVID relay: wire=%q want=%q; %q -> %q", wire, want, in.Opts.EnvelopeID, out.Opts.EnvelopeID)
				}
			})
		}
	}
}

// checklist: DSN-RELAY-01
func TestRFC3461RelayReturn(t *testing.T) {
	for _, pipeline := range []bool{false, true} {
		for _, ret := range []string{"", "FULL", "HDRS"} {
			t.Run(fmt.Sprintf("pipeline=%v/ret=%s", pipeline, ret), func(t *testing.T) {
				param := ""
				if ret != "" {
					param = " RET=" + ret
				}
				in, out, wire := relayDSN(t, pipeline, true, param, []string{""}, nil)
				want := "MAIL FROM:<Sender@Example.ORG> BODY=8BITMIME" + param + "\r\nRCPT TO:<route0@next.example>\r\n"
				if wire != want || out.Opts.Return != in.Opts.Return {
					t.Fatalf("RET relay: wire=%q want=%q; %q -> %q", wire, want, in.Opts.Return, out.Opts.Return)
				}
			})
		}
	}
}

// checklist: DSN-RELAY-02
func TestRFC3461RelayNotify(t *testing.T) {
	params := []string{"", " NOTIFY=NEVER", " NOTIFY=SUCCESS", " NOTIFY=FAILURE", " NOTIFY=DELAY", " NOTIFY=SUCCESS,FAILURE,DELAY"}
	for _, pipeline := range []bool{false, true} {
		t.Run(fmt.Sprint(pipeline), func(t *testing.T) {
			in, out, wire := relayDSN(t, pipeline, true, "", params, nil)
			want := "MAIL FROM:<Sender@Example.ORG> BODY=8BITMIME\r\n"
			for i, param := range params {
				want += fmt.Sprintf("RCPT TO:<route%d@next.example>%s\r\n", i, param)
				if !reflect.DeepEqual(out.RcptOpts[i].Notify, in.RcptOpts[i].Notify) {
					t.Errorf("recipient %d: %v -> %v", i, in.RcptOpts[i].Notify, out.RcptOpts[i].Notify)
				}
			}
			if wire != want {
				t.Fatalf("NOTIFY wire=%q want=%q", wire, want)
			}
		})
	}
}

// checklist: DSN-RELAY-03
func TestRFC3461RelayOriginalRecipient(t *testing.T) {
	for _, pipeline := range []bool{false, true} {
		for _, typ := range []string{"RFC822", "rfc822", "rFc822"} {
			t.Run(fmt.Sprintf("pipeline=%v/type=%s", pipeline, typ), func(t *testing.T) {
				param := " ORCPT=" + typ + ";Original+2BTag@MiXeD.Example"
				in, out, wire := relayDSN(t, pipeline, true, "", []string{param, ""}, nil)
				want := "MAIL FROM:<Sender@Example.ORG> BODY=8BITMIME\r\nRCPT TO:<route0@next.example>" + param + "\r\nRCPT TO:<route1@next.example>\r\n"
				if wire != want || out.RcptOpts[0].OriginalRecipientType != smtp.DSNAddressType(typ) || out.RcptOpts[0].OriginalRecipient != "Original+Tag@MiXeD.Example" || !reflect.DeepEqual(in.RcptOpts, out.RcptOpts) {
					t.Fatalf("ORCPT relay: wire=%q want=%q; %+v -> %+v", wire, want, in.RcptOpts, out.RcptOpts)
				}
			})
		}
	}
}

// checklist: DSN-RELAY-04
func TestRFC3461RelayAddedOriginalRecipient(t *testing.T) {
	for _, pipeline := range []bool{false, true} {
		t.Run(fmt.Sprint(pipeline), func(t *testing.T) {
			_, out, wire := relayDSN(t, pipeline, true, "", []string{""}, func(in *message) {
				// The host elects to add ORCPT before rewriting the routing address.
				in.RcptOpts[0].OriginalRecipientType = smtp.DSNAddressTypeRFC822
				in.RcptOpts[0].OriginalRecipient = in.To[0]
			})
			want := "MAIL FROM:<Sender@Example.ORG> BODY=8BITMIME\r\nRCPT TO:<route0@next.example> ORCPT=RFC822;User0@Example.ORG\r\n"
			if wire != want || out.RcptOpts[0].OriginalRecipient != "User0@Example.ORG" {
				t.Fatalf("added ORCPT wire=%q want=%q; opts=%+v", wire, want, out.RcptOpts[0])
			}
		})
	}
}

// checklist: DSN-HOST-04
func TestRFC3461RelayNonDSN(t *testing.T) {
	for _, pipeline := range []bool{false, true} {
		t.Run(fmt.Sprint(pipeline), func(t *testing.T) {
			_, out, wire := relayDSN(t, pipeline, false, " ENVID=Mixed+2BID RET=HDRS", []string{" NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;Original@Example.ORG", " NOTIFY=NEVER"}, nil)
			want := "MAIL FROM:<Sender@Example.ORG> BODY=8BITMIME\r\nRCPT TO:<route0@next.example>\r\nRCPT TO:<route1@next.example>\r\n"
			if wire != want || out.Opts.EnvelopeID != "" || out.Opts.Return != "" {
				t.Fatalf("non-DSN wire=%q want=%q; opts=%+v", wire, want, out.Opts)
			}
			for _, opts := range out.RcptOpts {
				if !reflect.DeepEqual(*opts, smtp.RcptOptions{}) {
					t.Fatalf("DSN recipient metadata sent to non-DSN next hop: %+v", opts)
				}
			}
		})
	}
}
