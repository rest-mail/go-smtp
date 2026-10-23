package server

import (
	"bufio"
	"crypto/tls"
	"net"
	"strings"
	"testing"
)

func xclientCommand(t *testing.T, raw net.Conn, br *bufio.Reader, command, code string) []string {
	t.Helper()
	writeFlushBatch(t, raw, command+"\r\n")
	reply := readFlushReply(t, br)
	if !strings.HasPrefix(reply[0], code+" ") && !strings.HasPrefix(reply[0], code+"-") {
		t.Fatalf("%q: got %q, want %s", command, reply, code)
	}
	return reply
}

func enableTestXClient(s *Server) {
	s.EnableXCLIENT = true
	s.TrustXCLIENT = func(*Conn) bool { return true }
}

// checklist: XC-SYNTAX-01 XC-STATE-01 XC-STATE-02 XC-STATE-03 XC-STATE-04 XC-STATE-05 XC-CACHE-01
func TestXClientReplacesSession(t *testing.T) {
	type snapshot struct {
		host  string
		attrs *XClientAttrs
	}
	snapshots := make(chan snapshot, 4)
	logouts := make(chan chan struct{}, 4)
	_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
		enableTestXClient(s)
		s.Backend = BackendFunc(func(c *Conn) (Session, error) {
			snapshots <- snapshot{c.Hostname(), c.XClient()}
			logout := make(chan struct{})
			logouts <- logout
			return rfc3207Session{loggedOut: logout}, nil
		})
	})
	xclientCommand(t, raw, br, "EHLO proxy.example", "250")
	before := <-snapshots
	logout := <-logouts
	if before.attrs != nil {
		t.Fatal("identity asserted before XCLIENT")
	}
	xclientCommand(t, raw, br, "AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk", "235")
	xclientCommand(t, raw, br, "XCLIENT NAME=spike.porcupine.org ADDR=168.100.189.2 HELO=original.example PROTO=ESMTP LOGIN=alice", "220")
	select {
	case <-logout:
	default:
		t.Fatal("XCLIENT did not log out the previous backend session")
	}
	// Asserted HELO is metadata, not the proxy's new SMTP greeting.
	xclientCommand(t, raw, br, "MAIL FROM:<wietse@porcupine.org>", "503")
	xclientCommand(t, raw, br, "AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk", "503")
	xclientCommand(t, raw, br, "EHLO spike.porcupine.org", "250")
	after := <-snapshots
	<-logouts
	if after.host != "spike.porcupine.org" || after.attrs == nil || *after.attrs != (XClientAttrs{
		Addr: "168.100.189.2", Name: "spike.porcupine.org", Proto: "ESMTP", Helo: "original.example", Login: "alice",
	}) {
		t.Fatalf("replacement session = %+v, attrs = %+v", after, after.attrs)
	}
	xclientCommand(t, raw, br, "AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk", "235")
	xclientCommand(t, raw, br, "MAIL FROM:<wietse@porcupine.org>", "250")
	xclientCommand(t, raw, br, "RSET", "250")
	// Multiple commands accumulate attributes; snapshots already given to a
	// backend must not change under it when the next identity arrives.
	xclientCommand(t, raw, br, "xclient name=next.example login=[UNAVAILABLE]", "220")
	xclientCommand(t, raw, br, "EHLO next.example", "250")
	next := <-snapshots
	<-logouts
	if next.attrs.Name != "next.example" || next.attrs.Login != "[UNAVAILABLE]" || next.attrs.Addr != after.attrs.Addr || next.attrs.Helo != "original.example" || next.attrs.Proto != "ESMTP" {
		t.Fatalf("accumulated identity = %+v", next.attrs)
	}
	if after.attrs.Name != "spike.porcupine.org" || after.attrs.Login != "alice" {
		t.Fatalf("previous identity mutated: %+v", after.attrs)
	}
}

// checklist: XC-ORDER-01 XC-STATE-03 XC-EXAMPLE-01
func TestXClientRefusedDuringTransaction(t *testing.T) {
	for _, stage := range []string{"MAIL", "RCPT", "BDAT"} {
		t.Run(stage, func(t *testing.T) {
			_, raw, br, _ := newFlushTestConn(t, enableTestXClient)
			xclientCommand(t, raw, br, "EHLO client.example.com", "250")
			xclientCommand(t, raw, br, "XCLIENT NAME=spike.porcupine.org ADDR=168.100.189.2", "220")
			xclientCommand(t, raw, br, "EHLO spike.porcupine.org", "250")
			xclientCommand(t, raw, br, "MAIL FROM:<wietse@porcupine.org>", "250")
			if stage != "MAIL" {
				xclientCommand(t, raw, br, "RCPT TO:<user@example.com>", "250")
			}
			if stage == "BDAT" {
				xclientCommand(t, raw, br, "BDAT 0", "250")
			}
			xclientCommand(t, raw, br, "XCLIENT NAME=other.example", "503")
			// The rejected command must leave the delivery transaction intact.
			if stage == "MAIL" {
				xclientCommand(t, raw, br, "RCPT TO:<user@example.com>", "250")
			}
			if stage == "BDAT" {
				xclientCommand(t, raw, br, "BDAT 0 LAST", "250")
			} else {
				xclientCommand(t, raw, br, "DATA", "354")
				xclientCommand(t, raw, br, ".", "250")
			}
			xclientCommand(t, raw, br, "XCLIENT NAME=other.example", "220")
		})
	}
}

// checklist: XC-SYNTAX-01 XC-SYNTAX-02 XC-SYNTAX-03 XC-STATE-06
func TestXClientRejectedCommandIsAtomic(t *testing.T) {
	for _, bad := range []string{
		"XCLIENT", "XCLIENT NAME=changed.example BROKEN", "XCLIENT HELO=changed.example UNKNOWN=value",
		"XCLIENT LOGIN=mallory NAME=changed.example ADDR",
		"XCLIENT NAME=changed.example LOGIN=user+tag@example.com", "XCLIENT LOGIN=mallory HELO=a+2",
		"XCLIENT NAME=changed.example PORT=+ZZ",
	} {
		t.Run(bad, func(t *testing.T) {
			var conn *Conn
			_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
				enableTestXClient(s)
				s.Backend = BackendFunc(func(c *Conn) (Session, error) {
					conn = c
					return flushAuthSession{}, nil
				})
			})
			xclientCommand(t, raw, br, "XCLIENT NAME=original.example HELO=original.example LOGIN=alice", "220")
			xclientCommand(t, raw, br, "EHLO proxy.example", "250")
			xclientCommand(t, raw, br, "AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk", "235")
			before := *conn.XClient()
			session := conn.Session()
			xclientCommand(t, raw, br, bad, "501")
			if *conn.XClient() != before || conn.Hostname() != "proxy.example" || !conn.didAuth || conn.Session() != session {
				t.Fatalf("rejected command changed state: attrs=%+v host=%q auth=%v", conn.XClient(), conn.Hostname(), conn.didAuth)
			}
			xclientCommand(t, raw, br, "MAIL FROM:<a@example.com>", "250")
		})
	}
}

// checklist: XC-SYNTAX-03
func TestXClientDecodesXtextValues(t *testing.T) {
	var conn *Conn
	_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
		enableTestXClient(s)
		s.Backend = BackendFunc(func(c *Conn) (Session, error) {
			conn = c
			return flushAuthSession{}, nil
		})
	})
	xclientCommand(t, raw, br, "XCLIENT LOGIN=user+2Btag+3Dx@example.com ADDR=IPV6+3A2001:db8::1 "+
		"NAME=caf+c3+a9.example HELO=[UNAVAILABLE] PROTO=ESMTP PORT=25+32+35", "220")
	xclientCommand(t, raw, br, "EHLO proxy.example", "250")
	want := XClientAttrs{
		Login: "user+tag=x@example.com", Addr: "IPV6:2001:db8::1", Name: "caf\u00e9.example",
		Helo: "[UNAVAILABLE]", Proto: "ESMTP",
	}
	if got := *conn.XClient(); got != want {
		t.Fatalf("XClient() = %+v, want %+v", got, want)
	}
}

// checklist: XC-SEC-01 XC-EHLO-01
func TestXClientTrustConfiguration(t *testing.T) {
	for _, mode := range []string{"disabled", "no callback", "untrusted", "trusted"} {
		t.Run(mode, func(t *testing.T) {
			_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
				s.EnableXCLIENT = mode != "disabled"
				if mode != "no callback" {
					s.TrustXCLIENT = func(*Conn) bool { return mode == "trusted" || mode == "disabled" }
				}
			})
			caps := xclientCommand(t, raw, br, "EHLO proxy.example", "250")
			advertised := false
			for _, line := range caps {
				if line[4:] == "XCLIENT ADDR NAME PROTO HELO LOGIN" {
					advertised = true
				}
			}
			if advertised != (mode == "trusted") {
				t.Fatalf("XCLIENT advertisement: %q", caps)
			}
			code := "550"
			if mode == "trusted" {
				code = "220"
			}
			xclientCommand(t, raw, br, "XCLIENT NAME=client.example", code)
		})
	}
}

// checklist: XC-TLS-01 XC-STATE-02
func TestXClientPreservesTLS(t *testing.T) {
	snapshots := make(chan bool, 3)
	_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
		enableTestXClient(s)
		s.TLSConfig = rfc3207TLSConfig(t)
		s.Backend = BackendFunc(func(c *Conn) (Session, error) {
			state, ok := c.TLSConnectionState()
			snapshots <- ok && state.HandshakeComplete
			return flushAuthSession{}, nil
		})
	})
	xclientCommand(t, raw, br, "STARTTLS", "220")
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed test certificate
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	br = bufio.NewReader(tc)
	xclientCommand(t, tc, br, "EHLO proxy.example", "250")
	if !<-snapshots {
		t.Fatal("initial session was not encrypted")
	}
	xclientCommand(t, tc, br, "XCLIENT NAME=client.example", "220")
	caps := xclientCommand(t, tc, br, "EHLO client.example", "250")
	if len(snapshots) != 1 {
		t.Fatal("XCLIENT did not create a replacement TLS backend session")
	}
	if !<-snapshots || strings.Contains(strings.Join(caps, "\n"), "STARTTLS") {
		t.Fatalf("TLS lost or STARTTLS re-advertised: %q", caps)
	}
	xclientCommand(t, tc, br, "STARTTLS", "503")
}

// checklist: XC-ORDER-02 XC-STATE-01 XC-STATE-03 XC-CACHE-01 XC-EXAMPLE-01
func TestXClientPipelinedExample(t *testing.T) {
	identities := make(chan *XClientAttrs, 4)
	_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
		enableTestXClient(s)
		s.Backend = BackendFunc(func(c *Conn) (Session, error) {
			identities <- c.XClient()
			return nopSession{}, nil
		})
	})
	xclientCommand(t, raw, br, "EHLO client.example.com", "250")
	<-identities
	// XCLIENT is the last command in this group, as Postfix recommends.
	writeFlushBatch(t, raw, "NOOP\r\nXCLIENT NAME=spike.porcupine.org ADDR=168.100.189.2\r\n")
	for _, code := range []string{"250 ", "220 "} {
		if reply := readFlushReply(t, br); !strings.HasPrefix(reply[0], code) {
			t.Fatalf("pipeline reply = %q, want %q", reply, code)
		}
	}
	xclientCommand(t, raw, br, "EHLO spike.porcupine.org", "250")
	if len(identities) != 1 {
		t.Fatal("backend session was not replaced")
	}
	identity := <-identities
	if identity == nil || identity.Name != "spike.porcupine.org" || identity.Addr != "168.100.189.2" {
		t.Fatalf("example identity = %+v", identity)
	}
	xclientCommand(t, raw, br, "MAIL FROM:<wietse@porcupine.org>", "250")
	xclientCommand(t, raw, br, "RCPT TO:<user@example.com>", "250")
	xclientCommand(t, raw, br, "DATA", "354")
	xclientCommand(t, raw, br, ". . .message content. . .\r\n.", "250")
	xclientCommand(t, raw, br, "RSET", "250")
	xclientCommand(t, raw, br, "EHLO again.example", "250")
	if len(identities) != 0 {
		t.Fatal("ordinary SMTP reset replaced the backend session")
	}
	// A new XCLIENT preserves attributes omitted from the command, including
	// across completed deliveries, RSET and repeated EHLO.
	xclientCommand(t, raw, br, "XCLIENT LOGIN=alice", "220")
	xclientCommand(t, raw, br, "EHLO final.example", "250")
	if len(identities) != 1 {
		t.Fatal("second XCLIENT did not replace the session")
	}
	final := <-identities
	if final.Name != identity.Name || final.Addr != identity.Addr || final.Login != "alice" {
		t.Fatalf("cached identity lost: %+v", final)
	}
	xclientCommand(t, raw, br, "QUIT", "221")
}

// checklist: XC-SEC-01 XC-SEC-02
func TestXClientTrustRechecked(t *testing.T) {
	_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
		s.EnableXCLIENT = true
		// A host may revoke proxy access based on an asserted attribute.
		s.TrustXCLIENT = func(c *Conn) bool { return c.XClient() == nil }
	})
	xclientCommand(t, raw, br, "XCLIENT ADDR=168.100.189.2", "220")
	caps := xclientCommand(t, raw, br, "EHLO spike.porcupine.org", "250")
	if strings.Contains(strings.Join(caps, "\n"), "XCLIENT") {
		t.Fatalf("XCLIENT advertised after trust revoked: %q", caps)
	}
	xclientCommand(t, raw, br, "XCLIENT ADDR=203.0.113.5", "550")
}
