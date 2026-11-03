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
		"NAME=xn--caf-dma.example HELO=caf+c3+a9.example PROTO=ESMTP PORT=25+32+35", "220")
	xclientCommand(t, raw, br, "EHLO proxy.example", "250")
	want := XClientAttrs{
		Login: "user+tag=x@example.com", Addr: "IPV6:2001:db8::1", Name: "xn--caf-dma.example",
		Helo: "caf\u00e9.example", Proto: "ESMTP", Port: "2525",
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
				if line[4:] == "XCLIENT ADDR NAME PROTO HELO LOGIN PORT DESTADDR DESTPORT" {
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

// xclientAttrs sends one XCLIENT command and returns the identity the next
// session sees.
func xclientAttrs(t *testing.T, command string) XClientAttrs {
	t.Helper()
	var conn *Conn
	_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
		enableTestXClient(s)
		s.Backend = BackendFunc(func(c *Conn) (Session, error) {
			conn = c
			return flushAuthSession{}, nil
		})
	})
	xclientCommand(t, raw, br, command, "220")
	xclientCommand(t, raw, br, "EHLO proxy.example", "250")
	return *conn.XClient()
}

// Postfix XCLIENT specification, attribute syntax and notes 1-2: NAME is a
// host name of at most 255 characters, [UNAVAILABLE] or [TEMPUNAVAIL]; ADDR
// and DESTADDR are an IPv4 address, "IPV6:" and an IPv6 address, or
// [UNAVAILABLE]; PORT and DESTPORT are a decimal port or [UNAVAILABLE];
// PROTO is SMTP or ESMTP; HELO is at most 255 characters. Sentinels and the
// IPV6: prefix are case-insensitive and are stored in upper case.
//
// checklist: XC-SYNTAX-04 XC-SYNTAX-05 XC-SYNTAX-06 XC-SYNTAX-07 XC-SYNTAX-09 XC-SYNTAX-10
func TestXClientAttributeSyntax(t *testing.T) {
	label63 := strings.Repeat("h", 63)
	name255 := strings.Join([]string{label63, label63, label63, label63}, ".")
	helo255 := strings.Repeat("h", 255)
	for _, tc := range []struct {
		command string
		want    XClientAttrs
	}{
		{"XCLIENT NAME=mx.example.com", XClientAttrs{Name: "mx.example.com"}},
		{"XCLIENT NAME=" + name255, XClientAttrs{Name: name255}},
		{"XCLIENT NAME=[unavailable]", XClientAttrs{Name: "[UNAVAILABLE]"}},
		{"XCLIENT NAME=[TempUnavail]", XClientAttrs{Name: "[TEMPUNAVAIL]"}},
		{"XCLIENT ADDR=192.0.2.1", XClientAttrs{Addr: "192.0.2.1"}},
		{"XCLIENT ADDR=ipv6:2001:db8::1", XClientAttrs{Addr: "IPV6:2001:db8::1"}},
		{"XCLIENT ADDR=IPv6:::ffff:192.0.2.1", XClientAttrs{Addr: "IPV6:::ffff:192.0.2.1"}},
		{"XCLIENT ADDR=[Unavailable]", XClientAttrs{Addr: "[UNAVAILABLE]"}},
		{"XCLIENT PROTO=esmtp", XClientAttrs{Proto: "ESMTP"}},
		{"XCLIENT PROTO=SMTP", XClientAttrs{Proto: "SMTP"}},
		{"XCLIENT HELO=" + helo255, XClientAttrs{Helo: helo255}},
		{"XCLIENT HELO=[192.0.2.1]", XClientAttrs{Helo: "[192.0.2.1]"}},
		{"XCLIENT HELO=[unavailable]", XClientAttrs{Helo: "[UNAVAILABLE]"}},
		{"XCLIENT LOGIN=[unavailable]", XClientAttrs{Login: "[UNAVAILABLE]"}},
		{"XCLIENT PORT=0", XClientAttrs{Port: "0"}},
		{"XCLIENT PORT=65535", XClientAttrs{Port: "65535"}},
		{"XCLIENT PORT=[UNAVAILABLE]", XClientAttrs{Port: "[UNAVAILABLE]"}},
		{"XCLIENT DESTADDR=IPV6:2001:db8::25 DESTPORT=587", XClientAttrs{DestAddr: "IPV6:2001:db8::25", DestPort: "587"}},
		{"XCLIENT DESTADDR=198.51.100.7 DESTPORT=[unavailable]", XClientAttrs{DestAddr: "198.51.100.7", DestPort: "[UNAVAILABLE]"}},
	} {
		t.Run(tc.command, func(t *testing.T) {
			if got := xclientAttrs(t, tc.command); got != tc.want {
				t.Fatalf("XClient() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// A malformed attribute value is refused with 501 5.5.4, and the identity
// stays as it was.
//
// checklist: XC-SYNTAX-04 XC-SYNTAX-05 XC-SYNTAX-06 XC-SYNTAX-07 XC-SYNTAX-09 XC-SYNTAX-10
func TestXClientRefusesMalformedAttributes(t *testing.T) {
	label63 := strings.Repeat("h", 63)
	for _, bad := range []string{
		"NAME=", "NAME=bad_name.example", "NAME=-mx.example", "NAME=mx..example", "NAME=caf+C3+A9.example",
		"NAME=" + strings.Repeat("h", 64) + ".example",
		"NAME=" + strings.Join([]string{label63, label63, label63, label63}, ".") + "h",
		"NAME=[192.0.2.1]", "NAME=[UNKNOWN]",
		"ADDR=", "ADDR=192.0.2", "ADDR=192.0.2.256", "ADDR=2001:db8::1", "ADDR=[192.0.2.1]",
		"ADDR=IPV6:192.0.2.1", "ADDR=IPV6:fe80::1%25eth0", "ADDR=[TEMPUNAVAIL]", "ADDR=mx.example",
		"PROTO=LMTP", "PROTO=", "PROTO=ESMTPS",
		"HELO=", "HELO=" + strings.Repeat("h", 256), "HELO=a+01b",
		"PORT=", "PORT=65536", "PORT=-1", "PORT=+2B25", "PORT=0x19", "PORT=999999",
		"DESTADDR=example.com", "DESTADDR=IPV6:", "DESTPORT=70000", "DESTPORT=smtp",
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
			xclientCommand(t, raw, br, "XCLIENT NAME=original.example ADDR=192.0.2.9 PORT=1025", "220")
			xclientCommand(t, raw, br, "EHLO proxy.example", "250")
			before := *conn.XClient()
			reply := xclientCommand(t, raw, br, "XCLIENT "+bad, "501")
			name, _, _ := strings.Cut(bad, "=")
			if want := "501 5.5.4 Bad XCLIENT " + name + " syntax"; reply[0] != want {
				t.Fatalf("reply = %q, want %q", reply, want)
			}
			if got := *conn.XClient(); got != before {
				t.Fatalf("refused command changed identity: %+v, was %+v", got, before)
			}
		})
	}
}
