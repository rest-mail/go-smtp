package smtp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/textproto"
	"strings"
	"testing"
)

// checklist: MIME-CLIENT-01 MIME-CLIENT-02 MIME-CLIENT-03 MIME-SYNTAX-02
func TestRFC6152ClientBodyOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		exts []string
		opts *MailOptions
		want string
	}{
		{"automatic extended", []string{"8BITMIME"}, nil, " BODY=8BITMIME"},
		{"automatic basic", nil, nil, ""},
		{"empty options", []string{"8BITMIME"}, &MailOptions{}, " BODY=8BITMIME"},
		{"explicit seven bit", []string{"8BITMIME"}, &MailOptions{Body: Body7Bit}, " BODY=7BIT"},
		{"basic seven bit", nil, &MailOptions{Body: Body7Bit}, ""},
		{"explicit eight bit", []string{"8BITMIME"}, &MailOptions{Body: Body8BitMIME}, " BODY=8BITMIME"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, wrote := newMailParamClient(tc.exts...)
			defer c.Close()
			if err := c.Mail("a@example.org", tc.opts); err != nil {
				t.Fatal(err)
			}
			if got, want := wrote.String(), "MAIL FROM:<a@example.org>"+tc.want+"\r\n"; got != want {
				t.Fatalf("wire = %q, want %q", got, want)
			}
		})
	}
	for _, tc := range []struct {
		name string
		exts []string
		body BodyType
	}{
		{"unadvertised eight bit", nil, Body8BitMIME},
		{"binary needs BDAT", []string{"8BITMIME", "BINARYMIME", "CHUNKING"}, BodyBinaryMIME},
		{"unknown", []string{"8BITMIME"}, "8BIT"},
		{"injection", []string{"8BITMIME"}, "7BIT\r\nQUIT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, wrote := newMailParamClient(tc.exts...)
			defer c.Close()
			if err := c.Mail("a@example.org", &MailOptions{Body: tc.body}); err == nil {
				t.Fatal("unsupported BODY accepted")
			}
			if wrote.Len() != 0 {
				t.Fatalf("invalid BODY wrote %q", wrote.String())
			}
		})
	}
}

type rfc6152Session struct {
	nopSession
	mail func(string, *MailOptions) error
	data chan []byte
}

func (s rfc6152Session) Mail(from string, opts *MailOptions) error { return s.mail(from, opts) }

func (s rfc6152Session) Data(r io.Reader) error {
	b, err := io.ReadAll(r)
	if err == nil {
		s.data <- b
	}
	return err
}

// checklist: MIME-SYNTAX-01 MIME-SYNTAX-02 MIME-SYNTAX-03 MIME-SYNTAX-04 MIME-DATA-01 MIME-DATA-02 MIME-DATA-03 MIME-DATA-04 MIME-EXAMPLE-01
func TestRFC6152ServerExample(t *testing.T) {
	for _, body := range []string{"8BITMIME", "7BIT", ""} {
		t.Run("body="+body, func(t *testing.T) {
			data := make(chan []byte, 1)
			_, raw, br, _ := newFlushTestConn(t, func(s *Server) {
				s.Domain = "dbc.mtview.ca.us"
				s.MaxLineLength = 512 // Command limits must not cap DATA at 512.
				s.Backend = BackendFunc(func(*Conn) (Session, error) {
					return rfc6152Session{data: data, mail: func(from string, opts *MailOptions) error {
						if from != "ned@ymir.claremont.edu" || opts.Body != BodyType(body) {
							return fmt.Errorf("unexpected envelope: %s, %+v", from, opts)
						}
						return nil
					}}, nil
				})
			})
			command := func(command, want string) []string {
				t.Helper()
				writeFlushBatch(t, raw, command+"\r\n")
				reply := readFlushReply(t, br)
				if !strings.HasPrefix(reply[0], want+" ") && !strings.HasPrefix(reply[0], want+"-") {
					t.Fatalf("%q reply = %q, want %s", command, reply, want)
				}
				return reply
			}
			caps := command("EHLO ymir.claremont.edu", "250")
			count := 0
			for _, cap := range caps {
				if strings.HasPrefix(cap[4:], "8BITMIME") {
					count++
					if cap[4:] != "8BITMIME" {
						t.Fatalf("parameter on 8BITMIME advertisement: %q", cap)
					}
				}
			}
			if count != 1 {
				t.Fatalf("8BITMIME advertisements = %d", count)
			}
			mail := "MAIL FROM:<ned@ymir.claremont.edu>"
			if body != "" {
				mail += " bOdY=" + strings.ToLower(body)
			}
			command(mail, "250")
			command("RCPT TO:<mrose@dbc.mtview.ca.us>", "250")
			command("DATA", "354")
			payload := "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 7bit\r\n\r\n"
			if body == "8BITMIME" {
				payload = strings.Replace(payload, "Encoding: 7bit", "Encoding: 8bit", 1)
				for b := 128; b <= 255; b++ {
					payload += string([]byte{byte(b)})
				}
				payload += "\r\n"
			}
			payload += ".\r\n.leading dot\r\n" + strings.Repeat("x", 998) + "\r\n"
			// Independent stuffing oracle; keep the CRLF before the final dot.
			wire := strings.ReplaceAll(payload, "\r\n.", "\r\n..")
			command(wire+".", "250")
			if got := <-data; !bytes.Equal(got, []byte(payload)) {
				t.Fatalf("delivered bytes = %q, want %q", got, payload)
			}
			command("QUIT", "221") // RFC example's 250 is superseded by RFC 5321.
		})
	}
}

// checklist: MIME-SYNTAX-02 MIME-SYNTAX-03 MIME-CLIENT-03
func TestRFC6152ServerBodyGrammar(t *testing.T) {
	for _, args := range []string{"BODY", "BODY=", "BODY=8BIT", "BODY=8BITMIME BODY=7BIT", "BODY=7BIT body=7bit", "BODY=8BITMIME\u0085", "BODY=BINARYMIME"} {
		t.Run(args, func(t *testing.T) {
			_, raw, br, _ := newFlushTestConn(t, nil)
			writeFlushBatch(t, raw, "EHLO client.example\r\n")
			readFlushReply(t, br)
			writeFlushBatch(t, raw, "MAIL FROM:<a@example.org> "+args+"\r\n")
			if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, "501 ") && !strings.HasPrefix(got, "504 ") {
				t.Fatalf("invalid BODY reply = %q", got)
			}
			writeFlushBatch(t, raw, "MAIL FROM:<a@example.org> BODY=8BITMIME\r\n")
			if got := readFlushReply(t, br)[0]; !strings.HasPrefix(got, "250 ") {
				t.Fatalf("valid retry reply = %q", got)
			}
		})
	}
}

// checklist: MIME-CLIENT-01 MIME-DATA-01 MIME-DATA-02 MIME-DATA-03
func TestRFC6152ClientPreservesOctets(t *testing.T) {
	data := make(chan []byte, 1)
	_, raw, _, _ := newFlushTestConn(t, func(s *Server) {
		s.Backend = BackendFunc(func(*Conn) (Session, error) {
			return rfc6152Session{data: data, mail: func(_ string, opts *MailOptions) error {
				if opts.Body != Body8BitMIME {
					return fmt.Errorf("BODY = %q, want 8BITMIME", opts.Body)
				}
				return nil
			}}, nil
		})
	})
	c := NewClient(raw)
	c.didGreet = true // newFlushTestConn consumed the greeting.
	defer c.Close()
	payload := "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\n.\r\n"
	for b := 128; b <= 255; b++ {
		payload += string([]byte{byte(b)})
	}
	payload += "\r\n.last\r\n"
	// Exercise the public convenience path, including EHLO negotiation,
	// automatic BODY, DATA dot stuffing, and the backend byte reader.
	if err := c.SendMail("ned@ymir.claremont.edu", []string{"mrose@dbc.mtview.ca.us"}, strings.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	if got := <-data; !bytes.Equal(got, []byte(payload)) {
		t.Fatalf("delivered bytes = %q, want %q", got, payload)
	}
	if err := c.Quit(); err != nil {
		t.Fatal(err)
	}
}

// checklist: MIME-DATA-01 MIME-DATA-02 MIME-DATA-03
func FuzzRFC6152DataOctets(f *testing.F) {
	f.Add([]byte{0x80, 0xff, '.', 0xc3, 0xa9})
	f.Add([]byte(".\r\n.\r\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 4096 {
			t.Skip()
		}
		// Build legal CRLF-framed lines without normalizing any high-bit byte.
		var payload bytes.Buffer
		for i, b := range input {
			if b == '\r' || b == '\n' {
				payload.WriteString("\r\n")
			} else {
				payload.WriteByte(b)
			}
			if i%200 == 199 {
				payload.WriteString("\r\n")
			}
		}
		payload.WriteString("\r\n")
		want := payload.Bytes()
		wire := bytes.ReplaceAll(want, []byte("\r\n."), []byte("\r\n.."))
		if len(wire) > 0 && wire[0] == '.' {
			wire = append([]byte{'.'}, wire...)
		}
		wire = append(wire, []byte(".\r\nNEXT\r\n")...)
		br := bufio.NewReader(bytes.NewReader(wire))
		r := &dataReader{r: br}
		got, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("DATA = %q, %v; want %q", got, err, want)
		}
		// Go's independent SMTP transparency reader normalizes CRLF to LF;
		// compare after accounting for that documented difference.
		ref, err := io.ReadAll(textproto.NewReader(bufio.NewReader(bytes.NewReader(wire))).DotReader())
		if err != nil || !bytes.Equal(ref, bytes.ReplaceAll(got, []byte("\r\n"), []byte("\n"))) {
			t.Fatalf("reference reader = %q, %v; library = %q", ref, err, got)
		}
		if tail, err := br.ReadString('\n'); err != nil || tail != "NEXT\r\n" {
			t.Fatalf("consumed beyond terminator: %q, %v", tail, err)
		}
	})
}
