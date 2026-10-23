package rfctest

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rest-mail/go-smtp/pkg/smtp"
	"github.com/rest-mail/go-smtp/pkg/smtp/server"
)

func chunkCommand(t *testing.T, c net.Conn, scanner *bufio.Scanner, wire, code string) {
	t.Helper()
	if _, err := io.WriteString(c, wire); err != nil {
		t.Fatal(err)
	}
	chunkReply(t, scanner, code)
}

func chunkReply(t *testing.T, scanner *bufio.Scanner, code string) {
	t.Helper()
	if !scanner.Scan() || !strings.HasPrefix(scanner.Text(), code+" ") {
		t.Fatalf("reply = %q (%v), want %s", scanner.Text(), scanner.Err(), code)
	}
}

// checklist: CHUNK-EHLO-01 CHUNK-EHLO-02 CHUNK-DATA-01 CHUNK-DATA-02 CHUNK-DATA-03 CHUNK-STATE-02 CHUNK-EXAMPLE-01 CHUNK-EXAMPLE-02 BINARY-DATA-01
func TestRFC3030Examples(t *testing.T) {
	for _, binary := range []bool{false, true} {
		t.Run(fmt.Sprint(binary), func(t *testing.T) {
			be, s, c, scanner, caps := testServerEhlo(t, func(s *server.Server) { s.EnableBINARYMIME = binary })
			defer s.Close()
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			if !caps["CHUNKING"] || caps["BINARYMIME"] != binary {
				t.Fatalf("capabilities: %v", caps)
			}
			body := "To: Susan@random.com\r\nFrom: Sam@random.com\r\nSubject: This is a bodyless test message\r\n"
			mail := "MAIL FROM:<Sam@Random.com>"
			if binary {
				mail = "MAIL FROM:<ned@ymir.claremont.edu> BODY=BINARYMIME"
			}
			chunkCommand(t, c, scanner, mail+"\r\n", "250")
			firstRecipient := "Susan@Random.com"
			if binary {
				firstRecipient = "gvaudre@cnri.reston.va.us"
			}
			chunkCommand(t, c, scanner, "RCPT TO:<"+firstRecipient+">\r\n", "250")
			if binary {
				chunkCommand(t, c, scanner, "RCPT TO:<jstewart@cnri.reston.va.us>\r\n", "250")
				// RFC §4.2 says 100000 in the command and response but 10000 in its
				// placeholder prose. Follow the wire count, with deterministic octets.
				octets := make([]byte, 100324)
				for i := range octets {
					octets[i] = byte(i)
				}
				copy(octets, "\r\n.\r\nBDAT 0 LAST\r\n")
				body = string(octets)
				batch := "BDAT 100000\r\n" + body[:100000] + "BDAT 324\r\n" + body[100000:] + "BDAT 0 LAST\r\n"
				if _, err := io.WriteString(c, batch); err != nil {
					t.Fatal(err)
				}
				for i := 0; i < 3; i++ {
					chunkReply(t, scanner, "250")
				}
			} else {
				if len(body) != 86 {
					t.Fatalf("RFC example length: %d", len(body))
				}
				chunkCommand(t, c, scanner, fmt.Sprintf("BDAT 86 LAST\r\n%s", body), "250")
			}
			if len(be.anonmsgs) != 1 || string(be.anonmsgs[0].Data) != body {
				t.Fatal("message octets changed")
			}
			// A new transaction can use DATA in this same CHUNKING session.
			chunkCommand(t, c, scanner, "MAIL FROM:<a@example.org>\r\n", "250")
			chunkCommand(t, c, scanner, "RCPT TO:<b@example.org>\r\n", "250")
			chunkCommand(t, c, scanner, "DATA\r\n", "354")
			chunkCommand(t, c, scanner, "text\r\n.\r\n", "250")
		})
	}
}

// checklist: CHUNK-ERROR-01 CHUNK-ERROR-02 CHUNK-STATE-01
func TestRFC3030RejectedChunksAreOpaque(t *testing.T) {
	for _, why := range []string{"no envelope", "no recipients", "after LAST", "size limit", "backend failure"} {
		t.Run(why, func(t *testing.T) {
			be, s, c, scanner, _ := testServerEhlo(t, func(s *server.Server) {
				s.MaxLineLength = 100
				if why == "size limit" {
					s.MaxMessageBytes = 1
				}
			})
			defer s.Close()
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			if why != "no envelope" {
				chunkCommand(t, c, scanner, "MAIL FROM:<a@example.org>\r\n", "250")
				if why != "no recipients" {
					chunkCommand(t, c, scanner, "RCPT TO:<b@example.org>\r\n", "250")
				}
			}
			if why == "after LAST" {
				chunkCommand(t, c, scanner, "BDAT 0 LAST\r\n", "250")
			}
			if why == "backend failure" {
				be.dataErr = &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "storage unavailable"}
			}
			payload := "MAIL FROM:<injected@example.org>\r\n" + strings.Repeat("x", 200) + "\r\n"
			code := "503"
			if why == "size limit" {
				code = "552"
			}
			if why == "backend failure" {
				code = "451"
			}
			// Both rejected chunks are already in the pipeline. Payload must never
			// be interpreted as commands, including the second chunk after reset.
			batch := fmt.Sprintf("BDAT %d\r\n%sBDAT %d LAST\r\n%sRSET\r\nNOOP\r\n", len(payload), payload, len(payload), payload)
			if _, err := io.WriteString(c, batch); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{code, "503", "250", "250"} {
				chunkReply(t, scanner, want)
			}
			if why != "after LAST" && len(be.anonmsgs) != 0 {
				t.Fatal("rejected chunk delivered")
			}
		})
	}
}

// checklist: BINARY-BODY-01 BINARY-BODY-02 CHUNK-STATE-02 CHUNK-STATE-03
func TestRFC3030BinaryAndResetRules(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			be, s, c, scanner, _ := testServerEhlo(t, func(s *server.Server) { s.EnableBINARYMIME = enabled })
			defer s.Close()
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			code := "504"
			if enabled {
				code = "250"
			}
			chunkCommand(t, c, scanner, "MAIL FROM:<a@example.org> BODY=BINARYMIME\r\n", code)
			if enabled {
				chunkCommand(t, c, scanner, "RCPT TO:<b@example.org>\r\n", "250")
				chunkCommand(t, c, scanner, "DATA\r\n", "503")
				chunkCommand(t, c, scanner, "RSET\r\n", "250")
			}
			for _, body := range []string{"7BIT", "8BITMIME"} {
				chunkCommand(t, c, scanner, "MAIL FROM:<a@example.org> BODY="+body+"\r\n", "250")
				chunkCommand(t, c, scanner, "RCPT TO:<b@example.org>\r\n", "250")
				chunkCommand(t, c, scanner, "BDAT 3\r\nold", "250")
				chunkCommand(t, c, scanner, "DATA\r\n", "503")
				chunkCommand(t, c, scanner, "RSET\r\n", "250")
				// RSET removes the accumulated bytes. A new transaction carries only
				// its own chunks, without the discarded prefix or old body selection.
				chunkCommand(t, c, scanner, "MAIL FROM:<a@example.org>\r\n", "250")
				chunkCommand(t, c, scanner, "RCPT TO:<b@example.org>\r\n", "250")
				chunkCommand(t, c, scanner, "BDAT 3 LAST\r\nnew", "250")
			}
			if len(be.anonmsgs) != 2 {
				t.Fatalf("delivered %d messages", len(be.anonmsgs))
			}
			for _, m := range be.anonmsgs {
				if string(m.Data) != "new" {
					t.Fatalf("reset leaked %q", m.Data)
				}
			}
		})
	}
}
