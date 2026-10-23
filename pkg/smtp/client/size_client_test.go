package client

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"

	"github.com/rest-mail/go-smtp/pkg/smtp"
)

// checklist: SIZE-CLIENT-01 SIZE-CLIENT-02
func TestRFC1870ClientDeclarations(t *testing.T) {
	for _, advertised := range []bool{false, true} {
		c := &Client{ext: make(map[string]string)}
		if advertised {
			c.ext["SIZE"] = "0"
		}
		for _, size := range []int64{-1, 0, 1, 1 << 40} {
			cmd, err := c.buildMailCmd("a@example.org", &smtp.MailOptions{Size: size})
			if size < 0 {
				if err == nil {
					t.Errorf("negative SIZE accepted (advertised=%v): %q", advertised, cmd)
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, want := strings.Contains(cmd, " SIZE="), advertised && size != 0; got != want {
				t.Errorf("SIZE inclusion for %d, advertised=%v: %q", size, advertised, cmd)
			}
		}
	}
}

// A successful MAIL estimate is no guarantee that DATA will succeed.
// checklist: SIZE-CLIENT-03
func TestRFC1870ClientFailures(t *testing.T) {
	for _, stage := range []string{"MAIL", "RCPT", "DATA", "content"} {
		for _, code := range []int{452, 552} {
			t.Run(fmt.Sprintf("%s/%d", stage, code), func(t *testing.T) {
				failure := fmt.Sprintf("%d %d.3.4 size refused\r\n", code, code/100)
				replies := "220 ready\r\n250-server\r\n250 SIZE 1000000\r\n"
				for _, step := range []string{"MAIL", "RCPT", "DATA", "content"} {
					if step == stage {
						replies += failure
						break
					}
					if step == "DATA" {
						replies += "354 send content\r\n"
					} else {
						replies += "250 accepted\r\n"
					}
				}
				var sent bytes.Buffer
				c := New(faker{ReadWriter: struct {
					io.Reader
					io.Writer
				}{strings.NewReader(replies), &sent}})
				defer c.Close()
				err := c.Mail("a@example.org", &smtp.MailOptions{Size: 100})
				if stage != "MAIL" {
					if err != nil {
						t.Fatal(err)
					}
					err = c.Rcpt("b@example.org", nil)
				}
				if stage == "DATA" || stage == "content" {
					if err != nil {
						t.Fatal(err)
					}
					var data *DataCommand
					data, err = c.Data()
					if stage == "content" {
						if err != nil {
							t.Fatal(err)
						}
						if _, err = io.WriteString(data, "Subject: size\r\n\r\nsmall\r\n"); err != nil {
							t.Fatal(err)
						}
						err = data.Close()
					}
				}
				var smtpErr *smtp.SMTPError
				if !errors.As(err, &smtpErr) || smtpErr.Code != code || smtpErr.Temporary() != (code == 452) {
					t.Fatalf("%s returned %v, want SMTPError %d", stage, err, code)
				}
				if !strings.Contains(sent.String(), "MAIL FROM:<a@example.org> SIZE=100\r\n") {
					t.Fatalf("missing declaration: %q", sent.String())
				}
			})
		}
	}
}

// checklist: SIZE-EHLO-03
func TestRFC1870ClientLimits(t *testing.T) {
	for _, tc := range []struct {
		value string
		size  int
		ok    bool
	}{
		{"", 0, false}, {"0", 0, true}, {"1000000", 1000000, true},
		{"+1", 0, false}, {"-1", 0, false}, {"1 2", 0, false},
		{"rabbit", 0, false}, {"999999999999999999999999999999", 0, false},
	} {
		c := &Client{didHello: true, ext: map[string]string{"SIZE": tc.value}}
		if size, ok := c.MaxMessageSize(); size != tc.size || ok != tc.ok {
			t.Errorf("SIZE %q: (%d,%v), want (%d,%v)", tc.value, size, ok, tc.size, tc.ok)
		}
	}
}

// Use an arbitrary-precision reference so malformed or overflowing EHLO
// limits cannot silently turn into a smaller, valid client-side limit.
// checklist: SIZE-EHLO-03
func FuzzRFC1870SizeValues(f *testing.F) {
	for _, seed := range []string{"", "0", "000001", "4294967296", "9223372036854775807", "99999999999999999999", "+1", "-1", "1 2", "１２", "\x00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 4096 {
			t.Skip()
		}
		c := &Client{didHello: true, ext: map[string]string{"SIZE": value}}
		got, ok := c.MaxMessageSize()
		ref, parsed := new(big.Int).SetString(value, 10)
		wantOK := parsed && value != "" && strings.Trim(value, "0123456789") == "" && ref.Sign() >= 0 && ref.Cmp(big.NewInt(int64(int(^uint(0)>>1)))) <= 0
		if ok != wantOK {
			t.Fatalf("SIZE %q: valid=%v, want %v", value, ok, wantOK)
		}
		if ok && int64(got) != ref.Int64() {
			t.Fatalf("SIZE %q: got %d, want %s", value, got, ref)
		}
	})
}
