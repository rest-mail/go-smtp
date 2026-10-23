package client

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/emersion/go-sasl"
)

func authTranscript(t *testing.T, replies string, a sasl.Client) (string, error) {
	t.Helper()
	var wrote bytes.Buffer
	c := New(faker{ReadWriter: struct {
		io.Reader
		io.Writer
	}{strings.NewReader(replies), &wrote}})
	if err := c.greet(); err != nil {
		t.Fatal(err)
	}
	c.didHello = true
	defer c.Close()
	err := c.Auth(a)
	return wrote.String(), err
}

// checklist: SMTP-AUTH-32
func TestRFC4954_ClientChallengeIndependentOfLineLimit(t *testing.T) {
	run := func(t *testing.T, limit, size int, after string) (*rfc4954EchoClient, *Client, error) {
		t.Helper()
		challenge := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'c'}, size))
		replies := "220 ready\r\n334 " + challenge + "\r\n235 2.7.0 ok\r\n" + after
		var wrote bytes.Buffer
		c := New(faker{ReadWriter: struct {
			io.Reader
			io.Writer
		}{lineAtATimeReader{strings.NewReader(replies)}, &wrote}})
		c.MaxAuthChallengeLength = limit
		if err := c.greet(); err != nil {
			t.Fatal(err)
		}
		c.didHello = true
		t.Cleanup(func() { c.Close() })
		a := &rfc4954EchoClient{}
		return a, c, c.Auth(a)
	}
	t.Run("default accepts a challenge beyond the reply limit", func(t *testing.T) {
		a, _, err := run(t, 0, 30000, "")
		if err != nil || len(a.challenge) != 30000 {
			t.Fatalf("err=%v, challenge=%d octets", err, len(a.challenge))
		}
	})
	t.Run("negative means no limit", func(t *testing.T) {
		a, _, err := run(t, -1, 100000, "")
		if err != nil || len(a.challenge) != 100000 {
			t.Fatalf("err=%v, challenge=%d octets", err, len(a.challenge))
		}
	})
	t.Run("own bound refuses a longer challenge", func(t *testing.T) {
		a, _, err := run(t, 3000, 3000, "")
		if err == nil || a.challenge != nil {
			t.Fatalf("err=%v, challenge=%d octets", err, len(a.challenge))
		}
	})
	t.Run("reply limit returns after AUTH", func(t *testing.T) {
		_, c, err := run(t, 0, 3000, "250 "+strings.Repeat("x", 3000)+"\r\n")
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Noop(); err == nil {
			t.Fatal("a reply longer than the reply line limit was accepted after AUTH")
		}
	})
}

// lineAtATimeReader returns at most one line per Read, as a server that
// answers each command only after reading it would.
type lineAtATimeReader struct{ r *strings.Reader }

func (l lineAtATimeReader) Read(b []byte) (int, error) {
	n := 0
	for n < len(b) {
		c, err := l.r.ReadByte()
		if err != nil {
			if n > 0 {
				return n, nil
			}
			return 0, err
		}
		b[n] = c
		n++
		if c == '\n' {
			break
		}
	}
	return n, nil
}

type rfc4954EchoClient struct{ challenge []byte }

func (*rfc4954EchoClient) Start() (string, []byte, error) { return "TOKEN", nil, nil }

func (a *rfc4954EchoClient) Next(challenge []byte) ([]byte, error) {
	a.challenge = challenge
	return []byte("ok"), nil
}

type rfc4954Client struct{ response []byte }

func (a rfc4954Client) Start() (string, []byte, error) { return "PLAIN", a.response, nil }

func (rfc4954Client) Next([]byte) ([]byte, error) { return nil, fmt.Errorf("unexpected Next call") }

// checklist: SMTP-AUTH-12 SMTP-AUTH-11
func TestRFC4954_ClientInitialResponseLimit(t *testing.T) {
	for _, n := range []int{0, 372, 375, 12000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			response := bytes.Repeat([]byte{'a'}, n)
			encoded := base64.StdEncoding.EncodeToString(response)
			if n == 0 {
				encoded = "="
			}
			want := "AUTH PLAIN " + encoded + "\r\n"
			replies := "220 ready\r\n235 2.7.0 ok\r\n"
			if len(want) > 512 {
				want = "AUTH PLAIN\r\n" + encoded + "\r\n"
				replies = "220 ready\r\n334 \r\n235 2.7.0 ok\r\n"
			}
			got, err := authTranscript(t, replies, rfc4954Client{response})
			if err != nil || got != want {
				t.Fatalf("err=%v, output length=%d want=%d", err, len(got), len(want))
			}
		})
	}
}

// checklist: SMTP-AUTH-13 SMTP-AUTH-14
func TestRFC4954_ClientCancelAndFailure(t *testing.T) {
	for _, challenge := range []string{"!!!!", "=AAA", "AAA=BBB", "YW Jj", "YWJj\nZGVm"} {
		t.Run(challenge, func(t *testing.T) {
			reply := "334 " + challenge + "\r\n"
			if strings.Contains(challenge, "\n") {
				reply = "334-YWJj\r\n334 ZGVm\r\n"
			}
			got, err := authTranscript(t, "220 ready\r\n"+reply+"501 cancelled\r\n", rfc4954Client{})
			if err == nil || got != "AUTH PLAIN\r\n*\r\n" {
				t.Fatalf("err=%v, wrote=%q", err, got)
			}
		})
	}
	got, err := authTranscript(t, "220 ready\r\n535 5.7.8 denied\r\n", rfc4954Client{})
	if err == nil || got != "AUTH PLAIN\r\n" {
		t.Fatalf("err=%v, wrote=%q", err, got)
	}
	// An unexpected nonempty challenge cannot consume a deferred response.
	got, err = authTranscript(t, "220 ready\r\n334 YQ==\r\n501 cancelled\r\n", rfc4954Client{bytes.Repeat([]byte{'x'}, 400)})
	if err == nil || got != "AUTH PLAIN\r\n*\r\n" {
		t.Fatalf("err=%v, wrote=%q", err, got)
	}
}
