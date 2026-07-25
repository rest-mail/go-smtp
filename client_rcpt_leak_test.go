// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package smtp

import (
	"bufio"
	"bytes"
	"net/textproto"
	"reflect"
	"strings"
	"testing"
)

// scriptedClient returns a Client whose reads are served from the given
// (already CRLF-terminated) server script and whose writes are discarded. The
// greeting and hello exchanges are marked done so tests can drive commands
// directly.
func scriptedClient(serverScript string) *Client {
	var fake faker
	fake.ReadWriter = bufio.NewReadWriter(
		bufio.NewReader(strings.NewReader(serverScript)),
		bufio.NewWriter(&bytes.Buffer{}),
	)
	return &Client{
		text:     textproto.NewConn(fake),
		conn:     fake,
		didGreet: true,
		didHello: true,
	}
}

// TestClientMailClearsRcpts is a regression test for issue #45: recipients
// accumulated in one transaction must not leak into the next. Starting a new
// MAIL transaction has to clear the client's recipient bookkeeping, otherwise a
// reused connection carries stale recipients forward (unbounded growth for
// SMTP, response misattribution for LMTP).
func TestClientMailClearsRcpts(t *testing.T) {
	script := "250 Sender OK\r\n" + // MAIL (transaction 1)
		"250 Receiver OK\r\n" + // RCPT a
		"250 Receiver OK\r\n" + // RCPT b
		"250 Sender OK\r\n" // MAIL (transaction 2)
	c := scriptedClient(script)

	if err := c.Mail("from1@example.com", nil); err != nil {
		t.Fatalf("MAIL 1: %v", err)
	}
	if err := c.Rcpt("a@example.com", nil); err != nil {
		t.Fatalf("RCPT a: %v", err)
	}
	if err := c.Rcpt("b@example.com", nil); err != nil {
		t.Fatalf("RCPT b: %v", err)
	}

	// Begin a new transaction without an explicit Reset.
	if err := c.Mail("from2@example.com", nil); err != nil {
		t.Fatalf("MAIL 2: %v", err)
	}

	if len(c.rcpts) != 0 {
		t.Fatalf("after a new MAIL, c.rcpts = %v; want empty (recipients leaked across transactions)", c.rcpts)
	}
}

// TestLMTPRcptLeakAcrossTransactions reproduces the concrete LMTP symptom from
// issue #45: two messages on a reused LMTP connection, the first with two
// recipients and the second with one, without an intervening Reset. Because
// CloseWithLMTPResponse reads exactly len(c.rcpts) per-recipient replies, a
// leaked recipient list makes the second message consume the wrong replies and
// then read past the end of the server's output.
func TestLMTPRcptLeakAcrossTransactions(t *testing.T) {
	script := "250 Sender OK\r\n" + // MAIL 1
		"250 Receiver OK\r\n" + // RCPT 1a
		"250 Receiver OK\r\n" + // RCPT 1b
		"354 Go ahead\r\n" + // DATA 1
		"250 rcpt1a delivered\r\n" + // LMTP data reply 1a
		"250 rcpt1b delivered\r\n" + // LMTP data reply 1b
		"250 Sender OK\r\n" + // MAIL 2
		"250 Receiver OK\r\n" + // RCPT 2
		"354 Go ahead\r\n" + // DATA 2
		"250 rcpt2 delivered\r\n" // LMTP data reply 2 (only one)
	c := scriptedClient(script)
	c.lmtp = true

	msg := "Subject: hi\r\n\r\nbody\r\n"

	// Message 1: two recipients.
	if err := c.Mail("from1@example.com", nil); err != nil {
		t.Fatalf("MAIL 1: %v", err)
	}
	for _, rcpt := range []string{"rcpt1a@example.com", "rcpt1b@example.com"} {
		if err := c.Rcpt(rcpt, nil); err != nil {
			t.Fatalf("RCPT %s: %v", rcpt, err)
		}
	}
	w1, err := c.Data()
	if err != nil {
		t.Fatalf("DATA 1: %v", err)
	}
	if _, err := w1.Write([]byte(msg)); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if _, err := w1.CloseWithLMTPResponse(); err != nil {
		t.Fatalf("message 1 close: %v", err)
	}

	// Message 2: a single recipient, reusing the connection without Reset.
	if err := c.Mail("from2@example.com", nil); err != nil {
		t.Fatalf("MAIL 2: %v", err)
	}
	if err := c.Rcpt("rcpt2@example.com", nil); err != nil {
		t.Fatalf("RCPT 2: %v", err)
	}
	w2, err := c.Data()
	if err != nil {
		t.Fatalf("DATA 2: %v", err)
	}
	if _, err := w2.Write([]byte(msg)); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	resp2, err := w2.CloseWithLMTPResponse()
	if err != nil {
		t.Fatalf("message 2 close: %v (recipients leaked from message 1)", err)
	}

	want := map[string]*DataResponse{
		"rcpt2@example.com": {StatusText: "rcpt2 delivered"},
	}
	if !reflect.DeepEqual(resp2, want) {
		t.Fatalf("message 2 response = %v; want %v (stale recipients from message 1 leaked in)", resp2, want)
	}
}

// TestPipelinerMailClearsRcpts is the pipelined counterpart of issue #45: a
// pipelined MAIL that succeeds in Pipeliner.Wait must clear any recipients left
// over from a prior transaction, just as the synchronous Client.Mail does.
func TestPipelinerMailClearsRcpts(t *testing.T) {
	script := "250 Sender OK\r\n" + // MAIL old (synchronous)
		"250 Receiver OK\r\n" + // RCPT stray (synchronous)
		"250 Sender OK\r\n" + // MAIL from (pipelined)
		"250 Receiver OK\r\n" // RCPT real (pipelined)
	c := scriptedClient(script)
	c.ext = map[string]string{"PIPELINING": ""}

	// A stray recipient left over from an earlier transaction.
	if err := c.Mail("old@example.com", nil); err != nil {
		t.Fatalf("MAIL old: %v", err)
	}
	if err := c.Rcpt("stray@example.com", nil); err != nil {
		t.Fatalf("RCPT stray: %v", err)
	}

	p, err := c.Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if err := p.Mail("from@example.com", nil); err != nil {
		t.Fatalf("queue MAIL: %v", err)
	}
	if err := p.Rcpt("real@example.com", nil); err != nil {
		t.Fatalf("queue RCPT: %v", err)
	}
	for i, e := range p.Wait() {
		if e != nil {
			t.Fatalf("pipelined command %d: %v", i, e)
		}
	}

	want := []string{"real@example.com"}
	if !reflect.DeepEqual(c.rcpts, want) {
		t.Fatalf("after pipelined MAIL, c.rcpts = %v; want %v (stray recipient leaked across transactions)", c.rcpts, want)
	}
}
