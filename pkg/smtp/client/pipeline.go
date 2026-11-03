// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"errors"
	"sync"
	"time"

	"github.com/rest-mail/go-smtp/pkg/smtp"
)

// Pipeliner sends a group of RSET, MAIL FROM and RCPT TO commands using the
// PIPELINING extension (RFC 2920): the commands are written back-to-back
// without the client waiting for a response between them, saving a network
// round-trip per command for high-throughput senders.
//
// Those three are the only commands this API permits inside a pipelined group.
// EHLO, DATA, VRFY and QUIT must end a group, so they are issued afterwards with
// the Client's normal (synchronous) methods.
//
// Obtain a Pipeliner with Client.Pipeline. Queue commands with Reset, Mail and
// Rcpt — each writes its command immediately but does not wait for the
// response. Call Wait to collect all queued responses, in order, ending the
// group; the Client is then back in synchronous mode, so a message body is sent
// with the usual Client.Data.
//
// While a group is open the responses are read on a separate goroutine as they
// arrive, so a group of any size cannot deadlock against a server that stops
// reading commands until its replies are read (RFC 2920 section 3.1). The size
// of the transport's buffers does not matter, and neither does the length of a
// single command.
//
//	p, err := c.Pipeline()
//	if err != nil {
//		// server does not support PIPELINING; fall back to c.Mail/c.Rcpt
//	}
//	p.Mail(from, nil)
//	for _, rcpt := range rcpts {
//		p.Rcpt(rcpt, nil)
//	}
//	errs := p.Wait() // errs[0] is MAIL's result, errs[1:] the RCPTs' in order
//	w, err := c.Data()
//	// ... write the message, w.Close() ...
//
// A Pipeliner must not be used concurrently, and no other method of the
// underlying Client may be called between the first queued command and Wait, or
// responses will be read out of order. Every group must end with Wait, which
// also stops the reading goroutine. Callers must inspect every Wait result
// before sending content. If all recipients failed and a nonconforming peer
// nevertheless accepts Client.Data, close the unwritten writer to send only the
// terminating dot, check the final response, and reset the transaction.
type Pipeliner struct {
	c       *Client
	cmds    []pipelinedCmd // commands queued in this group, in order
	err     error          // I/O error that put the connection out of step
	reading bool           // a reader goroutine is running for this group
	done    chan struct{}  // closed when that reader has finished

	// Shared with the reader goroutine, under mu.
	mu     sync.Mutex
	wake   *sync.Cond      // signalled when sent grows or closed is set
	sent   []pipelinedSent // commands written and not yet taken by the reader
	closed bool            // Wait has been called: no more commands will come
	ioErr  error           // the reader's I/O error, seen by later enqueues

	// Written only by the reader, read by Wait once done is closed.
	errs []error // one result per queued command, in order
}

// pipelinedSent is one command line written to the server, handed to the
// reader. A line whose write failed is still handed over with skip set, so its
// id passes through the response sequence without a response being read.
type pipelinedSent struct {
	id         uint
	expectCode int
	skip       bool
}

type pipelineKind int

const (
	pipelineReset pipelineKind = iota
	pipelineMail
	pipelineRcpt
)

type pipelinedCmd struct {
	expectCode int
	kind       pipelineKind
	rcpt       string // recipient address, for pipelineRcpt
}

// Pipeline begins a pipelined command group (see Pipeliner).
//
// It returns an error if the server has not advertised the PIPELINING extension
// (RFC 2920): pipelining to a server that has not opted in risks the server
// processing a command, replying, and closing the connection before it reads
// the rest of the group. Callers should fall back to the one-at-a-time Mail and
// Rcpt methods in that case.
func (c *Client) Pipeline() (*Pipeliner, error) {
	if err := c.hello(); err != nil {
		return nil, err
	}
	if _, ok := c.ext["PIPELINING"]; !ok {
		return nil, errors.New("smtp: server does not support PIPELINING")
	}
	return &Pipeliner{c: c}, nil
}

// Reset queues an RSET command, aborting the current mail transaction. Unlike
// Client.Reset it does not reset the greeting state (a pipelined group stays
// within one session); when Wait reads a successful response, the pending
// recipient list is cleared.
func (p *Pipeliner) Reset() error {
	p.c.utf8 = false
	return p.enqueue(pipelinedCmd{expectCode: 2, kind: pipelineReset}, "RSET")
}

// Mail queues a MAIL FROM command. Option handling matches Client.Mail. The
// error is non-nil only if the command could not be composed or sent (e.g.
// local validation failed, the write failed, or the connection failed earlier
// in the group); the server's response is read later by Wait.
func (p *Pipeliner) Mail(from string, opts *smtp.MailOptions) error {
	cmd, err := p.c.buildMailCmd(from, opts)
	if err != nil {
		return err
	}
	return p.enqueue(pipelinedCmd{expectCode: 2, kind: pipelineMail}, cmd)
}

// Rcpt queues a RCPT TO command. Option handling matches Client.Rcpt. The error
// is non-nil only if the command could not be composed or sent; the server's
// response is read later by Wait, and on success the recipient is added to the
// set used by a subsequent Data (or LMTP) call.
func (p *Pipeliner) Rcpt(to string, opts *smtp.RcptOptions) error {
	cmd, err := p.c.buildRcptCmd(to, opts)
	if err != nil {
		return err
	}
	return p.enqueue(pipelinedCmd{expectCode: 2, kind: pipelineRcpt, rcpt: to}, cmd)
}

// enqueue writes a command line without waiting for its response and records
// it for Wait. The command line is always sent verbatim (as a "%s" argument) so
// any '%' in an address is not treated as a format directive.
//
// The first command of a group starts the reader. After an I/O error (a failed
// write, or a failed or timed-out read) the connection is out of step, so
// enqueue sends nothing more and returns that error.
func (p *Pipeliner) enqueue(cmd pipelinedCmd, line string) error {
	if p.err == nil {
		p.err = p.readError()
	}
	if p.err != nil {
		return p.err
	}
	if !p.reading {
		p.startReader()
	}

	p.c.conn.SetWriteDeadline(time.Now().Add(p.c.CommandTimeout))
	defer p.c.conn.SetWriteDeadline(time.Time{})

	// textproto.Conn.Cmd, except that the id of a failed write is kept: every
	// id must pass through the response sequence, or the Client's next command
	// would wait for its turn forever.
	text := p.c.text
	id := text.Next()
	text.StartRequest(id)
	err := text.PrintfLine("%s", line)
	text.EndRequest(id)
	if err != nil {
		p.err = err
		p.hand(pipelinedSent{id: id, skip: true})
		return err
	}
	p.cmds = append(p.cmds, cmd)
	p.hand(pipelinedSent{id: id, expectCode: cmd.expectCode})
	return nil
}

// hand passes a written command to the reader. The queue is unbounded, so the
// writer never waits for the reader: it only ever blocks on the transport.
func (p *Pipeliner) hand(s pipelinedSent) {
	p.mu.Lock()
	p.sent = append(p.sent, s)
	p.mu.Unlock()
	p.wake.Signal()
}

// next returns the next written command for the reader, waiting for one; ok is
// false once Wait has been called and every command has been taken.
func (p *Pipeliner) next() (s pipelinedSent, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.sent) == 0 && !p.closed {
		p.wake.Wait()
	}
	if len(p.sent) == 0 {
		return pipelinedSent{}, false
	}
	s = p.sent[0]
	p.sent = p.sent[1:]
	return s, true
}

func (p *Pipeliner) readError() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ioErr
}

// startReader starts the goroutine that reads the responses of this group.
//
// It reads the response to every command it is handed, in order, appending each
// result to p.errs. A response the server rejected is an *SMTPError and the next
// one is still read; any other read error means the reply stream can no longer
// be matched to commands, so it becomes the result of every command still
// unanswered. Each response gets its own CommandTimeout, armed only once its
// command is written, so a caller that is slow to queue the next command cannot
// make a read time out.
//
// Only the reader touches p.errs and reads from the connection until it closes
// p.done.
func (p *Pipeliner) startReader() {
	if p.wake == nil {
		p.wake = sync.NewCond(&p.mu)
	}
	p.reading, p.closed = true, false
	p.done = make(chan struct{})
	c, done := p.c, p.done
	go func() {
		defer close(done)
		defer c.conn.SetReadDeadline(time.Time{})
		var readErr error
		for {
			s, ok := p.next()
			if !ok {
				return
			}
			c.text.StartResponse(s.id)
			if s.skip {
				c.text.EndResponse(s.id)
				continue
			}
			err := readErr
			if err == nil {
				c.conn.SetReadDeadline(time.Now().Add(c.CommandTimeout))
				_, _, err = c.readResponse(s.expectCode)
				var smtpErr *smtp.SMTPError
				if err != nil && !errors.As(err, &smtpErr) {
					readErr = err
					p.mu.Lock()
					p.ioErr = err
					p.mu.Unlock()
				}
			}
			c.text.EndResponse(s.id)
			p.errs = append(p.errs, err)
		}
	}()
}

// Wait collects the server responses to all queued commands, in order, and
// returns one error per command index-aligned with the order the commands were
// queued (nil means that command succeeded; a rejection is an *SMTPError). It
// ends the pipelined group: the Client returns to synchronous operation and the
// Pipeliner is drained, so it can be reused for another group.
//
// The state changes of the successful commands are applied in queue order: a
// successful RSET or MAIL clears the recipient set, and a successful RCPT adds
// its recipient to the set used by the subsequent Data (or LMTP) call.
//
// The result of a command whose response could not be read (the connection
// failed, closed or timed out) is that I/O error. The connection is then out of
// step: every later command queued on this Pipeliner fails with the same
// error, and the Client should be closed.
//
// Wait returns nil when no commands are queued.
func (p *Pipeliner) Wait() []error {
	if !p.reading {
		return nil
	}
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.wake.Signal()
	<-p.done
	p.reading, p.done = false, nil
	if p.err == nil {
		p.err = p.readError()
	}

	errs := p.errs
	for i, cmd := range p.cmds {
		if errs[i] != nil {
			continue
		}
		switch cmd.kind {
		case pipelineReset, pipelineMail:
			// RSET aborts the current transaction and MAIL begins a new one;
			// either way any recipients from a previous message must be
			// dropped so they don't leak into this one (issue #45).
			p.c.rcpts = nil
		case pipelineRcpt:
			p.c.rcpts = append(p.c.rcpts, cmd.rcpt)
		}
	}
	p.cmds, p.errs = nil, nil
	if len(errs) == 0 {
		return nil
	}
	return errs
}
