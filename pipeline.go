// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package smtp

import (
	"errors"
	"time"
)

// Pipeliner sends a group of RSET, MAIL FROM and RCPT TO commands using the
// PIPELINING extension (RFC 2920): the commands are written back-to-back
// without the client waiting for a response between them, saving a network
// round-trip per command for high-throughput senders.
//
// Those three are the only commands RFC 2920 permits inside a pipelined group.
// EHLO, DATA, VRFY and QUIT must end a group, so they are issued afterwards with
// the Client's normal (synchronous) methods.
//
// Obtain a Pipeliner with Client.Pipeline. Queue commands with Reset, Mail and
// Rcpt — each writes its command immediately but does not read the response.
// Call Wait to read all queued responses, in order, ending the group; the
// Client is then back in synchronous mode, so a message body is sent with the
// usual Client.Data:
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
// responses will be read out of order.
type Pipeliner struct {
	c    *Client
	cmds []pipelinedCmd
}

type pipelineKind int

const (
	pipelineReset pipelineKind = iota
	pipelineMail
	pipelineRcpt
)

type pipelinedCmd struct {
	id         uint
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
	return p.enqueue(pipelinedCmd{expectCode: 250, kind: pipelineReset}, "RSET")
}

// Mail queues a MAIL FROM command. Option handling matches Client.Mail. The
// error is non-nil only if the command could not be composed or sent (e.g.
// local validation failed or the write failed); the server's response is read
// later by Wait.
func (p *Pipeliner) Mail(from string, opts *MailOptions) error {
	cmd, err := p.c.buildMailCmd(from, opts)
	if err != nil {
		return err
	}
	return p.enqueue(pipelinedCmd{expectCode: 250, kind: pipelineMail}, cmd)
}

// Rcpt queues a RCPT TO command. Option handling matches Client.Rcpt. The error
// is non-nil only if the command could not be composed or sent; the server's
// response is read later by Wait, and on success the recipient is added to the
// set used by a subsequent Data (or LMTP) call.
func (p *Pipeliner) Rcpt(to string, opts *RcptOptions) error {
	cmd, err := p.c.buildRcptCmd(to, opts)
	if err != nil {
		return err
	}
	return p.enqueue(pipelinedCmd{expectCode: 25, kind: pipelineRcpt, rcpt: to}, cmd)
}

// enqueue writes a command line without reading its response and records it for
// Wait. The command line is always sent verbatim (as a "%s" argument) so any
// '%' in an address is not treated as a format directive.
func (p *Pipeliner) enqueue(cmd pipelinedCmd, line string) error {
	p.c.conn.SetWriteDeadline(time.Now().Add(p.c.CommandTimeout))
	defer p.c.conn.SetWriteDeadline(time.Time{})

	id, err := p.c.text.Cmd("%s", line)
	if err != nil {
		return err
	}
	cmd.id = id
	p.cmds = append(p.cmds, cmd)
	return nil
}

// Wait reads the server responses to all queued commands, in order, and returns
// one error per command index-aligned with the order the commands were queued
// (nil means that command succeeded; a rejection is an *SMTPError). It ends the
// pipelined group: the Client returns to synchronous operation and the
// Pipeliner is drained, so it can be reused for another group.
//
// Wait applies the state changes of the successful commands as it reads them: a
// successful RSET clears the recipient set, and a successful RCPT adds its
// recipient to the set used by the subsequent Data (or LMTP) call.
//
// Wait returns nil when no commands are queued.
func (p *Pipeliner) Wait() []error {
	if len(p.cmds) == 0 {
		return nil
	}

	p.c.conn.SetDeadline(time.Now().Add(p.c.CommandTimeout))
	defer p.c.conn.SetDeadline(time.Time{})

	errs := make([]error, len(p.cmds))
	for i, cmd := range p.cmds {
		p.c.text.StartResponse(cmd.id)
		_, _, err := p.c.readResponse(cmd.expectCode)
		p.c.text.EndResponse(cmd.id)

		errs[i] = err
		if err != nil {
			continue
		}
		switch cmd.kind {
		case pipelineReset:
			p.c.rcpts = nil
		case pipelineRcpt:
			p.c.rcpts = append(p.c.rcpts, cmd.rcpt)
		}
	}
	p.cmds = nil
	return errs
}
