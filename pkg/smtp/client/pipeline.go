// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"errors"
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
// Rcpt — each writes its command immediately but does not read the response.
// Call Wait to read all queued responses, in order, ending the group; the
// Client is then back in synchronous mode, so a message body is sent with the
// usual Client.Data. A group larger than the assumed flow-control window (see
// pipelineWindow) is sent in window-sized parts: before writing past that window,
// the queueing method reads the responses already owed to reduce the risk of
// deadlock. The actual transport window is not checked. Every result is still
// reported by Wait, in queue order.
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
// responses will be read out of order. Callers must inspect every Wait result
// before sending content. If all recipients failed and a nonconforming peer
// nevertheless accepts Client.Data, close the unwritten writer to send only the
// terminating dot, check the final response, and reset the transaction.
type Pipeliner struct {
	c       *Client
	cmds    []pipelinedCmd // sent commands whose responses are not read yet
	errs    []error        // results already read for this group, in queue order
	pending int            // bytes of cmds' command lines, CRLF included
	err     error          // I/O error that put the connection out of step
}

// pipelineWindow is the most command bytes a Pipeliner leaves unanswered.
//
// The Pipeliner does not read responses while it writes, so RFC 2920 section 3.1
// requires it to make each group fit within the TCP window, "usually, but not
// always, 4K octets". Otherwise a big group (issue #78) deadlocks: the server
// stops reading because its replies have filled the buffers, and the client
// stops reading because it is still blocked writing commands. Keeping at most
// this many bytes outstanding reduces that risk when the transport provides at
// least this window. It is not a discovered TCP window: smaller windows (or a single command larger than
// the window) can still deadlock until CommandTimeout. This is a known RFC 2920
// section 3.1 conformance gap; see PIPE-CLIENT-07 in CHECKLIST.md.
const pipelineWindow = 4096

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

// enqueue writes a command line without reading its response and records it for
// Wait. The command line is always sent verbatim (as a "%s" argument) so any
// '%' in an address is not treated as a format directive.
//
// If the line would take the unanswered commands past pipelineWindow, the
// responses owed so far are read first. After an I/O error (a failed write, or
// a failed or timed-out read) the connection is out of step, so enqueue sends
// nothing more and returns that error.
func (p *Pipeliner) enqueue(cmd pipelinedCmd, line string) error {
	if p.err != nil {
		return p.err
	}
	n := len(line) + len("\r\n")
	if p.pending > 0 && p.pending+n > pipelineWindow {
		p.readResponses()
		if p.err != nil {
			return p.err
		}
	}

	p.c.conn.SetWriteDeadline(time.Now().Add(p.c.CommandTimeout))
	defer p.c.conn.SetWriteDeadline(time.Time{})

	id, err := p.c.text.Cmd("%s", line)
	if err != nil {
		p.err = err
		return err
	}
	cmd.id = id
	p.cmds = append(p.cmds, cmd)
	p.pending += n
	return nil
}

// readResponses reads the response to every sent command, in order, appending
// each result to p.errs and applying each success's state change. A response
// the server rejected is an *SMTPError and the next one is still read; any other
// read error means the reply stream can no longer be matched to commands, so it
// becomes the result of every command still unanswered and is kept in p.err.
// Responses are read even after a failed write: the commands sent before it
// were whole, and their replies come first.
func (p *Pipeliner) readResponses() {
	p.c.conn.SetReadDeadline(time.Now().Add(p.c.CommandTimeout))
	defer p.c.conn.SetReadDeadline(time.Time{})

	var readErr error
	for _, cmd := range p.cmds {
		// Every id must pass through the response sequence, even unread, or
		// the Client's next command would wait for its turn forever.
		p.c.text.StartResponse(cmd.id)
		err := readErr
		if err == nil {
			_, _, err = p.c.readResponse(cmd.expectCode)
			var smtpErr *smtp.SMTPError
			if err != nil && !errors.As(err, &smtpErr) {
				readErr = err
			}
		}
		p.c.text.EndResponse(cmd.id)

		p.errs = append(p.errs, err)
		if err != nil {
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
	if p.err == nil {
		p.err = readErr
	}
	p.cmds = nil
	p.pending = 0
}

// Wait reads the server responses to all queued commands, in order, and returns
// one error per command index-aligned with the order the commands were queued
// (nil means that command succeeded; a rejection is an *SMTPError). It ends the
// pipelined group: the Client returns to synchronous operation and the
// Pipeliner is drained, so it can be reused for another group.
//
// The state changes of the successful commands are applied in queue order as
// their responses are read (by Wait, or earlier by a queueing method once the
// group passes the flow-control window): a successful RSET or MAIL clears the
// recipient set, and a successful RCPT adds its recipient to the set used by
// the subsequent Data (or LMTP) call.
//
// The result of a command whose response could not be read (the connection
// failed, closed or timed out) is that I/O error. The connection is then out of
// step: every later command queued on this Pipeliner fails with the same
// error, and the Client should be closed.
//
// Wait returns nil when no commands are queued.
func (p *Pipeliner) Wait() []error {
	if len(p.cmds) == 0 && len(p.errs) == 0 {
		return nil
	}
	p.readResponses()
	errs := p.errs
	p.errs = nil
	return errs
}
