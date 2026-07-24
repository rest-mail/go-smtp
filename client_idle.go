// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package smtp

import (
	"errors"
	"net"
	"time"
)

// errIdleData is returned by CheckConn when the connection is not cleanly idle:
// bytes are already waiting to be read, which a well-behaved server does not
// send between commands. The connection must not be reused.
var errIdleData = errors.New("smtp: unexpected data on idle connection")

// CheckConn reports whether a pooled connection that has been sitting idle is
// still usable, detecting the common case where the server closed it while it
// was idle. It performs a read-ahead only: it never sends a command, so it adds
// no round-trip and cannot disturb an in-flight transaction.
//
// It must be called only when the client is idle — no command is awaiting a
// response and no DATA transfer is in progress. On such a connection the server
// sends nothing until the next command, so CheckConn interprets a read as
// follows:
//
//   - the read blocks for up to timeout and returns no data: the connection
//     appears healthy and CheckConn returns nil;
//   - the read reports the peer has closed the connection (io.EOF or another
//     error): CheckConn returns that error;
//   - data is already waiting, or arrives: the server sent something
//     unsolicited, so the connection is not cleanly idle and CheckConn returns a
//     non-nil error.
//
// A non-nil result means the connection should be closed and not reused. Because
// the check is a best-effort probe, a healthy result is not a guarantee the next
// command will succeed; a small positive timeout (e.g. a few tens of
// milliseconds) gives an in-flight FIN time to arrive, while timeout <= 0 makes
// it a pure non-blocking poll.
//
// CheckConn is safe on a STARTTLS/implicit-TLS connection: the probe reads
// through the *tls.Conn, which preserves any partially received TLS record
// internally when the read times out, so a subsequent command reads the stream
// intact. It never reads the raw socket beneath the TLS layer.
func (c *Client) CheckConn(timeout time.Duration) error {
	// If bytes are already buffered, the peer sent something we did not read as
	// part of a response — the connection is not cleanly idle.
	if c.text.R.Buffered() > 0 {
		return errIdleData
	}

	deadline := time.Now()
	if timeout > 0 {
		deadline = deadline.Add(timeout)
	}
	if err := c.conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	defer c.conn.SetReadDeadline(time.Time{})

	var buf [1]byte
	n, err := c.conn.Read(buf[:])
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			// No data arrived within the window: the idle connection is healthy.
			return nil
		}
		// io.EOF or any other read error: the server closed or the link broke.
		return err
	}
	if n > 0 {
		// Unsolicited data on an idle connection: consumed here and discarded, so
		// the caller must not reuse the connection.
		return errIdleData
	}
	return nil
}
