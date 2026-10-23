package client

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestDataCloseHonoursWriteDeadline covers issue #53 item 6: the DATA
// terminating flush must be bounded by a write deadline so a wedged peer that
// stops reading cannot block the close write forever.
//
// checklist: SMTP-SRV-02 SMTP-LIM-09
func TestDataCloseHonoursWriteDeadline(t *testing.T) {
	cconn, sconn := net.Pipe()
	defer func() { _ = cconn.Close() }()
	defer func() { _ = sconn.Close() }()

	c := New(cconn)
	c.DataTransferTimeout = 100 * time.Millisecond

	// Build a DATA writer directly, skipping the DATA handshake. net.Pipe is
	// unbuffered, so with nothing reading sconn the terminating flush blocks
	// until the write deadline fires.
	cmd := &DataCommand{client: c, wc: c.text.DotWriter()}
	if _, err := io.WriteString(cmd, "Subject: x\r\n\r\nbody\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.close() }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("close returned nil; expected a write-deadline timeout")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close hung: terminating flush ignored the write deadline")
	}
}
