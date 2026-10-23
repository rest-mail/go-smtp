package server

import (
	"strings"
	"testing"
)

// A synchronization command must end a reply batch even when another complete
// command is already buffered. Counting writes detects deferral to that command.
// checklist: PIPE-SERVER-01 PIPE-SERVER-05 PIPE-SERVER-06 PIPE-SERVER-09
func TestRFC2920SynchronizationFlush(t *testing.T) {
	for _, tc := range []struct{ command, code string }{
		{"NOOP", "250"}, {"EHLO again.example", "250"},
		{"VRFY user", "252"}, {"EXPN list", "502"}, {"TURN", "502"},
		{"DATA", "503"}, {"XXXX", "500"}, {"BOGUS", "501"}, {"", "500"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			wc, c, br, _ := newFlushTestConn(t, nil)
			writeFlushBatch(t, c, "EHLO localhost\r\n")
			readFlushReply(t, br)
			wc.takeWrites()
			writeFlushBatch(t, c, "MAIL FROM:<a@example.org>\r\n"+tc.command+"\r\nRSET\r\n")
			want := []string{"250", tc.code, "250"}
			if got := readFlushCodes(t, br, len(want)); strings.Join(got, " ") != strings.Join(want, " ") {
				t.Fatalf("codes = %v, want %v", got, want)
			}
			writes := wc.takeWrites()
			if len(writes) != 2 {
				t.Fatalf("got %d writes, want synchronization reply flushed before RSET: %q", len(writes), writes)
			}
			if !strings.HasSuffix(writes[1], "Session reset\r\n") || strings.Contains(writes[0], "Session reset") {
				t.Fatalf("RSET reply was not separate: %q", writes)
			}
		})
	}
}
