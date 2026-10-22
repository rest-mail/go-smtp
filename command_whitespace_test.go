package smtp

import (
	"strings"
	"testing"
)

// Trailing ASCII whitespace is tolerated without turning other bytes into
// separators or accepting a longer verb as a known command.
// checklist: SMTP-SYN-16
func TestParseCmdTrailingWhitespace(t *testing.T) {
	for _, tc := range []struct{ line, cmd, arg string }{
		{"noop", "NOOP", ""},
		{"DATA", "DATA", ""},
		{"RSET", "RSET", ""},
		{"QUIT", "QUIT", ""},
		{"STARTTLS", "STARTTLS", ""},
		{"XCLIENT", "XCLIENT", ""},
		{"HELO client.example", "HELO", "client.example"},
		{"MAIL FROM:<\"a b\"@example.org>", "MAIL", "FROM:<\"a b\"@example.org>"},
		{"NOOP x\u00a0", "NOOP", "x\u00a0"},
		{"NOOP \xff", "NOOP", "\xff"},
		{"STARTTLS forbidden", "STARTTLS", "forbidden"},
	} {
		for _, suffix := range []string{" ", "\t", " \t ", "\t\t", strings.Repeat(" ", 32)} {
			line := tc.line + suffix + "\r\n"
			cmd, arg, err := parseCmd(line)
			if err != nil || cmd != tc.cmd || arg != tc.arg {
				t.Errorf("parseCmd(%q) = (%q, %q, %v), want (%q, %q, nil)", line, cmd, arg, err, tc.cmd, tc.arg)
			}
		}
	}
	for _, line := range []string{"NOOPx ", "STARTTLSx ", "XCLIENTx ", " NOOP ", "NOOP\u00a0", "NOOP\x00", "NOOP\v", "NOOP\f", "HELO\tclient.example "} {
		if cmd, _, err := parseCmd(line + "\r\n"); err == nil {
			t.Errorf("parseCmd(%q) accepted malformed command %q", line, cmd)
		}
	}
}
