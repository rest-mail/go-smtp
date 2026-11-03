package client

import (
	"net/textproto"
	"strconv"
	"strings"
)

// readReply reads one SMTP reply, which may span several lines, with the same
// results as textproto.Reader.ReadResponse but with the reply grammar of RFC 5321
// section 4.2:
//
//	Reply-line = *( Reply-code "-" [ textstring ] CRLF )
//	             Reply-code [ SP textstring ] CRLF
//
// The text is optional, so a line may be a bare three-digit code with nothing
// after it (section 4.2.1: the client must accept it). textproto rejects such a
// line as a "short response"; here a bare code is a last line with empty text,
// whether it is the only line or ends a multiline reply.
//
// As in textproto, a line inside a multiline reply that does not parse, or that
// carries a different code, is kept as text rather than ending the reply, and a
// rejected multiline reply's error holds all of its lines.
func readReply(r *textproto.Reader, expectCode int) (code int, message string, err error) {
	line, err := r.ReadLine()
	if err != nil {
		return 0, "", err
	}
	code, continued, message, err := parseReplyLine(line, expectCode)
	multi := continued
	for continued {
		line, err := r.ReadLine()
		if err != nil {
			return 0, "", err
		}
		code2, cont, more, err := parseReplyLine(line, 0)
		if err != nil || code2 != code {
			message += "\n" + strings.TrimRight(line, "\r\n")
			continue
		}
		continued = cont
		message += "\n" + more
	}
	if err != nil && multi && message != "" {
		// Report every line of the reply, not just the first.
		err = &textproto.Error{Code: code, Msg: message}
	}
	return code, message, err
}

// parseReplyLine parses one reply line. A line is a three-digit code (100 to
// 599 are not enforced here: callers act on the first digit), then either
// nothing, a space and the text of a last line, or a hyphen and the text of a
// line that is followed by more. expectCode is checked as in
// textproto.Reader.ReadCodeLine: a one-, two- or three-digit prefix the code
// must start with, or 0 for any code; a mismatch is a *textproto.Error.
func parseReplyLine(line string, expectCode int) (code int, continued bool, message string, err error) {
	if len(line) < 3 || len(line) > 3 && line[3] != ' ' && line[3] != '-' {
		return 0, false, "", textproto.ProtocolError("short response: " + line)
	}
	for i := 0; i < 3; i++ {
		if line[i] < '0' || line[i] > '9' {
			return 0, false, "", textproto.ProtocolError("invalid response code: " + line)
		}
	}
	code, _ = strconv.Atoi(line[:3])
	if code < 100 {
		return 0, false, "", textproto.ProtocolError("invalid response code: " + line)
	}
	if len(line) > 3 {
		continued = line[3] == '-'
		message = line[4:]
	}
	if 1 <= expectCode && expectCode < 10 && code/100 != expectCode ||
		10 <= expectCode && expectCode < 100 && code/10 != expectCode ||
		100 <= expectCode && expectCode < 1000 && code != expectCode {
		err = &textproto.Error{Code: code, Msg: message}
	}
	return code, continued, message, err
}
