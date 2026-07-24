package smtp

import (
	"bufio"
	"fmt"
	"io"
)

type EnhancedCode [3]int

// SMTPError specifies the error code, enhanced error code (if any) and
// message returned by the server.
//
// Backend and Session methods should return an *SMTPError (or an error that
// wraps one) so the server sends a deliberate, well-formed status line. A plain
// error is surfaced to the client as "554 5.0.0 Error: transaction failed:
// <error text>", which leaks the raw internal message — return an *SMTPError,
// for example via Errorf, to choose the status code and message instead.
type SMTPError struct {
	Code         int
	EnhancedCode EnhancedCode
	Message      string
}

// NoEnhancedCode is used to indicate that enhanced error code should not be
// included in response.
//
// Note that RFC 2034 requires an enhanced code to be included in all 2xx, 4xx
// and 5xx responses. This constant is exported for use by extensions, you
// should probably use EnhancedCodeNotSet instead.
var NoEnhancedCode = EnhancedCode{-1, -1, -1}

// EnhancedCodeNotSet is a nil value of EnhancedCode field in SMTPError, used
// to indicate that backend failed to provide enhanced status code. X.0.0 will
// be used (X is derived from error code).
var EnhancedCodeNotSet = EnhancedCode{0, 0, 0}

func (err *SMTPError) Error() string {
	s := fmt.Sprintf("SMTP error %03d", err.Code)
	if err.Message != "" {
		s += ": " + err.Message
	}
	return s
}

func (err *SMTPError) Temporary() bool {
	return err.Code/100 == 4
}

// Errorf returns an *SMTPError with the given SMTP status code, enhanced status
// code, and a message formatted per fmt.Sprintf. It is a convenience for
// backends, which should return an *SMTPError so the server sends the chosen
// status line rather than leaking a raw error (see SMTPError).
func Errorf(code int, enhancedCode EnhancedCode, format string, a ...interface{}) *SMTPError {
	return &SMTPError{
		Code:         code,
		EnhancedCode: enhancedCode,
		Message:      fmt.Sprintf(format, a...),
	}
}

var ErrDataTooLarge = &SMTPError{
	Code:         552,
	EnhancedCode: EnhancedCode{5, 3, 4},
	Message:      "Maximum message size exceeded",
}

type dataReader struct {
	r     *bufio.Reader
	state int

	limited bool
	n       int64 // Maximum bytes remaining
}

func newDataReader(c *Conn) *dataReader {
	dr := &dataReader{
		r: c.text.R,
	}

	if c.server.MaxMessageBytes > 0 {
		dr.limited = true
		dr.n = int64(c.server.MaxMessageBytes)
	}

	return dr
}

func (r *dataReader) Read(b []byte) (n int, err error) {
	// Code below is taken from net/textproto with only one modification to
	// not rewrite CRLF -> LF.

	// Run data through a simple state machine to
	// elide leading dots and detect End-of-Data (<CR><LF>.<CR><LF>) line.
	const (
		stateBeginLine = iota // beginning of line; initial state; must be zero
		stateDot              // read . at beginning of line
		stateDotCR            // read .\r at beginning of line
		stateCR               // read \r (possibly at end of line)
		stateData             // reading data in middle of line
		stateEOF              // reached .\r\n end marker line
	)
	for n < len(b) && r.state != stateEOF {
		var c byte
		c, err = r.r.ReadByte()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			break
		}
		switch r.state {
		case stateBeginLine:
			if c == '.' {
				r.state = stateDot
				continue
			}
			if c == '\r' {
				r.state = stateCR
				break
			}
			r.state = stateData
		case stateDot:
			if c == '\r' {
				r.state = stateDotCR
				continue
			}
			r.state = stateData
		case stateDotCR:
			if c == '\n' {
				r.state = stateEOF
				continue
			}
			r.state = stateData
		case stateCR:
			if c == '\n' {
				r.state = stateBeginLine
				break
			}
			r.state = stateData
		case stateData:
			if c == '\r' {
				r.state = stateCR
			}
		}
		// Enforce the size limit where a content byte would be delivered:
		// MaxMessageBytes is an inclusive ceiling, so the first byte that would
		// carry the delivered content past it (byte MaxMessageBytes+1) is
		// rejected. Terminator and dot-stuffing bytes take the `continue` paths
		// above and never reach here, so a message of exactly MaxMessageBytes
		// still reads its end-of-data marker and is accepted.
		if r.limited {
			if r.n <= 0 {
				err = ErrDataTooLarge
				break
			}
			r.n--
		}
		b[n] = c
		n++
	}
	if err == nil && r.state == stateEOF {
		err = io.EOF
	}

	return
}
