package smtp

import "fmt"

type EnhancedCode [3]int

// SMTPError specifies the error code, enhanced error code (if any) and
// message returned by the server.
//
// Backend and Session methods should return an *SMTPError (or an error that
// wraps one) so the server sends a deliberate, well-formed status line. A plain
// error is surfaced to the client as "554 5.0.0 Error: transaction failed:
// <error text>", which leaks the raw internal message — return an *SMTPError,
// for example via Errorf, to choose the status code and message instead.
// Each reply line is limited to 512 octets including its status and CRLF;
// overlong text is truncated at a UTF-8 character boundary. Use newlines in
// Message to provide multiple diagnostic lines within that per-line limit.
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
//
// Errorf is not only for failures: returning an *SMTPError whose Code is in the
// 2xx range from Mail, Rcpt or Data sets a custom non-failure status line in
// place of the server's default (for example the "250 ... OK: queued" after the
// final dot). The transaction proceeds exactly as if nil had been returned; only
// the status text differs. This is the additive way to customize a success
// response, since those methods can only communicate back through their error
// return.
func Errorf(code int, enhancedCode EnhancedCode, format string, a ...interface{}) *SMTPError {
	return &SMTPError{
		Code:         code,
		EnhancedCode: enhancedCode,
		Message:      fmt.Sprintf(format, a...),
	}
}
