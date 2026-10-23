// Package wire holds the encoders, decoders and checks that the SMTP server
// and client both need: xtext and the RFC 6533 address forms, ASCII and decimal
// tests, the DSN NOTIFY rules, the DELIVERBY bound and the line-limited
// reader.
package wire

// MaxDeliverBySeconds is the largest by-time RFC 2852 section 4 can express:
// its grammar allows at most nine digits.
const MaxDeliverBySeconds = 999999999

// IsDecimal reports whether s contains one or more ASCII decimal digits.
// strconv's integer parsers alone also accept a leading sign.
func IsDecimal(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func IsASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}
