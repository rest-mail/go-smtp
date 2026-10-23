package wire

// maxDeliverBySeconds is the largest by-time RFC 2852 section 4 can express:
// its grammar allows at most nine digits.
const MaxDeliverBySeconds = 999999999

// isDecimal reports whether s contains one or more ASCII decimal digits.
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
