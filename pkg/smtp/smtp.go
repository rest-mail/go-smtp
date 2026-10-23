// Package smtp holds the types the SMTP server and client share: the MAIL and
// RCPT options, the extension parameter values and SMTPError.
//
// The protocol lives in two packages that import this one:
//
//   - [github.com/rest-mail/go-smtp/pkg/smtp/server] implements an SMTP and
//     LMTP server (RFC 5321, RFC 2033).
//   - [github.com/rest-mail/go-smtp/pkg/smtp/client] implements an SMTP and
//     LMTP client.
//
// Both implement the following extensions:
//
//   - 8BITMIME (RFC 6152)
//   - ENHANCEDSTATUSCODES (RFC 2034)
//   - AUTH (RFC 2554)
//   - DELIVERBY (RFC 2852)
//   - CHUNKING (RFC 3030)
//   - BINARYMIME (RFC 3030)
//   - STARTTLS (RFC 3207)
//   - DSN (RFC 3461, RFC 6533)
//   - SMTPUTF8 (RFC 6531)
//   - MT-PRIORITY (RFC 6710)
//   - RRVS (RFC 7293)
//   - REQUIRETLS (RFC 8689)
//
// Additional extensions may be handled by other packages.
package smtp

import (
	"time"
)

type BodyType string

const (
	Body7Bit       BodyType = "7BIT"
	Body8BitMIME   BodyType = "8BITMIME"
	BodyBinaryMIME BodyType = "BINARYMIME"
)

type DSNReturn string

const (
	DSNReturnFull    DSNReturn = "FULL"
	DSNReturnHeaders DSNReturn = "HDRS"
)

// MailOptions contains parameters for the MAIL command.
type MailOptions struct {
	// Value of BODY= argument, 7BIT, 8BITMIME or BINARYMIME.
	// On the client, the empty value selects 8BITMIME when advertised, otherwise
	// basic SMTP. Explicit 8BITMIME requires server support; BINARYMIME is not
	// supported by the DATA-only client. Content validation is the caller's job.
	Body BodyType

	// Estimated message size in octets, including headers and CRLF pairs,
	// excluding SMTP transparency dots and the DATA terminator (RFC 1870).
	// Must be non-negative. Zero makes the client omit the SIZE parameter;
	// on the server it can mean either SIZE=0 or no declaration.
	Size int64

	// TLS is required for the message transmission.
	//
	// The message should be rejected if it can't be transmitted
	// with TLS.
	// Client MAIL (including pipelined MAIL) requires completed TLS and an
	// advertised REQUIRETLS capability. The caller must configure certificate
	// validation and perform any required DNSSEC/MTA-STS/DANE routing checks.
	// Servers expose the received tag; hosts must persist and honor it.
	RequireTLS bool

	// The message envelope or message header contains UTF-8-encoded strings.
	// This flag is set by SMTPUTF8-aware (RFC 6531) client.
	UTF8 bool

	// Value of RET= argument, FULL or HDRS.
	Return DSNReturn

	// Opaque decoded envelope identifier set by the client (printable ASCII).
	EnvelopeID string

	// The authorization identity asserted by the message sender in decoded
	// form with angle brackets stripped.
	//
	// nil value indicates missing AUTH, non-nil empty string indicates
	// AUTH=<>.
	//
	// Defined in RFC 4954.
	Auth *string

	// Value of the BY= argument, or nil if unset.
	//
	// Defined in RFC 2852, which places it on MAIL: the deadline describes the
	// message, not an individual recipient.
	DeliverBy *DeliverByOptions

	// Value of the MT-PRIORITY= argument, or nil if unset. Ranges from -9 to 9.
	//
	// Defined in RFC 6710, which places it on MAIL: the priority describes the
	// message, not an individual recipient. The server preserves the exact
	// requested value; authorization, policy rounding and a nil default of 0
	// are the backend's responsibility. Client.Mail refuses an explicit value
	// when the peer does not advertise MT-PRIORITY; a relay must choose its
	// fallback policy and omit this option for a non-supporting next hop.
	MTPriority *int
}

type DSNNotify string

const (
	DSNNotifyNever   DSNNotify = "NEVER"
	DSNNotifyDelayed DSNNotify = "DELAY"
	DSNNotifyFailure DSNNotify = "FAILURE"
	DSNNotifySuccess DSNNotify = "SUCCESS"
)

type DSNAddressType string

const (
	DSNAddressTypeRFC822 DSNAddressType = "RFC822"
	DSNAddressTypeUTF8   DSNAddressType = "UTF-8"
)

type DeliverByMode string

const (
	DeliverByNotify DeliverByMode = "N"
	DeliverByReturn DeliverByMode = "R"
)

// DeliverByOptions carries RFC 2852 message deadline metadata. The host must
// capture receipt time, enforce expiry and generate delivery notifications; the
// transport does not schedule delivery or decrement Time between hops.
type DeliverByOptions struct {
	Time  time.Duration
	Mode  DeliverByMode
	Trace bool
}

// RRVSAction is the no-support action of an RRVS parameter (RFC 7293
// section 3.1): what a relay does when the next hop does not offer RRVS.
type RRVSAction string

const (
	// RRVSActionReject refuses the message. It is also the meaning of an
	// RRVS parameter that names no action.
	RRVSActionReject RRVSAction = "R"
	// RRVSActionContinue relays the message without the RRVS protection.
	RRVSActionContinue RRVSAction = "C"
)

type PriorityProfile string

const (
	PriorityUnspecified PriorityProfile = ""
	PriorityMIXER       PriorityProfile = "MIXER"
	PrioritySTANAG4406  PriorityProfile = "STANAG4406"
	PriorityNSEP        PriorityProfile = "NSEP"
)

// RcptOptions contains parameters for the RCPT command.
type RcptOptions struct {
	// Value of NOTIFY= argument, NEVER or a combination of either of
	// DELAY, FAILURE, SUCCESS. The server removes null/repeated list elements
	// and preserves first-occurrence order. An empty slice leaves host defaults
	// unspecified; the transport does not generate notifications.
	Notify []DSNNotify

	// Original recipient set by client. The server preserves the address type
	// spelling for relays; compare it case-insensitively. The client accepts
	// case-insensitive RFC822/UTF-8 types and retains the supplied spelling.
	OriginalRecipientType DSNAddressType
	OriginalRecipient     string

	// Time value of the RRVS= argument
	// or the zero time if unset.
	RequireRecipientValidSince time.Time
	// No-support action of the RRVS= argument, or empty if the parameter
	// named none (which means reject). A relay preserves it as given
	// (RFC 7293 section 5.1.1).
	RequireRecipientValidSinceAction RRVSAction
}
