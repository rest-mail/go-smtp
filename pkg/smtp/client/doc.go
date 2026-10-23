// Package client implements an SMTP client (RFC 5321) and an LMTP client
// (RFC 2033).
//
// [Dial], [DialTLS] and [DialStartTLS] connect to a server; [New], [NewLMTP]
// and [NewStartTLS] wrap an existing connection; [SendMail] sends one message
// in a single call. The extensions it can use are listed in the documentation
// of package [github.com/rest-mail/go-smtp/pkg/smtp], which holds the types
// this package shares with the server.
package client
