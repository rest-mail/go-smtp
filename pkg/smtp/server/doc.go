// Package server implements an SMTP server (RFC 5321) and an LMTP server
// (RFC 2033).
//
// A host supplies a [Backend], which opens a [Session] for each connection,
// and serves it with [New] and [Server.ListenAndServe] or [Server.Serve]. The
// extensions it can advertise are listed in the documentation of package
// [github.com/rest-mail/go-smtp/pkg/smtp], which holds the types this package
// shares with the client.
package server
