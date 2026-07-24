# go-smtp

[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-smtp.svg)](https://pkg.go.dev/github.com/rest-mail/go-smtp)

An ESMTP client and server library written in Go.

## Features

* ESMTP client & server implementing [RFC 5321]
* Support for additional SMTP extensions such as [AUTH] and [PIPELINING]
* UTF-8 support for subject and message
* [LMTP] support
* Server-side advertising of site-specific EHLO capabilities via the
  `ExtraCaps` hook
* Connection read deadlines enforced during the message body, so
  `ReadTimeout` acts as an idle timeout throughout DATA and BDAT transfers
* A read timeout during DATA returns `451 4.4.2` and closes the connection
* STARTTLS handshakes are bounded by the configured read/write timeouts and
  close the connection on failure
* Safe concurrent server shutdown (`Close`/`Shutdown` may be called from
  multiple goroutines)
* Response-write failures stop the connection loop promptly instead of
  spinning
* Connections closed before any command (such as bare TCP health checks) are
  treated as clean closes rather than logged errors
* Backend errors that wrap an `*SMTPError` are honored, preserving the SMTP
  status code

## Relationship with net/smtp

The Go standard library provides a SMTP client implementation in `net/smtp`.
However `net/smtp` is frozen: it's not getting any new features. go-smtp
provides a server implementation and a number of client improvements.

## Licence

MIT

[RFC 5321]: https://tools.ietf.org/html/rfc5321
[AUTH]: https://tools.ietf.org/html/rfc4954
[PIPELINING]: https://tools.ietf.org/html/rfc2920
[LMTP]: https://tools.ietf.org/html/rfc2033
