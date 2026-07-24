# go-smtp

[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-smtp.svg)](https://pkg.go.dev/github.com/rest-mail/go-smtp)

An ESMTP client and server library written in Go.

## Features

* ESMTP **client and server** implementing [RFC 5321], plus [LMTP] server support
* **TLS** — implicit TLS and [STARTTLS]
* **SASL authentication** via [go-sasl], with pluggable mechanisms
* **PIPELINING** and enhanced status codes
* **CHUNKING** (`BDAT`) and **BINARYMIME** ([RFC 3030])
* **SMTPUTF8** — internationalized addresses and headers ([RFC 6531])
* **8BITMIME** message bodies
* Message-size controls — **SIZE** ([RFC 1870]) and **LIMITS** `RCPTMAX` ([RFC 9422])
* **Delivery Status Notifications** — DSN ([RFC 3461])
* **REQUIRETLS** ([RFC 8689]), **MT-PRIORITY** ([RFC 6710]), **DELIVERBY** ([RFC 2852]) and **RRVS** ([RFC 7293])
* Pluggable server backend with per-message limits (max recipients, max message size, max line length, read/write timeouts)
* Server-side advertising of site-specific EHLO capabilities via the `ExtraCaps` hook

## Relationship with net/smtp

The Go standard library provides a SMTP client implementation in `net/smtp`.
However `net/smtp` is frozen: it's not getting any new features. go-smtp
provides a server implementation and a number of client improvements.

## Licence

MIT

[RFC 5321]: https://tools.ietf.org/html/rfc5321
[RFC 3030]: https://tools.ietf.org/html/rfc3030
[RFC 6531]: https://tools.ietf.org/html/rfc6531
[RFC 1870]: https://tools.ietf.org/html/rfc1870
[RFC 9422]: https://tools.ietf.org/html/rfc9422
[RFC 3461]: https://tools.ietf.org/html/rfc3461
[RFC 8689]: https://tools.ietf.org/html/rfc8689
[RFC 6710]: https://tools.ietf.org/html/rfc6710
[RFC 2852]: https://tools.ietf.org/html/rfc2852
[RFC 7293]: https://tools.ietf.org/html/rfc7293
[STARTTLS]: https://tools.ietf.org/html/rfc3207
[LMTP]: https://tools.ietf.org/html/rfc2033
[go-sasl]: https://github.com/emersion/go-sasl
