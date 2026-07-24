# go-smtp

[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-smtp.svg)](https://pkg.go.dev/github.com/rest-mail/go-smtp)

An ESMTP client and server library written in Go.

## Features

### Protocol

* ESMTP **client and server** implementing [RFC 5321], plus [LMTP] server support
* **TLS** — implicit TLS and [STARTTLS]
* **SASL authentication** via [go-sasl], with pluggable mechanisms
* **PIPELINING** and enhanced status codes
* **CHUNKING** (`BDAT`) and **BINARYMIME** ([RFC 3030])
* **SMTPUTF8** — internationalized addresses and headers ([RFC 6531]) — and **8BITMIME** bodies
* Message-size controls — **SIZE** ([RFC 1870]) and **LIMITS** `RCPTMAX` ([RFC 9422])
* **Delivery Status Notifications** — DSN ([RFC 3461])
* **REQUIRETLS** ([RFC 8689]), **MT-PRIORITY** ([RFC 6710]), **DELIVERBY** ([RFC 2852]) and **RRVS** ([RFC 7293])
* **XCLIENT** — a trusted proxy (haproxy/nginx/Postfix) can assert the real client's address, name, protocol, HELO and login; gated on a caller-supplied trust check so only trusted peers are honoured

### Server API

* Pluggable backend with per-message limits (max recipients, max message size, max line length, read/write timeouts)
* Dynamic EHLO capabilities — the static `ExtraCaps` field, or an optional `FeatureBackend` that computes advertised capabilities per connection
* `ConnState` hook (in the style of `net/http`) for connection open/close events — a single place for metrics, logging and debugging
* `Conn.Context()` — a per-connection `context.Context`, cancelled when the connection closes or the server shuts down, so backends can observe cancellation
* Backend error contract — return an `*SMTPError` (build one with `smtp.Errorf`) to choose the status code; a 2xx `*SMTPError` sets a custom success line, and wrapping an error with `CloseConnection` sends the response and then closes the connection
* A zero-value `Server` is usable directly, without `NewServer`

### Client API

* Command batching with `Client.Pipeline()` — pipelines `RSET`/`MAIL`/`RCPT` per [RFC 2920] to cut round-trips on high-throughput senders
* `Client.CheckConn()` — detect a server-closed idle/pooled connection without sending a command (STARTTLS-safe)

## Relationship with net/smtp

The Go standard library provides a SMTP client implementation in `net/smtp`.
However `net/smtp` is frozen: it's not getting any new features. go-smtp
provides a server implementation and a number of client improvements.

## Licence

MIT

[RFC 5321]: https://tools.ietf.org/html/rfc5321
[RFC 2920]: https://tools.ietf.org/html/rfc2920
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
