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

## The RFC checklist

[CHECKLIST.md](CHECKLIST.md) lists the requirements of RFC 5321 (the SMTP
server and client core), RFC 3207 (STARTTLS), RFC 1870 (SIZE),
RFC 2920 (PIPELINING) and RFC 6152 (8BITMIME) item by item, plus individual
AUTH exchange requirements from RFC 4954 §4. Other extensions retain summary
rows. A small program,
[`internal/checklist`](internal/checklist/main.go), checks it against the tests
in CI. It is the same program as
[go-spf](https://github.com/rest-mail/go-spf)'s and the other `go-*`
libraries', without package `slices`, since this module still declares go 1.13.

The checklist is a Markdown file holding one or more tables whose header is
exactly:

```markdown
| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SMTP-RSET-01 | 4.1.1.5 | MUST | RSET clears the sender, the recipients and the data. | `TestRFC5321_RsetAndSecondEhloClearTransaction` |
| SMTP-LIM-06 | 4.5.3.1.5 | MUST | A reply line is at most 512 octets, CRLF included (SASL challenges excepted). | `TestRFC5321_ReplyLine512`, `TestRFC5321_MultilineReplyLine512`, `TestRFC5321_BackendReplyLine512`, `TestRFC4954_LongChallengeNotTruncated` |
```

Each test names the items it covers in its doc comment:

```go
// checklist: SMTP-RSET-01 SMTP-RSET-02
func TestRFC5321_RsetAndSecondEhloClearTransaction(t *testing.T) {
```

`go run ./internal/checklist [-file CHECKLIST.md] [package dir ...]` fails when
an ID is used twice, an item names no test and is not `n/a`, an item and a test
disagree about each other, or a `Test` or `Fuzz` function names no item.
Coverage is in [COVERAGE.md](COVERAGE.md).

The server limits each ordinary reply line to 512 octets, including its reply
code, enhanced status (if present), and CRLF. Overlong text is truncated at a
UTF-8 character boundary; the status and existing multiline framing are kept.
Backends can use newline-separated text to supply longer diagnostics across
multiple lines. This also bounds greetings and backend-supplied EHLO lines;
keep domain names, capabilities and other protocol tokens within the budget.
SASL `334` challenges are sent intact because RFC 4954 §4 makes their size
independent of ordinary SMTP line limits.

The client honors explicit `MailOptions.Body`: `Body7Bit` uses 7-bit transport,
and `Body8BitMIME` requires the peer's advertised 8BITMIME support. With no body
option, it selects 8BITMIME when available, as before. This DATA-only client
refuses `BodyBinaryMIME`; it requires BDAT. The default `Mail`/`SendMail` API and
`Data` do not inspect or convert MIME: callers must provide 7-bit content when
the peer lacks 8BITMIME. Backends must preserve accepted 8-bit data during
storage/delivery and negotiate, convert losslessly, or fail at the next hop.
Those responsibilities and the automatic API's validation gap are explicit in
the checklist. The DATA fuzz target compares transparency against Go's
`net/textproto` reader, accounting for that reader's CRLF-to-LF conversion.

SIZE declarations are whole-message octet estimates (headers and CRLF included,
SMTP transparency dots and the DATA terminator excluded). The server accepts
1–20 decimal digits, passes estimates up to `int64` to the backend, and answers
552 for declarations above its configured limit or representable range. The
unlimited configuration advertises `SIZE 0`. The declared size never delimits
DATA; actual content is bounded by `MaxMessageBytes`. A client omits SIZE when
`MailOptions.Size` is zero and rejects negative estimates. Storage reservation,
recipient limits, retry queues and delivery notifications remain host policy;
see the RFC 1870 checklist's explicit policy rows.

PIPELINING replies retain command order. Only transaction-command replies
(RSET/MAIL/RCPT) are held for batching; synchronization and unknown-command
replies flush before later commands are processed. The client exposes those
three queue operations and returns every status from `Wait`; DATA is sent
synchronously afterwards. Inspect every result before sending message content.
If every recipient failed but a peer nevertheless accepts DATA, close the
unwritten writer to send only `.\r\n`, check the final response, and reset.
An empty DATA writer now sends that terminator without an extra blank line.

The client still assumes a 4096-byte transport window instead of checking the
actual TCP window or reading responses concurrently. Its congestion tests prove
that assumed window only; smaller windows and oversized individual commands
remain a conformance gap (PIPE-CLIENT-07), bounded by `CommandTimeout`.

## Relationship with net/smtp

The Go standard library provides a SMTP client implementation in `net/smtp`.
However `net/smtp` is frozen: it's not getting any new features. go-smtp
provides a server implementation and a number of client improvements.

## Changelog

Recent releases — see [CHANGELOG.md](CHANGELOG.md) for the complete history.

- **v0.28.3** (2026-07-26) — `MaxLineLength` now bounds command lines only; the per-line limit is disabled during DATA (mirroring BDAT), so a server can cap pre-auth command input without limiting message body lines.
- **v0.28.2** (2026-07-25) — STARTTLS/Close data race, nested-MAIL 503, AUTH/BDAT desync fixes, EHLO case-normalization, MAIL/RCPT param strictness, shutdown 421.
- **v0.28.1** (2026-07-25) — BDAT inter-chunk line-limit enforcement, over-limit chunk discard framing, LMTP oversized-DATA discard bound, client recipient-list reset per transaction.

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
