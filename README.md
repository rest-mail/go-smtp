# go-smtp

[![CI](https://github.com/rest-mail/go-smtp/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-smtp/actions/workflows/ci.yml)
[![Coverage gate: >=94.5%](https://img.shields.io/badge/coverage%20gate-%3E%3D94.5%25-yellowgreen)](COVERAGE.md)
[![Checklist: 282/388 mapped](https://img.shields.io/badge/checklist-282%2F388%20mapped-blue)](CHECKLIST.md)
[![Go Reference](https://pkg.go.dev/badge/github.com/rest-mail/go-smtp.svg)](https://pkg.go.dev/github.com/rest-mail/go-smtp)

An ESMTP client and server library written in Go.

## Features

### Protocol

* ESMTP **client and server** implementing [RFC 5321], plus [LMTP] client and server support
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
RFC 2920 (PIPELINING), RFC 3030 (CHUNKING/BINARYMIME) and
RFC 6152 (8BITMIME) item by item, plus individual
AUTH exchange requirements from RFC 4954 §4 and the DSN parameter/protocol
rules from RFC 3461 §§2–4, 5.1 and 5.4, and the SMTPUTF8 envelope rules
from RFC 6531 (including refusal of `SMTPUTF8=`) and the RRVS parameter
from RFC 7293, DELIVERBY transport from RFC 2852 and MT-PRIORITY transport
from RFC 6710, LMTP from RFC 2033, and Postfix XCLIENT session state and
trust boundaries (a non-IETF extension with explicit syntax gaps), plus the
RFC 6409 §4.3 submission authentication error/backend contract. A small program,
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

The badges at the top are checked by `TestReadmeBadges` in
`internal/checklist`. The checklist badge counts mapped items over all items:
the 106 `n/a` rows are in the denominator, so the badge never claims more than
the tests prove. The coverage badge shows the floor CI enforces (`FLOOR` in
`.github/workflows/ci.yml`), not a measured figure; each CI run prints the
measured statement coverage.

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

CHUNKING is always advertised; `EnableBINARYMIME` additionally advertises
BINARYMIME. BDAT payloads reach the backend unchanged, even when binary bytes
share a read buffer with the command. Every failed, syntactically valid chunk
is consumed before its reply, including chunks already pipelined after an
error; incomplete chunks close the connection and are never delivered.
Senders must issue RSET after a failed chunk or illegal DATA/BDAT mixing.
The current per-chunk count limit is 2^32-1 octets; larger messages can use
multiple chunks. The client has no BDAT sender. MIME canonicalization,
lossless storage/relay, next-hop conversion and delivery notifications remain
host responsibilities; enabling BINARYMIME promises those capabilities.
The argument parser has a fuzz target with an independent grammar/integer
oracle. The RFC 3030 checklist records these limitations explicitly.

SIZE declarations are whole-message octet estimates (headers and CRLF included,
SMTP transparency dots and the DATA terminator excluded). The server accepts
1–20 decimal digits, passes estimates up to `int64` to the backend, and answers
552 for declarations above its configured limit or representable range. The
unlimited configuration advertises `SIZE 0`. The declared size never delimits
DATA; actual content is bounded by `MaxMessageBytes`. A client omits SIZE when
`MailOptions.Size` is zero and rejects negative estimates. Storage reservation,
recipient limits, retry queues and delivery notifications remain host policy;
see the RFC 1870 checklist's explicit policy rows.

DSN (`EnableDSN`) is an opt-in promise by the host to honor notification
requests, not just to parse the parameters. The transport exposes decoded
`MailOptions.Return`/`EnvelopeID` and each recipient's `Notify`/original address.
NOTIFY accepts repeated conditions and null list elements as RFC 3461's RFC 822
list grammar permits; the server passes unique conditions to the backend in
first-occurrence order. NEVER must be standalone. RET and NOTIFY keywords are
ASCII and case-insensitive; Unicode look-alikes are refused.

The host owns report generation, retries, alias/list policy and preservation
of these options when relaying. With no DSN capability the client silently
omits the options; inspect `Extension("DSN")` before choosing fallback policy.
No DSN may be generated for a null sender. Unset NOTIFY/RET values remain unset
for host defaults. RFC822 original addresses are opaque printable ASCII, not
revalidated mailbox syntax. Other registered address types besides RFC822 and
RFC 6533 UTF-8 remain unsupported; the checklist records this conformance gap.
The default command limit covers the tested DSN size allowances, but hosts
changing `MaxLineLength` must budget all enabled extension combinations.

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

DELIVERBY (`EnableDELIVERBY`) requires the host to enforce RFC 2852's deadline
and notification rules. `Session.Mail` receives a relative `DeliverBy.Time`;
capture receipt time there, enforce expiry in the queue, and recompute time
remaining before relaying. Return mode requires a positive deadline; notify
mode accepts zero and negative values. `MinimumDeliverByTime` should be whole
seconds in the range 0–999999999; zero omits the advertised minimum. A valid
return request below the configured minimum receives 555 5.5.4.

The client checks the peer's advertised minimum for return mode before MAIL,
including comma-separated future options. It refuses malformed minima and
all unadvertised BY requests. Notify-mode fallback to a peer without DELIVERBY
is a host decision requiring DSNs and notification adjustments; the client
does not silently drop the parameter. Hosts also generate deadline/trace DSNs,
include Arrival-Date/Deliver-By-Date, preserve mode/trace across hops and choose
MX routes. The transport checklist explicitly records these responsibilities.

MT-PRIORITY (`EnableMTPRIORITY`) transports one priority for the whole message.
The server accepts only RFC 6710's `0`, `1` through `9`, and `-1` through `-9`;
`+1`, `-0` and leading zeroes are syntax errors (501 5.5.2). A nil
`MailOptions.MTPriority` leaves the default of 0 or site policy to the backend.
The original requested value is preserved even if the selected policy internally
rounds to fewer service classes. `MtPriorityProfile` is only an advertisement:
set it to a valid 1–20 character ASCII policy name, or leave it empty to withhold
the name (clients assume MIXER). The configuration is not validated.

Enable this extension only when the backend authorizes priority requests.
In particular, `Session.Mail` must reject or lower positive priorities from
untrusted or unauthorized sources; successful SMTP AUTH alone does not grant
that permission. The host implements policy levels, queue ordering, retries,
trace/log fields, DSN priorities and metadata preservation across aliases and
relay hops. Custom backend SMTP replies can report reassignment (250 2.3.6),
a priority below the current minimum (450/550 X.7.15), or priority-specific size
limits (552 5.7.16). Client.Mail refuses an explicit priority when the peer does
not advertise MT-PRIORITY; a relay must explicitly choose fallback and omit the
option for such a peer. These policy boundaries are recorded in the checklist.

LMTP uses LHLO and refuses SMTP HELO/EHLO. `NewClientLMTP` preserves an LHLO
refusal instead of falling back to HELO. `LMTPSession.LMTPData` can supply
one status per accepted RCPT, including duplicate paths; unset statuses use
the method's returned error. A plain `Session.Data` result applies to all
recipients. DATA and BDAT LAST replies are flushed individually in RCPT order
as statuses become available, including before `LMTPData` returns. The server
waits for the method to return before resetting the transaction or processing
the next command.

A successful status promises durable delivery or relay responsibility: the
host must persist the message before reporting success. Deploy LMTP only by
prior arrangement on local transports, never TCP port 25; explicit listeners
and addresses are not validated (the default network is Unix sockets).
`CloseWithLMTPResponse` accepts every 2xx final recipient reply as success,
including unrecognized codes, and returns partial successes and known failures
alongside transport errors. Treat every unanswered recipient as a temporary failure;
there are no synthetic per-recipient 4xx entries or streaming callbacks. Its
address-keyed maps cannot preserve separate duplicate-path outcomes. The
checklist also records BDAT gaps: no-recipient LAST returns 503 instead
of zero replies, and early failures use a single SMTP reply.

XCLIENT is restricted to connections approved by `TrustXCLIENT`. A successful
assertion logs out the old backend session, clears SMTP greeting/authentication
state and sends 220. The proxy must greet again; `Backend.NewSession` then sees
the accumulated `Conn.XClient()` identity. Asserted HELO/PROTO remain metadata;
the transport peer and TLS session remain intact. XCLIENT during a mail
transaction gets 503, and rejected syntax leaves the existing identity intact.
A backend may retain an identity pointer: later assertions use a copy.

The [Postfix XCLIENT checklist](CHECKLIST.md#postfix-xclient-session-state-and-trust-boundaries)
records incomplete compatibility: asserted HELO does not satisfy the new
SMTP greeting requirement and PROTO does not select effective protocol state.
Values remain literal (no xtext decoding),
address/protocol/sentinel validation is not implemented, and PORT/DESTADDR/DESTPORT
are accepted but not surfaced or advertised. The host must validate attributes,
map LOGIN to its own identity policy, apply relay/access rules and reset cached
client assertions appropriately. Identity policy runs when the replacement
backend session is created after the new greeting, rather than before the 220.

For message submission, the backend must require successful AUTH or independently
established authorization in `Session.Mail`, returning `ErrAuthRequired` otherwise
(as in `ExampleServer`). This error sends `530 5.7.0`. Binding to port 587 does
not select a submission mode, and `AllowInsecureAuth` only permits plaintext AUTH;
it does not require authentication. Other RFC 6409 requirements remain unaudited.

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
