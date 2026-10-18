# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Note: pre-1.0, breaking changes may ship in a minor release.

## [Unreleased]

### Added

- `CHECKLIST.md`: the requirements of RFC 5321 (server and client core), each
  mapped to the tests that cover it, with one row per supported extension, and
  `internal/checklist` to check it in CI. Every `Test` and `Fuzz` function now
  names the items it covers. `COVERAGE.md` records the coverage.
- Tests for RFC 5321 requirements that had none: command order, RSET and a second
  EHLO, case-insensitive verbs, the recipient limit and 100 recipients, dot
  unstuffing on the server and dot stuffing on the client, the 512-octet command
  line and the minimum address sizes.

### Fixed

- Out-of-sequence commands now return `503 5.5.1` rather than `502`
  (SMTP-ORD-05): MAIL/AUTH before HELO/EHLO, RCPT before MAIL, DATA/BDAT
  without recipients, MAIL/RCPT/DATA/XCLIENT between BDAT chunks, DATA after
  BODY=BINARYMIME, and STARTTLS on a TLS connection. AUTH and STARTTLS are
  also refused with `503 5.5.1` during a mail transaction. This is a
  client-visible change; existing response text is preserved.
- The server now ends a command line at `<CRLF>` only (RFC 5321 §2.3.8). A
  line ended by a bare LF was accepted, so `MAIL ...\nRCPT ...\r\n` ran as two
  commands; it now draws `500 5.5.2` and the connection is closed.
- The DATA reader no longer mistakes the end of a message for content, or
  loses a byte, around a stray CR. A CR before the `<CRLF>` of the last line
  (`x\r\r\n.\r\n`) hid the end-of-data marker, so the server waited for a
  second one until the read timeout; and a CR straight after a leading dot
  (`.\rX`) was silently dropped. Neither let a message end early, and bare
  LF, bare CR, `<LF>.<LF>`, `<CR>.<CR>`, `<LF>.<CR><LF>` and `<CR><LF>.<LF>`
  were already treated as content, now covered by `eod_conformance_test.go`.
- A `utf-8` `ORCPT` address now follows RFC 6533 §3. The server refuses
  malformed UTF-8 (overlong forms, encoded surrogates, octets past U+10FFFF,
  stray or truncated sequences), which QUCHAR does not allow (RFC 3629 §4), and
  accepts lower-case `\x{e9}`, since ABNF hex digits are case-insensitive
  (RFC 5234 §2.3). The client no longer sends a literal `\`, which is not a
  QCHAR, or a one-digit `\x{1}`; it writes `\x{5C}` and `\x{01}`. `Rcpt` now
  returns an error for an original recipient that is not UTF-8, or that holds
  NUL, %x0A-0F or %x1A-1F, which HEXPOINT cannot express. Found by the new
  `FuzzDecodeUTF8AddrXtext`, `FuzzEncodeUTF8AddrXtext` and
  `FuzzEncodeUTF8AddrUnitext` targets, which check all three functions against
  an independent copy of the grammar and CI runs for 10 seconds each.
- The server no longer accepts a literal `=`, space, control or non-ASCII byte
  in an xtext parameter (`AUTH`, `ENVID`, and an `rfc822` `ORCPT`). RFC 3461
  §4 and RFC 4954 §8 allow only xchars (printable US-ASCII other than `+` and
  `=`) and `+HH` hexchars, so `ENVID=e=mc2` and `AUTH=e=mc2@example.com` were
  accepted although `=` must be sent as `+3D`. Lower-case hex digits are still
  accepted. Found by the new `FuzzDecodeXtext` and `FuzzEncodeXtext` targets,
  which check both functions against the RFC grammar and CI runs for 10
  seconds each.
- The server no longer lets a source route run past the end of a `MAIL` or
  `RCPT` path. The obsolete A-d-l (RFC 5321 §4.1.2) was skipped up to the first
  `:` anywhere in the argument, so `<@r> X=:u@x>` was accepted as `u@x`, and a
  route could carry whitespace or control bytes. A route that reaches
  whitespace, `<`, `>` or a control byte before its `:` is now rejected. Found
  by the new `FuzzParseReversePath` and `FuzzParseForwardPath` targets, which
  CI runs for 10 seconds each.
- A large pipelined group no longer deadlocks the client (#78). `Pipeliner`
  only read replies in `Wait`, so once a group outgrew the buffers the server
  stopped reading (its replies went unread) while the client was still blocked
  writing commands. As RFC 2920 §3.1 requires of a client that does not read
  while it sends, a group is now sent in parts of at most 4 KiB of commands:
  before writing past that, `Mail`, `Rcpt` and `Reset` read the replies already
  owed. `Wait` still returns every result in queue order, and the recipient set
  is built in the same order. After an I/O error (a failed write, or a failed or
  timed-out read) the remaining results are that error and later commands on
  the `Pipeliner` fail with it instead of being sent out of step.

## [0.29.0] - 2026-09-13

### Changed

- **Breaking:** `MT-PRIORITY` (RFC 6710) and `BY` (RFC 2852, the DELIVERBY
  extension) are now MAIL parameters, which is where both RFCs define them —
  each describes the message, not an individual recipient. `DeliverBy` and
  `MTPriority` have moved from `RcptOptions` to `MailOptions`, the server reads
  both from `MAIL` and no longer accepts them on `RCPT`, and `Client.Mail` sends
  them instead of `Client.Rcpt`. Previously neither extension was usable in
  either direction despite being advertised: a conforming client's
  `MAIL FROM:<a@example.org> BY=120;R` was answered `500 5.5.4 Unknown MAIL FROM
  argument`, and this client's RCPT parameters were refused by a conforming
  server.
- `Client.Mail` now fails when `DeliverBy` or `MTPriority` is set and the server
  has not advertised the extension, rather than dropping the parameter. A caller
  that asked for a delivery deadline and silently did not get one has no way to
  find out. (`AUTH` is unchanged: RFC 4954 §5 permits discarding it.)

### Fixed

- The `BY` parser rejects a by-time wider than the nine digits RFC 2852 §4
  allows, instead of passing an arbitrarily large deadline to the backend.

## [0.28.3] - 2026-07-26

### Fixed

- The per-line length limit is now disabled during the DATA phase (mirroring
  BDAT), so `MaxLineLength` bounds only command lines — a server can cap pre-auth
  command input without limiting message body lines.

## [0.28.2] - 2026-07-25

### Fixed

- Envelope address parsing: reject control bytes (below `0x20`, and `0x7F`) in
  the local-part and domain of `MAIL FROM`/`RCPT TO` addresses. A parsed
  address is echoed back into status lines, so a bare `CR` or other control
  character could be used for command/response injection or to desync the
  protocol; such addresses are now rejected with a syntax error at parse time.
  Bytes above `0x7F` remain permitted for SMTPUTF8 (RFC 5321 §4.1.2).
- `RCPT TO:<Postmaster>`: accept the special domainless postmaster forward-path
  form that every receiver is required to honor. It was previously rejected
  with `501 5.5.2` before the backend saw it; the domain-qualified
  `<Postmaster@domain>` form was unaffected. The bare form is now surfaced to
  the backend to accept or reject per local policy (RFC 5321 §4.1.1.3, §4.5.1).
- Nested `MAIL`: a second `MAIL FROM` issued while a transaction is already open
  is now rejected with `503` (bad sequence of commands) and leaves the
  in-progress transaction intact. Previously the new command silently replaced
  the sender, retained the earlier recipients, and skipped the backend's
  transaction reset (RFC 5321 §4.1.1.2, §4.1.4).
- STARTTLS: serialize the post-handshake connection swap with `Conn.Close` so
  the two no longer race. A concurrent `Server.Close`/`Shutdown` could observe
  the connection mid-swap and close the underlying TCP socket instead of the
  TLS connection; the swap and close now share the connection mutex. The TLS
  handshake still runs outside the lock.
- AUTH: terminate the exchange and close the connection on a read error while
  reading a SASL continuation line, instead of resuming the command loop on a
  half-finished exchange. Previously the client's next SASL response was parsed
  as an SMTP command, producing spurious `5xx` replies on a desynced
  connection. The continuation loop is also bounded so a misbehaving mechanism
  cannot spin it indefinitely (RFC 4954).
- CHUNKING (`BDAT`): on a read timeout or transport error mid-chunk, reply with
  a clean, generic `451 4.4.2` and close the connection instead of resuming on
  a desynced connection. The previous behavior echoed the raw network error
  text (e.g. `i/o timeout`) into a `554` reply and then re-parsed the peer's
  unread chunk octets as commands. The raw error is now logged internally and
  never sent to the client.
- ESMTP parameters (`MAIL`/`RCPT`): require whitespace between the address path
  and any parameter (reject `MAIL FROM:<a@b>SIZE=10`) and reject a repeated
  parameter instead of silently keeping the last value (RFC 5321 §4.1.1.2,
  §4.1.1.11).
- AUTH: reject trailing tokens after the initial response with `501`, and refuse
  AUTH on an unprotected connection with `530 5.7.0` rather than the unassigned
  `523` (RFC 4954 §4, RFC 3207 §4).
- Shutdown: `Server.Close` now delivers a `421` service-closing reply to a live
  connection before the socket is dropped, rather than closing it silently. The
  reply is written by the connection's own goroutine, so it does not race that
  goroutine's other writes (RFC 5321 §3.8).
- Error handling: the per-connection error counter now counts *consecutive*
  protocol errors. A command that completes successfully clears the tally, so a
  connection is dropped only for a sustained burst of errors rather than for the
  Nth error accumulated across an otherwise healthy session.
- The `DATA` terminating flush is now bounded by a write deadline, so a peer
  that has stopped reading cannot block the closing write indefinitely.
- Client: normalize EHLO extension keywords to upper case when populating the
  capability map. Keywords are case-insensitive, but internal feature lookups
  use upper-case keys, so a server advertising `starttls`, `size`, `auth`, etc.
  in lower or mixed case silently defeated the capability check — the client
  would skip STARTTLS, omit `SIZE=`/`BODY=8BITMIME`, or not pipeline. Parameter
  values are preserved verbatim (RFC 5321 §2.4, §4.1.1.1).

## [0.28.1] - 2026-07-25

### Fixed

- CHUNKING (`BDAT`): keep the per-line length limit enforced between chunks.
  The limit was previously restored only after the final chunk or on error, so
  a client could stream a single unbounded line after a non-final chunk and
  drive the server toward memory exhaustion. An over-length command line
  between chunks is now rejected as a too-long line.
- CHUNKING (`BDAT`): disable the line-length limit while discarding an
  over-limit chunk. A `552` size rejection is no longer followed by a spurious
  `500 5.4.0 Too long line` and a dropped connection when the discarded chunk
  contains a line longer than the command-line limit; the connection stays
  framed and usable afterwards.
- LMTP: bound the discard of an over-limit `DATA` message and handle mid-body
  read timeouts. A message that exceeds the size limit and never sends the
  end-of-data marker no longer pins the connection, and a body read timeout now
  returns `451 4.4.2` per recipient and closes the connection instead of
  desyncing the command loop.
- Client: clear the recipient list when a new transaction begins. On a reused
  connection, recipients no longer leak across messages. Previously this
  misattributed per-recipient LMTP replies and could stall the client, and grew
  the recipient slice without bound on pooled or kept-alive SMTP connections.
