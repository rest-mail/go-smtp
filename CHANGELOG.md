# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Note: pre-1.0, breaking changes may ship in a minor release.

## [Unreleased]

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
