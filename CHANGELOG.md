# Changelog

All notable changes to this project are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## v0.28.1 (2026-07-25)

Bug fixes:

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
