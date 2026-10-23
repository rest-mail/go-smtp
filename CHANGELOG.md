# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Note: pre-1.0, breaking changes may ship in a minor release.

## [Unreleased]

### Added

- Checked wire-level proof of historical HELO/EHLO identifying-suffix
  interoperability (RFC 5321 §4.1.1.1), including LHLO, backend identity,
  transaction reset, capability framing and delivery. Runtime behavior is
  unchanged.

### Fixed

- `HELP`, with or without an argument, now gets a `214` reply that points the
  client at `EHLO` (or `LHLO` on an LMTP server) instead of `502`. RFC 5321
  §4.1.1.8 says servers SHOULD support HELP without arguments.

- A SASL response line during AUTH is no longer limited by `MaxLineLength`
  (RFC 4954 §4 makes challenge and response sizes independent of the command
  line limit). The new `Server.MaxAuthResponseLength` bounds it instead:
  64 KiB by default, enough for large GSSAPI tokens; a negative value removes
  the bound. An over-long response still gets `500 5.5.6` and the connection
  closes. The client side remains a known gap (SMTP-AUTH-32).

- When an LMTP connection fails during the DATA replies,
  `CloseWithLMTPResponse` now returns a temporary `451 4.4.2` failure in its
  `LMTPDataError` for each recipient left without a reply, joined with the
  transport error. Before, those recipients were missing from both results
  (RFC 2033 §5).
- A MAIL or RCPT path with a second `@` in its domain, such as
  `<user@@example.net>`, now gets `501` instead of reaching the backend. No
  RFC 5321 domain or address literal contains `@` (RFC 6409 §5.1 asks
  submission servers to reject such envelope syntax). CHECKLIST.md now records
  the rest of RFC 6409 section by section.

- Command parsing tolerates trailing ASCII spaces and tabs before CRLF
  (RFC 5321 §4.1.1). A single space after `NOOP`, `RSET`, `DATA` or `QUIT`
  previously returned 501; trailing tabs could also prevent dispatch.
  SMTPUTF8 argument bytes and message body whitespace are preserved.

- REQUIRETLS MAIL parameters reject values, including empty values, with
  501 5.5.4. Enabled servers reject plaintext REQUIRETLS with 530 5.7.0.
  Synchronous and pipelined clients reject explicit REQUIRETLS unless TLS
  has completed, even when a plaintext peer advertises the capability.

- The client acts on the first digit of a reply code only (RFC 5321 §4.2.1,
  §4.3.2). A 252 to VRFY, a 251 to MAIL, any other 2yz completion, and any 3yz
  to DATA now succeed; before, every command but RCPT needed its exact code
  (250, 220, 221, 354) and returned an `SMTPError` otherwise. Pipelined MAIL
  and RCPT follow the same rule. Callers that relied on `Verify` failing with
  252 now get nil.

- DATA body writes could block indefinitely before Close. The client now
  applies `DataTransferTimeout` to each network write, including the final
  flush, and retains a write failure so a partial message cannot be retried or
  completed accidentally. SMTP and LMTP share this behavior. The default is
  three minutes; a nonpositive value disables it. `SubmissionTimeout` now
  controls only the final reply, independently of writing the body/terminator.

- Preserve received ORCPT address-type spelling through relay: decoding no longer
  uppercases the type, and the outbound client accepts supported types in any
  ASCII letter case while retaining the supplied spelling. Hosts comparing
  `RcptOptions.OriginalRecipientType` must now compare it case-insensitively.

- The first line of the HELO and EHLO replies now starts with the server's
  domain (`250-mx.example.net Hello client.example.org`), as RFC 5321
  §4.1.1.1 requires; it used to be `250-Hello client.example.org`. Tests that
  match the exact reply text need updating.

- RSET and QUIT with arguments now return 501 without clearing the active
  transaction or closing the connection (RFC 5321 §§4.1.1, 4.3.2).

- Multiline server replies repeat the enhanced status code on every line, as
  RFC 2034 §4 requires; it used to appear on the last line only, so a client
  reading the first line (including this package's) found no status code.

- `Client.Quit` after STARTTLS sends QUIT immediately instead of first
  sending a fresh EHLO, so a client rejecting the negotiated security quits
  at once (RFC 3207 §4.1).

- LMTP BDAT LAST now returns zero replies with no accepted recipients and one
  reply per accepted RCPT on early size, backend or short-transfer failures.
  Duplicate recipients and explicit backend outcomes are retained. Ordinary
  SMTP and non-LAST reply counts are unchanged. Hosts consuming raw LMTP
  replies must account for these corrected counts (RFC 2033 section 4.3).

- Invalid enabled MT-PRIORITY policy names now receive EHLO/LHLO
  `451 4.3.5` before backend session creation, instead of advertising values
  outside RFC 6710's ASCII grammar or its 20-octet limit. An empty name still
  omits the policy; a disabled extension ignores the unused configuration.

- LMTP BDAT LAST flushes each recipient reply in RCPT order as soon as its
  status is available, without waiting for later deliveries or `LMTPData` to
  return. Unset statuses still use the backend's final result; transaction
  reset and subsequent commands wait for the backend to finish.

### Added

- RFC 8689 REQUIRETLS envelope checklist and certificate-verified wire tests
  for advertisement, grammar, TLS-only use, per-message tags, reset, extended
  MAIL length, client negotiation and the Appendix A.1 envelope. Header,
  trust/routing, queue and bounce responsibilities remain explicit.

- Two checked RFC 5321 §§4.5.3.2/4.5.3.2.5 DATA timeout rows, with per-buffer
  renewal, SMTP/LMTP framing, blocked-write, error and configuration tests.

- Six RFC 3461 relay transport checklist mappings, split from the previously
  combined host rows: ENVID, RET, per-recipient NOTIFY, original ORCPT, optional
  host-added ORCPT and omission of parameters for a non-DSN next hop. Real SMTP
  wire tests cover ordinary and pipelined outbound delivery. Queueing, routing
  and report-generation duties remain explicitly outside transport coverage.

- Checked RFC 4954 §5 MAIL `AUTH=` syntax (server decoding, malformed values,
  unauthenticated clients, client encoding and a client-to-server round trip)
  and §6 host failure replies (534/538/535/530/454) with wire tests.

- Seven more RFC 5321 core rows: server identification in HELO/EHLO,
  local-part case, address-literal HELO/EHLO, NOOP parameters, commands
  allowed at any time and client timeouts, each with a wire test; the
  server's own command timeout is n/a (host configuration).

- Dated line-by-line RFC 5321 sections 3–4 audit: 105 additional checklist
  rows, 13 mapped to wire proofs and 92 with explicit host/unsupported
  reasons. Five new wire tests cover command syntax/state, opaque content
  above 64 KiB, quoted mailbox equivalence, HELO framing and client exchanges.
  Existing open checklist slices are identified for merge reconciliation.

- RFC 2034 (ENHANCEDSTATUSCODES) checklist section: nine rows, seven mapped
  to new wire tests.

- Checked RFC 3207 STARTTLS policy rows: immediate TLS-state decisions by
  both peers, QUIT after a rejected negotiation, TLS required for selected
  hosts, opportunistic TLS and post-TLS capability changes.

- Six wire-tested RFC 2033/6531 checklist clauses from four formerly combined
  gaps: zero-recipient LAST, size/backend/short-transfer LAST failures,
  explicitly declared internationalized headers and host-selected next-hop
  rejection. Remaining content classification and routing/report policy stay
  explicit host duties; no new public API or automatic MIME inspection.

- Wire proofs for PLAIN over verified TLS, backend MAIL storage refusals (452),
  and default SMTPUTF8, RRVS and DELIVERBY command-length allowances. Five
  previously unmapped checklist rows now have executable proofs (281/387).
- Five previously unmapped transport requirements now have wire proofs:
  MT-PRIORITY profile grammar and independent DELIVERBY negotiation,
  STARTTLS at a pipeline boundary, AUTH between completed pipeline groups,
  and combined DSN commands at the default 2000-octet budget. Host scheduling,
  content classification and notification responsibilities remain explicit. An
  additional binary-refusal wire test strengthens the existing body-option
  safeguard; binary sending remains unsupported.

- README badges for CI, the enforced coverage floor and the checklist
  (276/387 mapped), checked against CHECKLIST.md and the CI `FLOOR` by
  `TestReadmeBadges`. The CI coverage floor rises from 85% to 94.5%.

- Checked RFC 6409 submission authentication error/backend contract, with
  failed-AUTH recovery, independent authorization, null return paths, transaction
  resets and DATA/BDAT wire tests. Remaining submission requirements are explicit.

- Postfix XCLIENT checklist for session state, trust, TLS retention, pipelining
  and the published example. Remaining value-validation/xtext and host-policy
  gaps are explicit; XCLIENT is not an IETF RFC.

- Checked RFC 2033 LMTP requirements, the RFC's mixed-recipient example,
  ordered/duplicate/multiline DATA and BDAT replies, fallback backend results,
  transaction isolation and client partial-disconnect results. Host durability
  and deployment duties and remaining client/BDAT gaps are explicit.

- Checked RFC 6710 MT-PRIORITY transport requirements, submission/relay
  envelopes, all 19 values, SMTP/LMTP advertisement, transaction state and
  backend policy status tests. A priority parser fuzz target uses the RFC's
  grammar as an independent oracle. Authorization, assignment policies,
  queue scheduling and relay/DSN metadata remain explicit host duties.

- Checked RFC 2852 DELIVERBY transport requirements, section 6 envelopes,
  minimum/deadline/state tests and a grammar oracle for the existing BY fuzzer.
  Queue expiry, DSNs and routing policy are explicit host responsibilities.

- Checked RFC 7293 RRVS requirements: the EHLO keyword, the strict RCPT
  parameter grammar and the client's sending rules. The ownership check,
  relaying and the header field are explicit host responsibilities.

- Checked RFC 6531 SMTPUTF8 envelope requirements: the EHLO keyword, the MAIL
  parameter, UTF-8 mailboxes, per-transaction state and ASCII VRFY/EXPN
  replies. Message headers, IDNA, downgrade and trace fields are explicit host
  responsibilities.

- Checked RFC 3030 CHUNKING/BINARYMIME transport requirements, the RFC's
  single-chunk and pipelined binary examples, error/recovery and byte-preservation
  tests, and a BDAT argument fuzzer using an independent grammar/integer oracle.
  Host MIME/relay obligations and implementation limits are explicit.

- RFC 3461 DSN parameter/protocol checklist, the six-recipient submission
  example, syntax/error/state/size tests and a NOTIFY list fuzz target checked
  against an independent ASCII grammar. Notification lifecycle, downgrade
  policy and unsupported address-type responsibilities are explicit gaps.

- RFC 6152 8BITMIME checklist with the RFC envelope/command example, all high-bit
  octets, 1000-octet lines, dot transparency and explicit host/gap rows. A DATA
  fuzz target compares byte preservation with Go's textproto transparency reader.
- RFC 4954 AUTH exchange checklist rows, wire tests for the RFC's PLAIN and
  empty EXTERNAL examples, malformed Base64, retries and response sizes; a
  SASL response decoder fuzz target runs in CI. Remaining authentication
  policy and SASL buffer/security-layer limitations are recorded explicitly.

- Clause-by-clause RFC 2920 PIPELINING checklist, its successful and failed
  recipient examples, multiline/positional client reply tests and explicit
  documentation of the client's fixed 4096-byte window limitation.

- Checked RFC 1870 SIZE requirements and its multi-recipient example, with
  boundary, message-octet counting and client error-propagation tests. A numeric
  limit fuzz target uses an arbitrary-precision reference and runs in CI.

- Clause-by-clause RFC 3207 STARTTLS checklist, with tests for the usage example,
  TLS state, session replacement, plaintext local delivery, temporary refusal,
  certificate verification and a stalled client handshake. Host policy and
  unsupported enforcement modes are explicitly recorded.

### Fixed

- The client sends `AUTH=<>` for an unknown submitter (an empty
  `MailOptions.Auth`) instead of the invalid empty `AUTH=` (RFC 4954 §5).

- The server answers a malformed MAIL `AUTH=` value with 501 5.5.4, the
  parameter syntax error of RFC 5321 §4.2.2, instead of 500.

- `ErrAuthRequired` now replies with 530 instead of 502, as required for
  unauthenticated submission by RFC 6409 section 4.3 and RFC 4954 section 6.

- XCLIENT now refuses assertions throughout a mail transaction (503), rejects
  an empty assertion (501), and applies attributes atomically. A successful
  assertion logs out the old backend session, clears its SMTP greeting and
  authentication, and requires a fresh HELO/EHLO. Accumulated proxy attributes
  and TLS survive; previous backend identity snapshots no longer change.

- The LMTP client accepts every 2xx final recipient reply as positive completion
  (RFC 2033), instead of misreporting successful codes other than 250 as
  per-recipient failures. Mixed failures and partial results retain their
  recipient association.

- The LMTP client no longer falls back to SMTP HELO after LHLO is refused
  with 500 or 502, preserving protocol-misconfiguration errors.

- MT-PRIORITY rejects `+1`, `-0`, leading zeroes and other spellings outside
  RFC 6710's grammar instead of accepting them as integers. Malformed values
  now receive 501 5.5.2; valid priorities remain unchanged at the backend.

- DELIVERBY accepts case-insensitive ABNF mode/trace letters. Valid return
  deadlines below the server minimum receive 555 instead of a syntax error.
  The client refuses return deadlines below the peer's advertised minimum
  (or malformed minima) before writing MAIL.

- RRVS: the server refuses a value with fractional seconds or a no-support
  action other than `R` or `C` (it used to ignore anything after `;`), and
  passes the action to the backend in `RcptOptions.RequireRecipientValidSinceAction`.
  The client sends the action, sends the timestamp in UTC, and returns an error
  instead of silently dropping RRVS when the server does not offer it, unless
  the action is `C`.

- Empty assignments such as `SMTPUTF8=` now receive 501 5.5.4, just like
  non-empty values. ESMTP parsing preserves the equals sign so the server can
  distinguish a bare flag from an empty assignment (RFC 6531 §3.1 item 4).
  Rejected parameters never reach the backend or start a mail transaction.

- The server refuses a non-ASCII reverse-path (550 5.6.7) or forward-path
  (553 5.6.7) unless the MAIL carried SMTPUTF8, refuses addresses that are not
  valid UTF-8 (501 5.5.2), and refuses a value on SMTPUTF8 (501 5.5.4). The
  client refuses to send a non-ASCII address without SMTPUTF8 instead of
  writing it (RFC 6531 §§3.1, 3.4, 3.5). Callers sending such addresses through
  `Mail`/`Rcpt` must now set `MailOptions.UTF8`; `SendMail` already does.

- Failed and out-of-sequence BDAT chunks are fully consumed before replying;
  already-pipelined rejected chunks cannot inject their payload as commands.
  Oversized chunks now get their 552 only after the full payload, as RFC 3030
  requires. Truncated chunks close the connection without partial delivery.
- Command length limits are applied when parsing commands, preserving valid
  opaque body bytes read ahead in the same packet and bounding command memory.
- The BDAT LAST marker rejects Unicode look-alikes instead of case-folding
  them into the ASCII keyword.

- DSN NOTIFY now accepts repeated conditions and null list elements permitted
  by RFC 3461's RFC 822 list grammar, exposing unique conditions to the backend.
  NEVER still must be standalone; client options can repeat valid conditions.
- Non-ASCII RET/NOTIFY look-alikes such as long s (`ſ`) are refused instead of
  becoming valid ASCII keywords during Unicode case conversion.

- The client honors `MailOptions.Body` instead of ignoring it. `Body7Bit` selects
  7-bit transport, and explicit `Body8BitMIME` fails before MAIL if unsupported.
  Invalid body types and `BodyBinaryMIME` are refused rather than silently
  downgraded; BINARYMIME needs BDAT, which this client does not implement.
  Empty/default options retain automatic 8BITMIME selection. Callers remain
  responsible for providing content matching the transport; no MIME conversion
  or content validation is added.

- Malformed Base64 in AUTH now returns `501 5.5.2` instead of `454 4.7.0`;
  a missing mechanism returns `501`, successful authentication uses `235 2.7.0`,
  unknown mechanisms use `504 5.5.4`, and oversized continuations use `500 5.5.6`.
  SASL decoding rejects CR/LF rather than silently discarding them.
- The client defers an initial SASL response that would exceed the 512-octet
  AUTH command limit until the server's empty challenge. Invalid Base64
  challenges trigger cancellation; terminal AUTH failures no longer send a
  stray asterisk as a new SMTP command.
- Server synchronization and unknown/malformed-command replies now flush before
  later buffered commands are processed, as required by RFC 2920. RSET, MAIL
  and RCPT replies can still share a batch.
- An unwritten DATA writer now sends only the dot terminator, without the
  extra blank line textproto.DotWriter normally adds. This permits RFC 2920's
  recovery when a peer accepts DATA despite refusing every recipient. Writes
  after DATA close return an error.

- SIZE declarations now accept 1–20 decimal digits through the signed 64-bit
  API range instead of stopping at 4 GiB. Syntactically valid larger values
  receive 552 rather than a syntax error; signs and overlong values receive
  501. Unlimited servers advertise `SIZE 0`, explicitly conveying no fixed
  configured maximum instead of promising resource checks through bare SIZE.
- Clients reject negative message-size estimates and malformed signed EHLO
  SIZE limits. MailOptions.Size documentation now includes headers and CRLF.

- Ordinary server reply lines now fit RFC 5321's 512-octet limit, counting
  status codes and CRLF. Overlong backend diagnostics, greetings and EHLO lines
  are truncated at UTF-8 character boundaries while keeping the status and
  existing multiline framing. SASL challenges are preserved intact under
  RFC 4954's independent size rules. Backend capability tokens must fit on
  their own line; longer diagnostics can use newline-separated text.
- STARTTLS parameters are now refused with 501 instead of being discarded and
  starting a handshake. Parsing and its fuzz oracle preserve the parameters.
- STARTTLS client constructors now complete the handshake and certificate
  verification before returning success. Negotiation uses CommandTimeout;
  failures close the connection. Pre-TLS extensions and recipients are cleared,
  and nested TLS upgrades are refused without disturbing the active session.
- The server discards pre-TLS XCLIENT assertions after STARTTLS, alongside its
  existing EHLO/authentication/session reset. Trusted proxies must reassert
  that identity over the encrypted connection.

## [0.30.0] - 2026-10-19

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

- ESMTP parameters are now separated by SP and HTAB only (RFC 5321 §4.1.2).
  The server used to split them, and trim the command argument, on any
  Unicode whitespace, so a U+0085 NEL or U+00A0 NBSP inside or at the end of
  a value silently cut the value short (`AUTH=x\u0085` arrived as `AUTH=x`),
  and could even make a new parameter. Those bytes are now value content,
  which RFC 6531 allows in an SMTPUTF8 esmtp-value. The HELO/EHLO domain now
  also ends at an HTAB, not only a space. CI's `FuzzParseArgs` found this.
- The same SP/HTAB rule now holds for the rest of the command arguments:
  the path after `MAIL FROM:` and `RCPT TO:`, the XCLIENT attributes, the AUTH
  mechanism and initial response, and the BDAT size and `LAST`. A NEL or NBSP
  at the end of the last MAIL or RCPT parameter was still trimmed, and one in
  an XCLIENT value split it in two. Now an XCLIENT value keeps the byte, and
  where the grammar asks for ASCII the argument is refused with the existing
  error (`BDAT 8\u0085` is `501 Malformed size argument`, not an 8-byte chunk).

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
