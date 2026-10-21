# Coverage

The BDAT LAST reply-flushing follow-up adds gated wire tests for zero-length
and nonempty LAST chunks, prompt per-recipient replies, duplicate paths,
multiline failures, unset success/error results, backend panic recovery and
post-delivery transaction state. Each gate opens only after the preceding
reply arrives, including the last explicit reply before the backend returns.
Focused tests and vet are checked locally; full coverage and race validation
run in CI. No new coverage percentage is claimed for this follow-up.

After the Postfix XCLIENT session-state audit, statement coverage of the library
package and `internal/checklist` is **95.4%** combined (library **95.1%**, checker
**99.3%**), measured locally on Go 1.27.1 linux/arm64 without the race
detector. This includes the preceding LMTP and MT-PRIORITY audits. The local
command was:

```
go test -count=1 -coverprofile=coverage.out . ./internal/...
go tool cover -func=coverage.out
```

The preceding LMTP positive-completion follow-up measured 95.1% combined
(library 94.8%, checker 99.3%). Those tests
exercise every final recipient code from 200 to 299, non-2xx boundaries,
multiline replies mixed with temporary/permanent failures, `Close`, and
partial results on disconnect. LMTP-CLIENT-06 is now mapped to these tests.

XCLIENT tests cover transaction refusal after MAIL/RCPT/between BDAT chunks,
atomic rejection, empty commands, backend logout/replacement, fresh greetings
and authentication, retained HELO/PROTO/identity snapshots, TLS retention,
trust configuration/revocation, caching and the Postfix pipelined example.
No standalone parser was added: existing SMTP token-parser fuzzers are unchanged.
Attribute xtext decoding, address/protocol/sentinel validation, full port/destination
support and immediate connection-level rejection remain documented gaps.

CI uses the same package list with `-race` and the current stable Go:

```
go test -race -count=1 -covermode=atomic -coverprofile=coverage.out . ./internal/...
go tool cover -func=coverage.out
```

`cmd/smtp-debug-server`, a demo program, is left out of the figure because
the package list does not name it. The 85% CI floor is unchanged; the merged
suite's CI figure may differ by Go version. Both the combined and library-only
local figures now exceed 95%. Raising the gate and moving to the shared workflow remain a separate slice after CI validation.

Earlier CI runs reported 87.2% combined (library 86.2%, checker 99.3%) on
Go 1.27.2 before the 503 tests of #87 landed. Local and CI statement counts
can differ between Go versions, so that historical result is not a measurement
of the merged suite. The per-audit measurements below are historical too.

After the RFC 3207 STARTTLS audit, a local run on Go 1.27.1 (linux/arm64,
without the race detector) reports **91.0%** combined: the library is 90.5%
and `internal/checklist` is 99.3%. This includes handshake success, certificate
rejection, handshake timeout and nested-upgrade refusal. The next CI run must
supply the comparable CI figure; the 85% gate is unchanged.

After enforcing the ordinary reply line limit (SMTP-LIM-06), the same local
Go 1.27.1 run reports **91.2%** combined (library **90.7%**, checker **99.3%**).
The new tests cover byte boundaries with and without enhanced statuses,
multiline replies, complete UTF-8 characters, backend transaction state and
the RFC 4954 exception for SASL challenges. The CI floor remains 85%.

After the RFC 1870 SIZE audit, the same local Go 1.27.1 run reports
**91.4%** combined (library **90.9%**, checker **99.3%**). Tests cover
20-digit syntax and integer overflow, backend estimates above 4 GiB, explicit
unlimited advertisement, dot transparency and CRLF byte counting, the RFC's
recipient-error example, and client errors at every transfer stage. The new
numeric-limit fuzz target uses an arbitrary-precision reference and runs for
10 seconds in CI. The CI floor remains 85%; this is still below the target.

After the RFC 2920 PIPELINING audit, the same local Go 1.27.1 run reports
**91.5%** combined (library **91.0%**, checker **99.3%**). Tests cover reply
flush boundaries with later commands already buffered, positional and multiline
response matching after failures, the RFC's recipient examples, and empty DATA
recovery with exactly the dot terminator. The TCP window is still assumed, not
discovered; PIPE-CLIENT-07 records that conformance gap. No parser was added or
changed by this audit; existing parser fuzz targets and the 85% CI floor remain.

After the RFC 6152 8BITMIME audit, the same local Go 1.27.1 run reports
**91.6%** combined (library **91.1%**, checker **99.3%**).
The added tests cover explicit client body choices and refusal paths,
all high-bit octets through DATA, the RFC envelope/example sequence,
duplicate/invalid BODY parameters, dot transparency and 1000-octet lines.
The DATA fuzz target checks byte preservation against a direct stuffing
oracle and Go's `net/textproto` reader. MIME conversion/validation and
backend delivery remain outside these transport tests; see the checklist's
explicit gap and host responsibility rows. The 85% gate is unchanged.

The other `go-*` libraries fail CI below 95%, through go-spf's shared
`rfc-verification.yml`. go-smtp is not there yet, and this slot (the RFC 5321
core) does not close the gap, so CI keeps its own steps and gates on a **floor
of 85%**, to be raised as the figure grows. The shared workflow replaces them
once coverage reaches 95%.

After the RFC 4954 AUTH exchange slice, a local Go 1.27.1 run of the same
package list without `-race` reports **91.2%** combined (library **90.7%**,
checker **99.3%**). This includes the new SASL decoder's fuzz seeds, the AUTH
wire examples, invalid response/error paths and oversized initial responses.
The 85% CI floor is unchanged; this is not a claim that the 95% target or all
RFC 4954 requirements are met.

The RFC 3030 audit adds the RFC's 86-octet single-chunk example and its
100000/324/zero-LAST pipelined example with synthetic binary content, all 256
octet values, rejection-before-reply ordering, failed pipeline draining,
truncated transfers, discard timeouts, RSET isolation, and command/body
read-ahead framing. The BDAT argument parser and the bounded command reader
are 100% covered in this local run; timed argument fuzzing uses a regexp and
arbitrary-precision integer reference. The existing 85% floor is unchanged.
This is a transport slice, not full MIME/relay conformance or the 95% target.

The DSN audit adds the RFC 3461 §10.1 submission envelope, per-recipient
metadata and RSET isolation, invalid/duplicate parameter refusals, backend
status preservation, default size allowances and client validation. The new
NOTIFY parser accepts RFC 822 lists (including repeated/null list elements),
normalizes backend flags, and refuses non-ASCII look-alikes; its fuzz target
uses an independent ASCII grammar. No notification generator or queue is
covered or supplied by this transport. Host responsibilities and unsupported
address types remain explicit in the checklist; the 85% CI floor is unchanged.

The RFC 6710 audit covers all 19 transport values, malformed spellings,
SMTP/LMTP advertisements, default command-length allowance, client fallback,
transaction isolation after reset/EHLO/DATA, backend policy replies and section
8's submission/relay MAIL envelopes. The new priority parser is 100% covered;
its fuzzer checks acceptance against the ABNF grammar and values against an
independent integer conversion. Positive-priority authorization, scheduling,
policy rounding, trace/log fields and relay/DSN metadata are host work, not
claimed as library conformance. The 85% gate remains below the 95% target.

## Left uncovered on purpose

| File | Function | Reason |
|------|----------|--------|
| `internal/checklist/main.go` | `main` | Exiting the process cannot be tested in-process. All of the checker's logic is in `run`, which the tests cover; CI also runs the command itself. |
| `cmd/smtp-debug-server/main.go` | everything | A demo server for manual testing, not part of the library; not in the figure. |

## Not covered yet

These are known gaps, not exclusions. The functions below are the ones with the
lowest coverage in the package; the next slots, which check the extensions
clause by clause, are where most of them get tests.

- **Never run by a test:** `Conn.handlePanic`, which only the BDAT and LMTP
  panic paths call. The TLS client helpers, the listen helpers and the `Conn`
  accessors are covered by `helpers_test.go`; `SendMailTLS` is tested only
  against an untrusted certificate, so its success path is not.
- **Partly covered:** the error branches of `handleMail`, `handleRcpt`,
  `handleAuth`, `handleBdat`, `handleDataLMTP` and `handleXClient` (RFC 3461,
  4954, 3030, 2033 and XCLIENT rows), and the client's `Auth`, `Verify`,
  `Extension`, `Noop`, `Quit` and `Reset` failure paths.
- **RFC 5321 core:** SMTP-LIM-06 now has boundary, multiline, UTF-8 and
  backend transaction tests for reply lengths. SASL challenges are tested to
  retain their independent RFC 4954 size rules. This does not complete the
  extension audits or reach the 95% coverage target.


The RFC 2033 audit adds mixed/duplicate/multiline per-recipient DATA and BDAT
outcomes, fallback backend success/failure expansion, unset statuses,
post-delivery transaction isolation, greeting/command checks and partial
client responses on disconnect. The regression test proves that refused LHLO
must not fall back to SMTP HELO. The checklist records unresolved BDAT reply
count/early-error paths, client streaming/temporary-failure/duplicate-map
limits, positive-reply classification and mandatory host durability/deployment
duties. No new parser is introduced, so existing shared parser fuzzers apply.
