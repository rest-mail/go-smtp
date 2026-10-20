# Coverage

Statement coverage of the library package and `internal/checklist` is **87.2%**
as CI measures it, which is the number the gate compares with its floor. CI runs

```
go test -race -count=1 -covermode=atomic -coverprofile=coverage.out . ./internal/...
go tool cover -func=coverage.out
```

(the package alone 86.2%, `internal/checklist` 99.3%). `cmd/smtp-debug-server`,
a demo program, is left out of the figure because the package list does not
name it.

The local and CI figures differ by about a point. Both runs leave the same
blocks uncovered; only the statement count of some blocks differs (a
composite literal counts as 3 statements locally and 1 in CI). CI uses the
current stable Go (1.27.2 when this was measured) and gets 87.2% (measured before the 503 tests of #87 landed, so the next run reads higher); the same tests
on Go 1.27.1 on the Pi report 89.9% (the package alone 89.3%, no race detector
there; measured locally after #88 landed). The floor leaves room for that difference.

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

The other `go-*` libraries fail CI below 95%, through go-spf's shared
`rfc-verification.yml`. go-smtp is not there yet, and this slot (the RFC 5321
core) does not close the gap, so CI keeps its own steps and gates on a **floor
of 85%**, to be raised as the figure grows. The shared workflow replaces them
once coverage reaches 95%.

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
