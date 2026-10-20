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
- **RFC 5321 core:** every requirement in CHECKLIST.md marked tested has a test;
  the one that does not (SMTP-LIM-06) is listed there with the
  reason.
