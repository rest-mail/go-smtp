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

The figure depends on the Go toolchain, because the cover tool splits
statements into blocks differently from one release to the next. CI uses the
current stable Go (1.27.2 when this was measured) and gets 87.2%. The same tests
on Go 1.27.1 report 89.1% (the package alone 88.4%). The race detector does not
change the number: the uncovered blocks are the same in both runs. The floor
leaves room for that difference.

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
- **RFC 5321 core:** every requirement in CHECKLIST.md marked tested has a test;
  the two that do not (SMTP-ORD-05, SMTP-LIM-06) are listed there with the
  reason.
