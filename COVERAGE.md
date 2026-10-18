# Coverage

Statement coverage of the library package and `internal/checklist` is **85.9%**
(the package alone 85.0%), measured with `go test -covermode=atomic -coverprofile=… . ./internal/...`.
`cmd/smtp-debug-server`, a demo program, is left out of the figure.

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

- **Never run by a test:** the TLS client helpers (`DialTLS`, `NewClientStartTLS`,
  `SendMailTLS`, `DialStartTLS` partly), the listen helpers (`ListenAndServe`,
  `ListenAndServeTLS`, `network`), `Server.String`, the `Conn` accessors
  (`Server`, `Hostname`, `Conn`, `Reject`), `Backend.NewSession`'s default,
  `SMTPError.Temporary` and the client `Error` and `Unwrap`.
- **Partly covered:** the error branches of `handleMail`, `handleRcpt`,
  `handleAuth`, `handleBdat`, `handleDataLMTP` and `handleXClient` (RFC 3461,
  4954, 3030, 2033 and XCLIENT rows), and the client's `Auth`, `Verify`,
  `Extension`, `Noop`, `Quit` and `Reset` failure paths.
- **RFC 5321 core:** every requirement in CHECKLIST.md marked tested has a test;
  the two that do not (SMTP-ORD-05, SMTP-LIM-06) are listed there with the
  reason.
