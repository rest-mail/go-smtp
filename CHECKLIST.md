# RFC 5321 checklist

Every requirement [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321) (SMTP)
places on the parts of go-smtp that this slice covers: the server and client
core, item by item, with the tests that cover it. A section number alone is
RFC 5321. The list takes in the MUSTs and SHOULDs, and the normative behaviour
that carries no keyword (level "Normative"), such as the grammar.

An item that does not apply, or is a known gap, says "n/a" and why. CI checks
this file against the tests with `go run ./internal/checklist`; the format is
described in the [README](README.md#the-rfc-checklist).

Not covered yet: each extension (PIPELINING, 8BITMIME, SIZE, DSN, CHUNKING,
SMTPUTF8, STARTTLS, AUTH, LMTP, RRVS, DELIVERBY, MT-PRIORITY, XCLIENT) is one
row in the last section, mapping its existing tests, and has not been checked
clause by clause; later slots do that. RFC 6409 (submission) is not in this
slot. The reply
line length of §4.5.3.1.5 is recorded as SMTP-LIM-06.


## Syntax and lexical rules (§2.3, §2.4, §4.1.2)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SMTP-SYN-01 | 4.1.2 | MUST | The reverse-path is a path or the null path `<>`; `MAIL FROM:<>` is accepted. | `TestServerEmptyFrom2`, `TestParser`, `FuzzParseReversePath` |
| SMTP-SYN-02 | 4.1.2 | MUST | A path is `<`, an optional source route and `:`, a mailbox and `>`; a quoted-string local-part holds no control characters; text that is not a path is a 501. | `TestParser`, `TestParserRejectsControlBytes`, `TestServerEmptyFrom1`, `FuzzParseReversePath`, `FuzzParseForwardPath` |
| SMTP-SYN-03 | 4.1.1.3, 4.5.1 | MUST | `RCPT TO:<Postmaster>` is accepted without a domain, in any letter case; the domain-qualified form keeps its domain. | `TestServerPostmasterRcpt`, `TestParsePostmasterPath`, `FuzzParseForwardPath` |
| SMTP-SYN-04 | 4.1.1.3 | Normative | A forward-path is never null: `RCPT TO:<>` and an empty `RCPT TO:` are refused. | `TestServerEmptyTo`, `FuzzParseForwardPath` |
| SMTP-SYN-05 | 2.4 | MUST | Command verbs and the `FROM:` and `TO:` keywords are case-insensitive and ASCII; a non-ASCII look-alike is not a verb. | `TestRFC5321_CommandsCaseInsensitive`, `TestParseCmdASCII`, `FuzzParseCmd` |
| SMTP-SYN-06 | 4.1.1.1, 4.1.2 | Normative | Parameters are `keyword` or `keyword=value` separated by spaces; a value may itself hold `=`. | `TestParseArgsBoundaries`, `TestParseArgsEqualsInValue`, `FuzzParseArgs` |
| SMTP-SYN-07 | 4.1.1.2 | Normative | Whitespace separates the path from the parameters: `MAIL FROM:<a@b>SIZE=10` is refused, not read as a parameter. | `TestMailParamRequiresSpace` |
| SMTP-SYN-08 | 4.1.2 | Normative | A parameter keyword is not repeated within one command: `SIZE=10 SIZE=20` is a 501. | `TestMailParamNoDuplicates` |
| SMTP-SYN-09 | 4.1.1.1 | MUST | `HELO` and `EHLO` without a domain argument are a 501. | `TestRFC5321_UnknownAndArgumentErrors` |
| SMTP-SYN-10 | 4.1.1.4 | MUST | `DATA` with an argument is a 501. | `TestRFC5321_UnknownAndArgumentErrors` |
| SMTP-SYN-11 | 2.3.8 | Normative | Only CRLF ends a line: a bare LF is not a line end, so `LF.LF` does not end the data (SMTP smuggling). | `TestServer_smtpSmuggling`, `TestServer_LFDotLF` |
| SMTP-SYN-12 | 2.2.2 | Normative | A MAIL parameter the server does not know is refused, not ignored. | `TestServerUnknownArg` |

## Command order and state (§3.3, §4.1.1.2, §4.1.4)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SMTP-ORD-01 | 4.1.4 | MUST | MAIL, RCPT and DATA are accepted only in that order; a command out of order is refused and the session stays usable. | `TestRFC5321_CommandOrder` |
| SMTP-ORD-02 | 4.1.4 | Normative | No mail transaction starts before the client has introduced itself with HELO or EHLO. | `TestRFC5321_CommandOrder` |
| SMTP-ORD-03 | 3.3, 4.1.1.4 | MUST | DATA is refused when the transaction has no recipient. | `TestRFC5321_CommandOrder` |
| SMTP-ORD-04 | 4.1.1.2, 4.1.4 | MUST | A second MAIL inside a transaction is a 503 and leaves the transaction (sender and recipients) intact; after RSET a new MAIL is accepted. | `TestServerNestedMailRejected`, `TestServerResetThenMail` |
| SMTP-ORD-05 | 4.1.4 | SHOULD | A command out of sequence is answered 503 5.5.1: MAIL or AUTH before HELO/EHLO, RCPT before MAIL, DATA or BDAT without a recipient, a transaction command between BDAT chunks, DATA after BODY=BINARYMIME, and STARTTLS on a TLS connection. | `TestServerBadSequence`, `TestServerSTARTTLSAlreadyTLSBadSequence`, `TestClientBadSequenceError` |

## Commands (§4.1.1, §4.5.1)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SMTP-CMD-01 | 4.1.1.1 | MUST | EHLO is answered 250: the first line holds the greeting, each extension is on its own `250-` line, and the last line is `250 `; a backend can add capabilities. | `TestServerExtraCaps`, `TestServerFeatureBackend` |
| SMTP-CMD-02 | 4.1.1.1, 4.5.1 | MUST | HELO is supported and answered 250. | `TestServer_helo`, `TestRFC5321_CommandsCaseInsensitive` |
| SMTP-CMD-03 | 4.1.1.2 | MUST | MAIL FROM begins a transaction and is answered 250 when accepted. | `TestServer`, `TestServerEmptyFrom2` |
| SMTP-CMD-04 | 4.1.1.9 | MUST | NOOP does nothing and is answered 250. | `TestServer_otherCommands` |
| SMTP-CMD-05 | 3.5.3, 4.1.1.6 | MUST | VRFY is supported: a server that will not confirm an address answers 252. | `TestServer_otherCommands` |
| SMTP-CMD-06 | 4.1.1.10 | MUST | QUIT is answered 221 before the connection closes. | `TestServer_otherCommands`, `TestQuitReplySentBeforeClose` |
| SMTP-CMD-07 | 4.2.4 | MUST | A command the server does not implement is a 502 (tested for HELP; SEND, SOML, SAML, EXPN and TURN share the code path). | `TestServer_otherCommands` |
| SMTP-CMD-08 | 4.2.4 | MUST | An unrecognised command is a 500, and the server answers the next command. | `TestServer_tooManyInvalidCommands`, `TestRFC5321_UnknownAndArgumentErrors` |
| SMTP-CMD-09 | 4.5.1 | MUST | The minimum implementation (EHLO, HELO, MAIL, RCPT, DATA, RSET, NOOP, QUIT, VRFY) is supported. | `TestServer`, `TestServer_helo`, `TestServer_otherCommands` |
| SMTP-RSET-01 | 4.1.1.5 | MUST | RSET clears the sender, the recipients and the message data, and is answered 250. | `TestRFC5321_RsetAndSecondEhloClearTransaction`, `TestServer_otherCommands` |
| SMTP-RSET-02 | 4.1.4 | MUST | A second EHLO or HELO clears the transaction exactly as RSET does. | `TestRFC5321_RsetAndSecondEhloClearTransaction` |
| SMTP-RCPT-01 | 3.3, 4.1.1.3 | MUST | A transaction may have several recipients; each is answered on its own. | `TestRFC5321_RecipientLimit`, `TestRFC5321_HundredRecipients` |
| SMTP-RCPT-02 | 4.5.3.1.8 | SHOULD | A server that limits recipients answers the ones over the limit 452 4.5.3, and the accepted ones stay in the transaction. | `TestRFC5321_RecipientLimit` |

## Message data (§4.1.1.4, §4.5.2)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SMTP-DATA-01 | 4.1.1.4 | MUST | DATA is answered 354, then the server reads lines up to one holding only `.`; the 354 is sent before the body is read. | `TestServer`, `TestServer_LFDotLF`, `TestDataReplySentBeforeBody`, `TestServer_EmptyMessage` |
| SMTP-DATA-02 | 4.5.2 | MUST | A leading `.` on a line is removed: `..x` is delivered as `.x`. | `TestServer`, `TestRFC5321_DotUnstuffing` |
| SMTP-DATA-03 | 4.5.2 | MUST | Only a line holding a single `.` ends the data; a line of two dots is content. | `TestRFC5321_DotUnstuffing`, `TestServer_LFDotLF` |
| SMTP-DATA-04 | 4.2.3, 4.1.1.4 | MUST | An accepted message is answered 250; a refused one gets a 5xx (552 when too large) and is not delivered. | `TestServer_tooLongMessage`, `TestServerSizeLimit_OverMaxRejected` |
| SMTP-DATA-05 | 2.3.8 | Normative | The data is delivered as received: line endings are not rewritten, and an empty body is a valid message. | `TestServer_EmptyMessage`, `TestServer_LFDotLF` |
| SMTP-DATA-06 | 4.5.3.1.6 | MUST | A text line of at least 1000 octets is accepted in DATA, whatever the command line limit is. | `TestServer_MaxLineLengthBoundsCommandsNotData` |

## Size limits and timeouts (§4.5.3)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SMTP-LIM-01 | 4.5.3.1.4 | MUST | A command line of 512 octets, CRLF included, is accepted. | `TestRFC5321_CommandLine512` |
| SMTP-LIM-02 | 4.5.3.1.4 | SHOULD | A command line longer than the server supports is answered 500 5.4.0. | `TestServer_TooLongCommand`, `TestServer_tooLongLine` |
| SMTP-LIM-03 | 4.5.3.1.1-3 | MUST | A local-part of 64 octets, a domain of 255 octets and a path of 256 octets are accepted. | `TestRFC5321_MinimumAddressSizes` |
| SMTP-LIM-04 | 4.5.3.1.8 | MUST | At least 100 recipients are accepted in one transaction. | `TestRFC5321_HundredRecipients` |
| SMTP-LIM-05 | 4.5.3.2 | SHOULD | A configured read timeout closes a connection that stops sending, in DATA as well as between commands; the timeout restarts as data arrives. | `TestDataReadTimeoutClosesConnection`, `TestDataBodyReadDeadlineRefresh` |
| SMTP-LIM-06 | 4.5.3.1.5 | MUST | A reply line is at most 512 octets, CRLF included. | n/a: a gap, not asserted yet: the library's own replies are short, but text a backend supplies is not truncated. |

## Replies (§4.2)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SMTP-REP-01 | 4.2 | MUST | The server greets a new connection with a 220 reply. | `TestServer_helo`, `TestServer` |
| SMTP-REP-02 | 3.8, 4.2.2 | MUST | A server that must stop answers 421 before closing: on shutdown, and after an internal error. | `TestServerCloseSends421`, `TestServerPanicRecover`, `TestConnReject` |
| SMTP-REP-03 | 4.2.1 | MUST | The code a backend returns is the reply code, with its text; a plain error is not leaked to the client. | `TestErrorf`, `TestBackendErrorf_StatusNotLeaked`, `TestDataWrappedSMTPError`, `TestMailWrappedSMTPError`, `TestCustomResponse_Mail`, `TestCustomResponse_Rcpt`, `TestCustomResponse_Data`, `TestSMTPErrorTemporary` |

## Connection handling (§3.8, §4.1.1.10), library behaviour

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SMTP-SRV-01 | 3.8 | Normative | The connection closes after QUIT, after a backend asks to close it, and on server shutdown; closing is safe while connections are live. | `TestCloseConnection_Mail`, `TestCloseConnection_Rcpt`, `TestCloseConnection_Data`, `TestCloseConnection_GracefulSuccess`, `TestCloseConnection_NilNoop`, `TestServerShutdown`, `TestServerCloseConcurrent`, `TestConnContextCancelledOnShutdown`, `TestServerAcceptErrorHandling`, `TestCloseConnectionError` |
| SMTP-SRV-02 | 3.8 | Normative | A failure inside the library ends the connection cleanly: a panic in the backend, a failed reply write, a slow client on close. | `TestServerPanicRecover`, `TestWriteErrorBreaksLoop`, `TestReplyWriteErrorEndsConnection`, `TestDataCloseHonoursWriteDeadline`, `TestZeroValueServer` |
| SMTP-SRV-03 | 4.1.1 | Normative | A client that sends many bad commands in a row is closed; the count is of consecutive errors, and interleaved good commands reset it. | `TestErrCountCountsConsecutive`, `TestServer_tooManyInvalidCommands` |
| SMTP-SRV-04 | n/a | Normative | The server reports connection state and errors to its operator without logging probes or hiding real failures. | `TestServerConnState`, `TestHealthcheckNoCommandNotLogged`, `TestMidSessionErrorStillLogged`, `TestConnStateString` |
| SMTP-SRV-05 | n/a | Normative | The server listens on the address it is given, with or without implicit TLS (a unix socket for LMTP), and refuses a bad address. | `TestListenAndServe`, `TestListenAndServeBadAddr`, `TestListenAndServeTLS`, `TestServerNetworkDefaultsToUnixForLMTP` |
| SMTP-SRV-06 | n/a | Normative | A backend is given the connection: its server, the name the client greeted with, and its socket. | `TestBackendFuncAndConnAccessors` |

## Client (§3, §4.1.1, §4.5.2)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SMTP-CLI-01 | 3.2, 4.1.1.1 | MUST | The client reads the greeting and sends EHLO, reading its multi-line reply; it falls back to HELO when EHLO is refused. | `TestHello`, `TestNewClient`, `TestNewClient2`, `TestBasic` |
| SMTP-CLI-02 | 2.4 | MUST | EHLO keywords in the reply are read case-insensitively. | `TestClientEHLOExtensionCaseInsensitive` |
| SMTP-CLI-03 | 4.2.1 | MUST | A 4xx or 5xx reply is returned as an error carrying the code and text, and a 421 ends the session. | `TestBasic_SMTPError`, `TestHello_421Response` |
| SMTP-CLI-04 | 4.5.2 | MUST | The client doubles a leading `.` of each line it sends in DATA and ends the data with a line holding one `.`. | `TestRFC5321_ClientDotStuffing` |
| SMTP-CLI-05 | 4.5.3.1.5 | MUST | A reply line longer than the client supports is an error, not a truncation. | `TestClient_TooLongLine` |
| SMTP-CLI-06 | 4.1.1.5 | MUST | A new MAIL starts with no recipients from the one before, and RSET clears them. | `TestClientMailClearsRcpts`, `TestPipelinerMailClearsRcpts`, `TestPipeline_Reset` |
| SMTP-CLI-07 | 2.2.2 | MUST | The client does not send a MAIL parameter the server did not advertise, or one out of range. | `TestClientMailParamsUnadvertised`, `TestClientMailParamsOutOfRange` |
| SMTP-CLI-08 | n/a | Normative | The client can tell whether a connection it kept is still healthy before it reuses it. | `TestCheckConn_HealthyPlaintext`, `TestCheckConn_ServerClosedPlaintext`, `TestCheckConn_UnsolicitedData`, `TestCheckConn_BufferedData`, `TestCheckConn_TLS` |

## Extensions (one row each; clause-by-clause checks come in later slots)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SMTP-EXT-01 | RFC 2920 | Normative | One row for the extension: PIPELINING: the replies to a batch of commands are sent in order and in one write; the client does not deadlock. The clauses of the RFC are not checked one by one yet. | `TestPipeline_NoRoundTripDeadlock`, `TestPipeline_Integration`, `TestPipeline_NotSupported`, `TestPipeline_LargeGroupDoesNotDeadlock`, `TestPipeline_LMTPSeesOnlyAcceptedRecipients`, `TestPipeline_StalledServerTimesOut`, `TestPipeline_ServerHangupMidGroup`, `TestPipelinedRepliesShareOneWrite`, `TestSingleCommandReplyIsPrompt`, `TestPartialPipelinedLineDoesNotHoldReplies` |
| SMTP-EXT-02 | RFC 6152 | Normative | One row for the extension: 8BITMIME: `BODY=8BITMIME` and `7BIT` are accepted, any other value is refused. The clauses of the RFC are not checked one by one yet. | `TestServer8BITMIME`, `TestServer_BODYInvalidValue` |
| SMTP-EXT-03 | RFC 1870 | Normative | One row for the extension: SIZE: the declared size and the message size are checked against `MaxMessageBytes` (inclusive), and an oversize message is drained and the connection kept. The clauses of the RFC are not checked one by one yet. | `TestServerBadSize`, `TestServerTooBig`, `TestServerSizeLimit_ExactlyMaxAccepted`, `TestServerSizeLimit_OverMaxRejected`, `TestServerSizeLimit_RejectWithinLimitKeepsConnection`, `TestServerSizeLimit_OversizedKeepsConnection`, `TestServerSizeLimit_OverLimitDrainBounded`, `TestServerSizeLimit_LMTP_OverLimitDrainBounded`, `TestServerSizeLimit_LMTP_Fallback_OverLimitDrainBounded` |
| SMTP-EXT-04 | RFC 3461, xtext (RFC 3461 §4) | Normative | One row for the extension: DSN: `RET`, `ENVID`, `NOTIFY` and `ORCPT`, with xtext encoding both ways. The clauses of the RFC are not checked one by one yet. | `TestServerDSN`, `TestClientDSN`, `TestClientXtext`, `TestXtextRoundTrip`, `TestServer_xtextLiteralNonXchar`, `FuzzDecodeXtext`, `FuzzEncodeXtext` |
| SMTP-EXT-05 | RFC 3030 | Normative | One row for the extension: CHUNKING and BINARYMIME: BDAT chunks, reset, errors, size limits and shutdown. The clauses of the RFC are not checked one by one yet. | `TestServer_Chunking`, `TestServer_Chunking_LMTP`, `TestServer_Chunking_Reset`, `TestServer_Chunking_ClosedInTheMiddle`, `TestServer_Chunking_EarlyError`, `TestServer_Chunking_EarlyErrorDuringChunk`, `TestServer_Chunking_tooLongMessage`, `TestServer_Chunking_OverLimitDiscardKeepsConnection`, `TestServer_Chunking_Binarymime`, `TestServer_Chunking_LineLimitAfterNonLastBdat`, `TestBDATShutdownRace`, `TestBdatReadTimeoutClosesConnection` |
| SMTP-EXT-06 | RFC 6531, 6533 | Normative | One row for the extension: SMTPUTF8: the parameter, UTF-8 addresses, `ORCPT` with UTF-8 (xtext and unitext), and the client's detection. The clauses of the RFC are not checked one by one yet. | `TestServerSMTPUTF8`, `TestServerSMTPUTF8_Disabled`, `TestServerDSNUTF8AddressORCPT`, `TestServerDSNwithSMTPUTF8`, `TestSendMail_SMTPUTF8_Autodetect`, `TestSendMail_SMTPUTF8_NotAdvertised`, `TestIsASCII`, `TestUTF8AddrOracleCatchesMutants`, `TestUTF8AddrRFC6533Regressions`, `TestClientORCPTUTF8Encoding`, `FuzzDecodeUTF8AddrXtext`, `FuzzEncodeUTF8AddrXtext`, `FuzzEncodeUTF8AddrUnitext` |
| SMTP-EXT-07 | RFC 3207 | Normative | One row for the extension: STARTTLS: it takes no argument, the 220 is sent before the handshake, a failed handshake closes the connection, and the client keeps the TLS state. The clauses of the RFC are not checked one by one yet. | `TestTLSClient`, `TestTLSConnState`, `TestStartTLSClosesOnHandshakeFailure`, `TestStartTLSCloseRace`, `TestStartTLSReplySentBeforeHandshake`, `TestParseCmdSTARTTLSExact`, `TestAuthTLSRequiredCode`, `TestNewClientStartTLS` |
| SMTP-EXT-08 | RFC 4954 | Normative | One row for the extension: AUTH: mechanisms, initial response, cancellation, a second AUTH, anonymous access, and read timeouts. The clauses of the RFC are not checked one by one yet. | `TestServerAuthTwice`, `TestServerCancelSASL`, `TestServer_authDisabled`, `TestServer_anonymousUserError`, `TestServer_anonymousUserOK`, `TestServer_authParam`, `TestAuthRejectsExtraTokens`, `TestAuthFailed`, `TestClientAuthTrimSpace`, `TestAuthChallengeSentBeforeReadingResponse`, `TestAuthClientCancelReturns501`, `TestAuthContinuationReadTimeoutClosesConnection` |
| SMTP-EXT-09 | RFC 2033 | Normative | One row for the extension: LMTP: `LHLO`, one reply per recipient after the data, and the client side. The clauses of the RFC are not checked one by one yet. | `TestServer_LMTP`, `TestServer_LMTP_Early`, `TestServer_LMTP_Expand`, `TestServer_LMTP_DuplicatedRcpt`, `TestServer_Chunking_LMTP`, `TestLMTP`, `TestLMTPData`, `TestLMTPRcptLeakAcrossTransactions`, `TestLMTPDataErrorMessages` |
| SMTP-EXT-10 | RFC 7293 | Normative | One row for the extension: RRVS: the `RRVS` parameter on RCPT. The clauses of the RFC are not checked one by one yet. | `TestServerRRVS`, `TestClientRRVS` |
| SMTP-EXT-11 | RFC 2852 | Normative | One row for the extension: DELIVERBY: `BY` on MAIL only, in range. The clauses of the RFC are not checked one by one yet. | `TestServerDELIVERBY`, `TestClientDELIVERBY`, `TestClientDeliverByTruncatesToSeconds`, `TestParseDeliverByBoundaries`, `FuzzParseDeliverByArgument`, `TestServerDeliverByAndMTPriorityRejectedOnRcpt` |
| SMTP-EXT-12 | RFC 6710 | Normative | One row for the extension: MT-PRIORITY: the `MT-PRIORITY` parameter on MAIL only, in range. The clauses of the RFC are not checked one by one yet. | `TestServerMTPRIORITY`, `TestClientMTPRIORITY` |
| SMTP-EXT-13 | Postfix XCLIENT (not an IETF RFC) | Normative | One row for the extension: XCLIENT: a trusted peer may set the client's address and name; an untrusted one may not. The clauses of the RFC are not checked one by one yet. | `TestServerXClientTrusted`, `TestServerXClientUntrusted` |
