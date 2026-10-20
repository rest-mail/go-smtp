# SMTP RFC checklist

Every requirement [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321) (SMTP)
places on the parts of go-smtp that this slice covers: the server and client
core, item by item, with the tests that cover it. A section number alone is
RFC 5321. The list takes in the MUSTs and SHOULDs, and the normative behaviour
that carries no keyword (level "Normative"), such as the grammar.

An item that does not apply, or is a known gap, says "n/a" and why. CI checks
this file against the tests with `go run ./internal/checklist`; the format is
described in the [README](README.md#the-rfc-checklist).

Not covered yet: each extension (DSN,
SMTPUTF8, LMTP, RRVS, DELIVERBY, MT-PRIORITY, XCLIENT) is one
row in the extension summary, mapping its existing tests, and has not been checked
clause by clause; later slots do that. STARTTLS (RFC 3207), SIZE (RFC 1870),
PIPELINING (RFC 2920), CHUNKING/BINARYMIME (RFC 3030),
8BITMIME (RFC 6152) and AUTH exchange rules
(RFC 4954 §4) are audited below; the rest of RFC 4954 remains for later slices.
RFC 6409 (submission) is not in this slot. Reply line lengths (§4.5.3.1.5)
are checked by SMTP-LIM-06;
SASL challenges retain the independent size rules of RFC 4954 §4.


## Syntax and lexical rules (§2.3, §2.4, §4.1.2)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SMTP-SYN-01 | 4.1.2 | MUST | The reverse-path is a path or the null path `<>`; `MAIL FROM:<>` is accepted. | `TestServerEmptyFrom2`, `TestParser`, `FuzzParseReversePath` |
| SMTP-SYN-02 | 4.1.2 | MUST | A path is `<`, an optional source route and `:`, a mailbox and `>`; a quoted-string local-part holds no control characters; text that is not a path is a 501. | `TestParser`, `TestParserRejectsControlBytes`, `TestServerEmptyFrom1`, `FuzzParseReversePath`, `FuzzParseForwardPath` |
| SMTP-SYN-03 | 4.1.1.3, 4.5.1 | MUST | `RCPT TO:<Postmaster>` is accepted without a domain, in any letter case; the domain-qualified form keeps its domain. | `TestServerPostmasterRcpt`, `TestParsePostmasterPath`, `FuzzParseForwardPath` |
| SMTP-SYN-04 | 4.1.1.3 | Normative | A forward-path is never null: `RCPT TO:<>` and an empty `RCPT TO:` are refused. | `TestServerEmptyTo`, `FuzzParseForwardPath` |
| SMTP-SYN-05 | 2.4 | MUST | Command verbs and the `FROM:` and `TO:` keywords are case-insensitive and ASCII; a non-ASCII look-alike is not a verb. | `TestRFC5321_CommandsCaseInsensitive`, `TestParseCmdASCII`, `TestParseCmdKeepsUnicodeSpaceInArgument`, `FuzzParseCmd` |
| SMTP-SYN-06 | 4.1.1.1, 4.1.2 | Normative | Parameters are `keyword` or `keyword=value` separated by spaces; a value may itself hold `=`. | `TestParseArgsBoundaries`, `TestParseArgsEqualsInValue`, `TestParseArgsUnicodeSpaceInValue`, `FuzzParseArgs` |
| SMTP-SYN-07 | 4.1.1.2 | Normative | Whitespace separates the path from the parameters: `MAIL FROM:<a@b>SIZE=10` is refused, not read as a parameter. | `TestMailParamRequiresSpace`, `TestMailUnicodeSpaceIsNotSeparator`, `TestRcptUnicodeSpaceIsNotSeparator` |
| SMTP-SYN-08 | 4.1.2 | Normative | A parameter keyword is not repeated within one command: `SIZE=10 SIZE=20` is a 501. | `TestMailParamNoDuplicates` |
| SMTP-SYN-09 | 4.1.1.1 | MUST | `HELO` and `EHLO` without a domain argument are a 501. | `TestRFC5321_UnknownAndArgumentErrors` |
| SMTP-SYN-10 | 4.1.1.4 | MUST | `DATA` with an argument is a 501. | `TestRFC5321_UnknownAndArgumentErrors` |
| SMTP-SYN-11 | 2.3.8 | Normative | Only CRLF ends a line: a bare LF is not a line end, so `LF.LF` does not end the data (SMTP smuggling). | `TestServer_smtpSmuggling`, `TestServer_LFDotLF`, `TestEODNonStandardSequencesDoNotEndData`, `TestEODCRBeforeCRLFDotEndsData`, `TestEODBDATChunksIgnoreDotSequences`, `TestEODClientDotStuffsAndNormalises` |
| SMTP-SYN-12 | 2.2.2 | Normative | A MAIL parameter the server does not know is refused, not ignored. | `TestServerUnknownArg` |
| SMTP-SYN-13 | 2.3.8, 4.1.1 | MUST | A command line ends at CRLF only: a bare LF does not end a command (it is a 500 and the connection is closed, and the text after it is not run), and a bare CR in the middle of a line does not split it into two commands. | `TestEODCommandLineBareLF` |

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
| SMTP-CMD-01 | 4.1.1.1 | MUST | EHLO is answered 250: the first line holds the greeting, each extension is on its own `250-` line, and the last line is `250 `; a backend can add capabilities. | `TestServerExtraCaps`, `TestServerFeatureBackend`, `TestParseHelloArgumentSeparators` |
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
| SMTP-DATA-07 | 4.1.1.4, 2.3.8, 4.5.2 | MUST | The data ends only at `<CRLF>.<CRLF>`: `LF.LF`, `CR.CR`, `LF.CRLF`, `CRLF.LF` and a CR after the leading dot (`CRLF.CR`) are content, never run as commands; a stray CR before the real `<CRLF>.<CRLF>` does not hide it, so the message ends there. | `TestEODNonStandardSequencesDoNotEndData`, `TestEODCRBeforeCRLFDotEndsData` |

## Size limits and timeouts (§4.5.3)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SMTP-LIM-01 | 4.5.3.1.4 | MUST | A command line of 512 octets, CRLF included, is accepted. | `TestRFC5321_CommandLine512` |
| SMTP-LIM-02 | 4.5.3.1.4 | SHOULD | A command line longer than the server supports is answered 500 5.4.0. | `TestServer_TooLongCommand`, `TestServer_tooLongLine` |
| SMTP-LIM-03 | 4.5.3.1.1-3 | MUST | A local-part of 64 octets, a domain of 255 octets and a path of 256 octets are accepted. | `TestRFC5321_MinimumAddressSizes` |
| SMTP-LIM-04 | 4.5.3.1.8 | MUST | At least 100 recipients are accepted in one transaction. | `TestRFC5321_HundredRecipients` |
| SMTP-LIM-05 | 4.5.3.2 | SHOULD | A configured read timeout closes a connection that stops sending, in DATA as well as between commands; the timeout restarts as data arrives. | `TestDataReadTimeoutClosesConnection`, `TestDataBodyReadDeadlineRefresh` |
| SMTP-LIM-06 | 4.5.3.1.5 | MUST | A server reply line is at most 512 octets, code and CRLF included; RFC 4954 SASL challenges have independent size rules. | `TestRFC5321_ReplyLine512`, `TestRFC5321_MultilineReplyLine512`, `TestRFC5321_BackendReplyLine512`, `TestRFC4954_LongChallengeNotTruncated` |

## Replies (§4.2)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SMTP-REP-01 | 4.2 | MUST | The server greets a new connection with a 220 reply. | `TestServer_helo`, `TestServer` |
| SMTP-REP-02 | 3.8, 4.2.2 | MUST | A server that must stop answers 421 before closing: on shutdown, and after an internal error. | `TestServerCloseSends421`, `TestServerPanicRecover`, `TestConnReject` |
| SMTP-REP-03 | 4.2.1 | MUST | The code a backend returns is the reply code, with its text; a plain error is not leaked to the client. | `TestErrorf`, `TestBackendErrorf_StatusNotLeaked`, `TestDataWrappedSMTPError`, `TestMailWrappedSMTPError`, `TestCustomResponse_Mail`, `TestCustomResponse_Rcpt`, `TestCustomResponse_Data`, `TestSMTPErrorTemporary`, `TestRFC5321_BackendReplyLine512` |

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
| SMTP-CLI-04 | 4.5.2 | MUST | The client doubles a leading `.` of each line it sends in DATA and ends the data with a line holding one `.`. | `TestRFC5321_ClientDotStuffing`, `TestEODClientDotStuffsAndNormalises` |
| SMTP-CLI-05 | 4.5.3.1.5 | MUST | A reply line longer than the client supports is an error, not a truncation. | `TestClient_TooLongLine` |
| SMTP-CLI-06 | 4.1.1.5 | MUST | A new MAIL starts with no recipients from the one before, and RSET clears them. | `TestClientMailClearsRcpts`, `TestPipelinerMailClearsRcpts`, `TestPipeline_Reset` |
| SMTP-CLI-07 | 2.2.2 | MUST | The client does not send a MAIL parameter the server did not advertise, or one out of range. | `TestClientMailParamsUnadvertised`, `TestClientMailParamsOutOfRange` |
| SMTP-CLI-08 | n/a | Normative | The client can tell whether a connection it kept is still healthy before it reuses it. | `TestCheckConn_HealthyPlaintext`, `TestCheckConn_ServerClosedPlaintext`, `TestCheckConn_UnsolicitedData`, `TestCheckConn_BufferedData`, `TestCheckConn_TLS` |

## Extensions (one row each; clause-by-clause checks come in later slots)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SMTP-EXT-01 | RFC 2920 | Normative | PIPELINING regression summary; the clause-by-clause RFC 2920 audit below records its fixed-window client limitation. | `TestPipeline_NoRoundTripDeadlock`, `TestPipeline_Integration`, `TestPipeline_NotSupported`, `TestPipeline_LargeGroupDoesNotDeadlock`, `TestPipeline_LMTPSeesOnlyAcceptedRecipients`, `TestPipeline_StalledServerTimesOut`, `TestPipeline_ServerHangupMidGroup`, `TestPipelinedRepliesShareOneWrite`, `TestSingleCommandReplyIsPrompt`, `TestPartialPipelinedLineDoesNotHoldReplies` |
| SMTP-EXT-02 | RFC 6152 | Normative | 8BITMIME summary: `BODY=8BITMIME` and `7BIT` are accepted, other values are refused without BINARYMIME. Clause-by-clause transport checks and host responsibilities are below. | `TestServer8BITMIME`, `TestServer_BODYInvalidValue` |
| SMTP-EXT-03 | RFC 1870 | Normative | SIZE summary: declared and actual sizes are checked against `MaxMessageBytes` (inclusive); oversized content is drained with a bound. The RFC 1870 audit is below. | `TestServerBadSize`, `TestServerTooBig`, `TestServerSizeLimit_ExactlyMaxAccepted`, `TestServerSizeLimit_OverMaxRejected`, `TestServerSizeLimit_RejectWithinLimitKeepsConnection`, `TestServerSizeLimit_OversizedKeepsConnection`, `TestServerSizeLimit_OverLimitDrainBounded`, `TestServerSizeLimit_LMTP_OverLimitDrainBounded`, `TestServerSizeLimit_LMTP_Fallback_OverLimitDrainBounded` |
| SMTP-EXT-04 | RFC 3461, xtext (RFC 3461 §4) | Normative | One row for the extension: DSN: `RET`, `ENVID`, `NOTIFY` and `ORCPT`, with xtext encoding both ways. The clauses of the RFC are not checked one by one yet. | `TestServerDSN`, `TestClientDSN`, `TestClientXtext`, `TestXtextRoundTrip`, `TestServer_xtextLiteralNonXchar`, `FuzzDecodeXtext`, `FuzzEncodeXtext` |
| SMTP-EXT-05 | RFC 3030 | Normative | CHUNKING and BINARYMIME summary: existing BDAT, reset, errors, size and shutdown regressions. RFC 3030 transport clauses and explicit scope limits are audited below. | `TestServer_Chunking`, `TestServer_Chunking_LMTP`, `TestServer_Chunking_Reset`, `TestServer_Chunking_ClosedInTheMiddle`, `TestServer_Chunking_EarlyError`, `TestServer_Chunking_EarlyErrorDuringChunk`, `TestServer_Chunking_tooLongMessage`, `TestServer_Chunking_OverLimitDiscardKeepsConnection`, `TestServer_Chunking_Binarymime`, `TestServer_Chunking_LineLimitAfterNonLastBdat`, `TestBDATShutdownRace`, `TestBdatReadTimeoutClosesConnection`, `TestEODBDATChunksIgnoreDotSequences`, `TestServerBdatUnicodeSpaceIsNotSeparator` |
| SMTP-EXT-06 | RFC 6531, 6533 | Normative | One row for the extension: SMTPUTF8: the parameter, UTF-8 addresses, `ORCPT` with UTF-8 (xtext and unitext), and the client's detection. The clauses of the RFC are not checked one by one yet. | `TestServerSMTPUTF8`, `TestServerSMTPUTF8_Disabled`, `TestServerDSNUTF8AddressORCPT`, `TestServerDSNwithSMTPUTF8`, `TestSendMail_SMTPUTF8_Autodetect`, `TestSendMail_SMTPUTF8_NotAdvertised`, `TestIsASCII`, `TestUTF8AddrOracleCatchesMutants`, `TestUTF8AddrRFC6533Regressions`, `TestClientORCPTUTF8Encoding`, `FuzzDecodeUTF8AddrXtext`, `FuzzEncodeUTF8AddrXtext`, `FuzzEncodeUTF8AddrUnitext` |
| SMTP-EXT-07 | RFC 3207 | Normative | STARTTLS summary: parser, handshake, TLS state, close races and AUTH protection. The clause-by-clause audit is below. | `TestTLSClient`, `TestTLSConnState`, `TestStartTLSClosesOnHandshakeFailure`, `TestStartTLSCloseRace`, `TestStartTLSReplySentBeforeHandshake`, `TestParseCmdSTARTTLSExact`, `TestAuthTLSRequiredCode`, `TestNewClientStartTLS` |
| SMTP-EXT-08 | RFC 4954 | Normative | One row for the extension: AUTH: mechanisms, initial response, cancellation, a second AUTH, anonymous access, and read timeouts. The exchange rules have individual rows below; other clauses remain unaudited. | `TestServerAuthTwice`, `TestServerCancelSASL`, `TestServer_authDisabled`, `TestServer_anonymousUserError`, `TestServer_anonymousUserOK`, `TestServer_authParam`, `TestAuthRejectsExtraTokens`, `TestAuthFailed`, `TestClientAuthTrimSpace`, `TestAuthChallengeSentBeforeReadingResponse`, `TestAuthClientCancelReturns501`, `TestAuthContinuationReadTimeoutClosesConnection`, `TestServerAuthUnicodeSpaceIsNotSeparator`, `TestRFC4954_LongChallengeNotTruncated` |
| SMTP-EXT-09 | RFC 2033 | Normative | One row for the extension: LMTP: `LHLO`, one reply per recipient after the data, and the client side. The clauses of the RFC are not checked one by one yet. | `TestServer_LMTP`, `TestServer_LMTP_Early`, `TestServer_LMTP_Expand`, `TestServer_LMTP_DuplicatedRcpt`, `TestServer_Chunking_LMTP`, `TestLMTP`, `TestLMTPData`, `TestLMTPRcptLeakAcrossTransactions`, `TestLMTPDataErrorMessages` |
| SMTP-EXT-10 | RFC 7293 | Normative | One row for the extension: RRVS: the `RRVS` parameter on RCPT. The clauses of the RFC are not checked one by one yet. | `TestServerRRVS`, `TestClientRRVS` |
| SMTP-EXT-11 | RFC 2852 | Normative | One row for the extension: DELIVERBY: `BY` on MAIL only, in range. The clauses of the RFC are not checked one by one yet. | `TestServerDELIVERBY`, `TestClientDELIVERBY`, `TestClientDeliverByTruncatesToSeconds`, `TestParseDeliverByBoundaries`, `FuzzParseDeliverByArgument`, `TestServerDeliverByAndMTPriorityRejectedOnRcpt` |
| SMTP-EXT-12 | RFC 6710 | Normative | One row for the extension: MT-PRIORITY: the `MT-PRIORITY` parameter on MAIL only, in range. The clauses of the RFC are not checked one by one yet. | `TestServerMTPRIORITY`, `TestClientMTPRIORITY` |
| SMTP-EXT-13 | Postfix XCLIENT (not an IETF RFC) | Normative | One row for the extension: XCLIENT: a trusted peer may set the client's address and name; an untrusted one may not. The clauses of the RFC are not checked one by one yet. | `TestServerXClientTrusted`, `TestServerXClientUntrusted`, `TestServerXClientKeepsUnicodeSpaceInValue` |


## AUTH exchange (RFC 4954 §3, §4 and §8)

This slice checks command framing and the SASL challenge/response exchange,
including the PLAIN and empty EXTERNAL wire examples of §4.1. It does **not**
claim a complete RFC 4954 audit. The §5 MAIL AUTH trust/relay rules, §6 policy,
§7 trace headers and §14 TLS identity requirements remain unaudited. Existing
MAIL AUTH tests remain in SMTP-EXT-08. The host supplies the actual SASL
mechanisms and credential/identity policy through AuthSession.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SMTP-AUTH-01 | RFC 4954 §3 | Normative | EHLO advertises AUTH followed by the available mechanisms separated by spaces. | `TestRFC4954_Examples` |
| SMTP-AUTH-02 | RFC 4954 §4 | MUST | A successful AUTH prevents another AUTH in the session, including after RSET, with reply 503. | `TestRFC4954_Examples` |
| SMTP-AUTH-03 | RFC 4954 §4, §4.1 | Normative | The PLAIN example authenticates with an initial Base64 response or after an empty 334 challenge. | `TestRFC4954_Examples` |
| SMTP-AUTH-04 | RFC 4954 §4, §6 | Normative | Successful authentication returns 235 2.7.0. | `TestRFC4954_Examples` |
| SMTP-AUTH-05 | RFC 4954 §8 | MUST | AUTH and SASL mechanism names are case-insensitive. | `TestRFC4954_Examples` |
| SMTP-AUTH-06 | RFC 4954 §4, §8 | Normative | AUTH requires a mechanism argument; missing arguments receive a syntax error. | `TestRFC4954_ServerFailuresAndRetry` |
| SMTP-AUTH-07 | RFC 4954 §4 | SHOULD | Unsupported mechanisms receive 504 with enhanced status 5.5.4. | `TestRFC4954_ServerFailuresAndRetry` |
| SMTP-AUTH-08 | RFC 4954 §4 | MUST | Server Base64 decoding rejects non-alphabet bytes and misplaced padding in initial responses and continuations. | `TestRFC4954_ServerFailuresAndRetry`, `FuzzDecodeSASLResponse` |
| SMTP-AUTH-09 | RFC 4954 §4 | MUST | Malformed Base64 responses receive 501 with enhanced status 5.5.2. | `TestRFC4954_ServerFailuresAndRetry` |
| SMTP-AUTH-10 | RFC 4954 §4, §6 | SHOULD | Invalid credentials reported by the host as ErrAuthFailed produce 535 5.7.8; a failed AUTH permits retry. | `TestRFC4954_ServerFailuresAndRetry` |
| SMTP-AUTH-11 | RFC 4954 §4, §4.1 | MUST | An equals sign denotes a present, zero-length initial response; the EXTERNAL example succeeds without a challenge. | `TestRFC4954_EmptyInitialResponse`, `TestRFC4954_ClientInitialResponseLimit` |
| SMTP-AUTH-12 | RFC 4954 §4 | MUST NOT | The client omits an initial response that would make AUTH exceed 512 octets, then sends it after the empty challenge. | `TestRFC4954_ClientInitialResponseLimit` |
| SMTP-AUTH-13 | RFC 4954 §4 | MUST | A client cancels with an asterisk if a challenge is not valid Base64, including non-alphabet bytes and misplaced padding. | `TestRFC4954_ClientCancelAndFailure` |
| SMTP-AUTH-14 | RFC 4954 §4 | Normative | Cancellation is sent during a challenge; a terminal AUTH failure ends the exchange without another SASL response. | `TestRFC4954_ClientCancelAndFailure` |
| SMTP-AUTH-15 | RFC 4954 §4, §6 | SHOULD | A continuation exceeding the configured authentication buffer receives 500 5.5.6; the connection closes to preserve framing. | `TestRFC4954_ContinuationTooLong` |
| SMTP-AUTH-16 | RFC 4954 §4 | MUST | AUTH during a mail transaction receives 503. | `TestServerBadSequence` |
| SMTP-AUTH-17 | RFC 4954 §4 | MUST | A client asterisk cancels the exchange and receives 501. | `TestAuthClientCancelReturns501`, `TestRFC4954_ChallengeAndCancel` |
| SMTP-AUTH-18 | RFC 4954 §4 | MUST NOT | A 334 challenge contains only Base64, with a trailing space and no text for an empty challenge, and is flushed before reading the response. | `TestAuthChallengeSentBeforeReadingResponse`, `TestRFC4954_ChallengeAndCancel` |
| SMTP-AUTH-19 | RFC 4954 §4, §6 | MUST | A configuration prevents plaintext password mechanisms on unprotected sessions and does not advertise them. | `TestAuthTLSRequiredCode`, `TestRFC4954_NoPlaintextAdvertisement` |
| SMTP-AUTH-20 | RFC 4954 §4 | MUST | A mechanism where the server speaks first refuses a client initial response with 501 (5.7.0 recommended). | n/a: delegated to the host's sasl.Server.Next; AuthSession exposes no server-first metadata, so the transport cannot enforce it independently. |
| SMTP-AUTH-21 | RFC 4954 §4 | MUST | SASL security layers reset SMTP knowledge on both sides and TLS wraps SASL when both layers are active. | n/a: not supported; the go-sasl interface supplies authentication exchanges only, without a connection security-layer adapter. |
| SMTP-AUTH-22 | RFC 4954 §4 | MUST | Supported mechanism challenge/response sizes are accepted independently of SMTP command line limits. | n/a: known gap; server continuations still share MaxLineLength (default 2000), and client challenges share its reply limit. A separate bounded SASL buffer is needed. |
| SMTP-AUTH-23 | RFC 4954 §4 | SHOULD | Authorization identities use SASLprep; failed preparation or an unexpectedly empty prepared identity must fail authentication. | n/a: host responsibility; the transport receives opaque SASL bytes and no authorization identity. Hosts must implement preparation and return a SASL error on failure. |
| SMTP-AUTH-24 | RFC 4954 §4 | MUST | PLAIN over TLS is available for interoperability. | n/a: host responsibility; applications must install a PLAIN AuthSession and a TLS configuration, and clients must supply a PLAIN sasl.Client. This exchange slice tests framing separately from TLS, not a complete PLAIN/TLS deployment. |
| SMTP-AUTH-25 | RFC 4954 §4 | MUST | AUTH is last in a pipelined group except for eligible one-round-trip mechanisms with an initial response. | n/a: client Auth is synchronous, outside the Pipeliner API; the raw server cannot distinguish a group boundary from buffered continuation bytes. Host-provided mechanisms must not negotiate unsupported security layers. |


## STARTTLS (RFC 3207)

Sections in this table refer to [RFC 3207](https://www.rfc-editor.org/rfc/rfc3207).
The §5 example is exercised as a real plaintext EHLO / STARTTLS / TLS handshake /
encrypted EHLO exchange, with capabilities checked before and after. TLS uses
Go's `crypto/tls`; these tests prove the SMTP integration, not the TLS protocol.
Policy rows distinguish host responsibilities and unsupported modes from tested
library behaviour. In particular, enabling STARTTLS does not enforce TLS on all
commands; a host's relay and submission policy remains outside this library.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| TLS-SYNTAX-01 | 2, 3 | Normative | The EHLO keyword is STARTTLS with no parameters when TLS is available. | `TestRFC3207ServerDiscardsKnowledge` |
| TLS-SYNTAX-02 | 4 | Normative | STARTTLS takes no parameters; parameters receive 501 and do not start a handshake. | `TestRFC3207RejectsParameters` |
| TLS-REPLY-01 | 4 | Normative | Send 220 before beginning the TLS negotiation. | `TestStartTLSReplySentBeforeHandshake` |
| TLS-REPLY-02 | 4 | Normative | A client receiving 454 applies its local policy; TLS-required constructors return that error and close rather than send plaintext mail. | `TestRFC3207ClientTemporaryRefusal` |
| TLS-REPLY-03 | 4 | Normative | Temporary server TLS unavailability is answered 454. | n/a: no temporary-unavailability mode; a nil TLSConfig means permanently unsupported (502), while configured TLS attempts the handshake. |
| TLS-POLICY-01 | 4 | MUST NOT | A publicly referenced SMTP server must not require STARTTLS for local delivery; configuring TLS alone permits a plaintext transaction. | `TestRFC3207PlaintextDelivery` |
| TLS-POLICY-02 | 4 | SHOULD | A private server requiring TLS answers commands other than NOOP, EHLO, STARTTLS and QUIT with 530 (enhanced 5.7.0). | n/a: no library-wide require-TLS mode; AllowInsecureAuth=false protects AUTH only. Host submission policy is separate; see TLS-POLICY-03. |
| TLS-POLICY-03 | 4 | SHOULD | AUTH protected by the host's TLS policy receives 530 with enhanced status 5.7.0 before TLS. | `TestAuthTLSRequiredCode` |
| TLS-CLIENT-01 | 4 | MUST | After 220, negotiate TLS before any further SMTP commands; report success only after the handshake and certificate verification complete. | `TestRFC3207ClientUpgrade`, `TestRFC3207ClientHandshakeFailure`, `TestRFC3207ClientHandshakeTimeout`, `TestRFC3207ConstructorsVerifyHandshake` |
| TLS-CLIENT-02 | 4.2 | MUST NOT | The client does not attempt STARTTLS while TLS is already active. | `TestRFC3207ClientUpgrade` |
| TLS-CLIENT-03 | 4 | SHOULD | Abort the connection when a failure prevents a usable TLS handshake; do not resume plaintext SMTP. | `TestRFC3207ClientHandshakeFailure`, `TestRFC3207ClientHandshakeTimeout`, `TestRFC3207ConstructorsVerifyHandshake` |
| TLS-PIPE-01 | 4 | Normative | STARTTLS is the last command in a pipelined group. | n/a: the client pipeline API has no STARTTLS operation; startTLS sends a standalone command. TestStartTLSReplySentBeforeHandshake covers the server accepting STARTTLS last in a group. |
| TLS-POLICY-04 | 4.1, 6 | MUST | Both peers immediately decide whether the achieved authentication and privacy permit continuing. | n/a: host policy through tls.Config (verification, client certificates, protocol and cipher restrictions) and TLSConnectionState; no universal trust policy is imposed by SMTP. Handshake rejection is tested by TLS-CLIENT-03. |
| TLS-POLICY-05 | 4.1 | SHOULD | A client rejecting an otherwise completed TLS negotiation immediately sends QUIT. | n/a: host policy; the client exposes TLSConnectionState and Quit. Failed TLS negotiation closes the socket instead (TLS-CLIENT-03). |
| TLS-POLICY-06 | 4.1 | SHOULD | A server rejecting an otherwise completed TLS negotiation answers commands other than QUIT with 554. | n/a: not supported yet as a library-wide state; TLSConfig can reject the handshake, and a host backend can reject the subsequent session. |
| TLS-STATE-01 | 4.2, 6 | MUST | The server resets SMTP state and discards pre-TLS EHLO, authentication, backend session and XCLIENT assertions. | `TestRFC3207ServerDiscardsKnowledge` |
| TLS-STATE-02 | 4.2, 6 | MUST | The client discards the pre-TLS service extension list and transaction recipients. | `TestRFC3207ClientUpgrade` |
| TLS-STATE-03 | 4.2 | SHOULD | The client's first SMTP command after a successful negotiation is a fresh EHLO. | `TestRFC3207ClientUpgrade` |
| TLS-STATE-04 | 4.2 | MUST | Both peers know whether TLS is active and expose the completed negotiation state. | `TestRFC3207ClientUpgrade`, `TestRFC3207ServerDiscardsKnowledge` |
| TLS-STATE-05 | 4.2 | MUST NOT | The server does not advertise STARTTLS after the TLS handshake. | `TestRFC3207ServerDiscardsKnowledge` |
| TLS-SERVER-01 | 4.1, 6 | Normative | A failed server-side TLS handshake ends the connection, preventing further SMTP on a half-upgraded stream. | `TestStartTLSClosesOnHandshakeFailure` |
| TLS-EXAMPLE-01 | 5 | Normative | The usage example's EHLO, STARTTLS, handshake and encrypted EHLO sequence changes the advertised capabilities. | `TestRFC3207ClientUpgrade`, `TestRFC3207ServerDiscardsKnowledge` |
| TLS-SEC-01 | 6 | MUST | Selected hosts can require successful TLS negotiation meeting the configured cipher and authentication policy before message transfer. | n/a: client TLS-required constructors enforce negotiation using tls.Config; server per-host enforcement is host backend policy, not a built-in library-wide gate (TLS-POLICY-02). |
| TLS-SEC-02 | 6 | SHOULD | Opportunistic TLS is also available as a local policy. | n/a: host transport choice; select DialStartTLS or Dial before transferring mail, with retry and downgrade policy outside the library. |

## 8BITMIME (RFC 6152)

Sections here refer to [RFC 6152](https://www.rfc-editor.org/rfc/rfc6152).
The section 4 dialogue uses its envelope addresses and command sequence, with
RFC 5321's 221 QUIT response in place of the example's 250. Tests prove the
transport boundary, not MIME validation or the backend's eventual delivery.
Explicit client body options are checked; the automatic/default API still
requires the caller to supply content suitable for the negotiated transport.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| MIME-SYNTAX-01 | 2 | Normative | EHLO advertises 8BITMIME without arguments. | `TestRFC6152ServerExample` |
| MIME-SYNTAX-02 | 2, 3 | Normative | BODY accepts 7BIT or 8BITMIME, case-insensitively. | `TestRFC6152ServerExample`, `TestRFC6152ServerBodyGrammar`, `TestRFC6152ClientBodyOptions` |
| MIME-SYNTAX-03 | 3 | Normative | A MAIL command contains at most one BODY parameter. | `TestRFC6152ServerExample`, `TestRFC6152ServerBodyGrammar` |
| MIME-SYNTAX-04 | 2, 3 | Normative | BODY is optional for ordinary 7-bit mail. | `TestRFC6152ServerExample` |
| MIME-DATA-01 | 3 | SHALL | DATA retains high-bit octets. | `TestRFC6152ServerExample`, `TestRFC6152ClientPreservesOctets`, `FuzzRFC6152DataOctets` |
| MIME-DATA-02 | 3 | Normative | Dot transparency still applies. | `TestRFC6152ServerExample`, `TestRFC6152ClientPreservesOctets`, `FuzzRFC6152DataOctets` |
| MIME-DATA-03 | 3 | Normative | The final content CRLF belongs to the message. | `TestRFC6152ServerExample`, `TestRFC6152ClientPreservesOctets`, `FuzzRFC6152DataOctets` |
| MIME-DATA-04 | 1, 3 | Normative | DATA permits lines of at least 1000 octets including CRLF. | `TestRFC6152ServerExample` |
| MIME-CLIENT-01 | 3 | Normative | The client negotiates before using BODY=8BITMIME. | `TestRFC6152ClientBodyOptions`, `TestRFC6152ClientPreservesOctets` |
| MIME-CLIENT-02 | 3 | MUST NOT | An explicit 8-bit request fails when the peer lacks support. | `TestRFC6152ClientBodyOptions` |
| MIME-CLIENT-03 | 1, 3 | Normative | 8BITMIME does not authorize BINARYMIME transport. | `TestRFC6152ClientBodyOptions`, `TestRFC6152ServerBodyGrammar` |
| MIME-POLICY-01 | 3 | MUST NOT | Send no high-bit content without negotiated support. | n/a: gap: default Mail/SendMail and Data do not inspect content; callers must ensure 7-bit content for an unextended peer. Explicit Body8BitMIME is protected by MIME-CLIENT-02. |
| MIME-RELAY-01 | 3 | MUST | Accepted 8-bit mail retains its octets through delivery. | n/a: backend storage/delivery responsibility; tests prove bytes presented to Session.Data only. |
| MIME-RELAY-02 | 3 | Normative | A relay facing an unextended next hop converts or fails delivery. | n/a: host routing, retry and delivery-failure policy; no MIME converter or queue is supplied. |
| MIME-RELAY-03 | 3 | MUST | Conversion loses no information. | n/a: no MIME conversion implementation; responsibility of a host choosing conversion. |
| MIME-RELAY-04 | 3 | MUST | Converted mail is valid 7-bit MIME. | n/a: no MIME conversion implementation; responsibility of a host choosing conversion. |
| MIME-EXAMPLE-01 | 4 | Normative | The example's extended mail transaction succeeds. | `TestRFC6152ServerExample` |

## Message size declaration (RFC 1870)

Sections below refer to [RFC 1870](https://www.rfc-editor.org/rfc/rfc1870).
This is the minimal server model of §7: the library enforces its fixed limit,
while a backend owns storage availability and recipient policy. An unlimited
server advertises `SIZE 0`, rather than the bare keyword whose §7 semantics
require a resource check. Values beyond the signed 64-bit API range receive
552 even when no administrator limit is configured. The client exposes SIZE
and SMTP errors; queueing, notifications and retry policy belong to its host.
The §8 example is a protocol test with backend-supplied recipient failures.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SIZE-EHLO-01 | 3, 4 | Normative | Advertise SIZE and the fixed inclusive maximum as a decimal octet count. | `TestRFC1870Advertisement` |
| SIZE-EHLO-02 | 3, 7 | Normative | SIZE 0 means no configured fixed maximum; a bare SIZE does not convey a maximum. | `TestRFC1870Advertisement` |
| SIZE-EHLO-03 | 3, 7 | Normative | The client distinguishes a numeric maximum (including unlimited zero) from an absent or unusable maximum; only ASCII decimal digits are valid. | `TestRFC1870ClientLimits`, `FuzzRFC1870SizeValues` |
| SIZE-MAIL-01 | 3, 6 | Normative | A SIZE value is 1–20 ASCII decimal digits, with no sign; leading zeroes are valid. | `TestRFC1870Declarations` |
| SIZE-MAIL-02 | 6 | Normative | A MAIL command has at most one SIZE parameter. | `TestRFC1870Declarations` |
| SIZE-MAIL-03 | 3, 6 | Normative | Pass the declared octet estimate to the backend without a 32-bit cap; values outside the implementation's int64 range are refused as too large. | `TestRFC1870Declarations` |
| SIZE-LINE-01 | 3 | Normative | SIZE extends the base MAIL command line allowance by 26 octets (538 total under the default server limit). | `TestRFC1870ExtendedMailLine` |
| SIZE-CLIENT-01 | 4, 6 | Normative | Send a SIZE declaration only when the extension was advertised, using a non-negative decimal estimate. | `TestRFC1870ClientDeclarations` |
| SIZE-CLIENT-02 | 7 | MAY | A minimal client may omit SIZE even when advertised; zero in MailOptions selects omission. | `TestRFC1870ClientDeclarations` |
| SIZE-DATA-01 | 5, 6 | Normative | Actual size counts headers, body and CRLF, excluding transparency dots and the DATA terminator. | `TestRFC1870DataOctets` |
| SIZE-DATA-02 | 6 | MUST NOT | Never use the declared SIZE to delimit DATA. | `TestRFC1870DataOctets` |
| SIZE-DATA-03 | 6.1, 6.3 | MAY | An underestimate may be accepted if the actual message still fits the server's fixed maximum. | `TestRFC1870DataOctets` |
| SIZE-REPLY-01 | 4, 6.1, 7 | Normative | Refuse a declaration above the fixed maximum with 552 before DATA; equality is accepted. | `TestRFC1870Declarations` |
| SIZE-REPLY-02 | 6.4 | MAY | A backend may refuse individual recipients with temporary 452 or permanent 552 without discarding other accepted recipients. | `TestRFC1870Example` |
| SIZE-REPLY-03 | 6.1 | MAY | Temporary storage shortage may be refused with 452 at MAIL time. | n/a: backend storage policy; Session.Mail can return SMTPError 452. The library has no storage allocator. |
| SIZE-REPLY-04 | 6.3 | SHOULD NOT | After accepting an estimate, do not issue a size-based 552 for content no larger than that estimate. | `TestRFC1870DataOctets` |
| SIZE-CLIENT-03 | 6.2, 6.4 | Normative | Preserve temporary and permanent errors from MAIL, RCPT, DATA and the final content response for host policy. | `TestRFC1870ClientFailures` |
| SIZE-POLICY-01 | 6.2 | SHOULD | After MAIL 452, reset or quit and retry later. | n/a: host queue and retry policy; the client returns SMTPError and exposes Reset/Quit. |
| SIZE-POLICY-02 | 6.2 | SHOULD | After MAIL 552, reset or quit and notify the sender of permanent failure. | n/a: host notification policy; no queue or delivery notification generator in this library. |
| SIZE-POLICY-03 | 6.4 | Normative | Recipient 452 may be retried; recipient 552 must not be requeued for that recipient. | n/a: host queue policy; the API returns each RCPT error to its caller. |
| SIZE-POLICY-04 | 7 | Normative | Before accepting a declaration with bare SIZE, check resources and if possible reserve storage. | n/a: server advertises SIZE 0 or a numeric fixed limit, never bare SIZE; actual storage reservations belong to the backend. |
| SIZE-EXAMPLE-01 | 8 | Normative | The example's 500000-octet estimate, successful recipient, permanent/temporary recipient refusals and successful DATA exchange are exercised. | `TestRFC1870Example` |

The size-counting tests also verify the §6.3 recommendation through the fixed
limit path. A backend can still choose its own status code, including 552;
it must apply that recommendation when rejecting for storage/size reasons.


## PIPELINING (RFC 2920)

Sections in this table are RFC 2920. The server and the three-command client
pipeline are audited separately. An n/a gap below is not a conformance claim.
The client API deliberately sends DATA synchronously after `Wait`; callers must
check every result, and if every RCPT failed but DATA is accepted, close the
unwritten data writer, check its result and reset the transaction. The library
does not automatically choose that recovery or the host's retry policy.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| PIPE-EHLO-01 | 2, 3 | Normative | Advertise PIPELINING as a parameterless EHLO keyword; no new verbs or MAIL/RCPT parameters are introduced. | `TestRFC2920Examples` |
| PIPE-EHLO-02 | 3 | Normative | Confirm successful EHLO and the PIPELINING keyword before using the extension. | `TestPipeline_NotSupported` |
| PIPE-CLIENT-01 | 3, 3.1 | Normative | The client sends a pipelined group only after discovering server support. | `TestPipeline_NotSupported`, `TestRFC2920ClientResponseCorrelation` |
| PIPE-CLIENT-02 | 3.1 | MUST | Check every command status, including statuses after an earlier rejection. | `TestPipeline_NoRoundTripDeadlock`, `TestRFC2920ClientResponseCorrelation` |
| PIPE-CLIENT-03 | 3.1 | MUST | Correlate statuses by command/response count, never by code value or response text, and support multiline responses. | `TestRFC2920ClientResponseCorrelation` |
| PIPE-CLIENT-04 | 3.1 | MUST NOT | Do not confuse a multiline response with responses to multiple commands. | `TestRFC2920ClientResponseCorrelation` |
| PIPE-CLIENT-05 | 3.1 | Normative | Check DATA even when every RCPT failed; if DATA is accepted, recovery sends only a dot and checks the final response. | `TestRFC2920EmptyDataRecovery`, `TestRFC2920EmptyDataWriter` |
| PIPE-CLIENT-06 | 3.1 | Normative | Only permitted commands occur inside a group; EHLO, DATA, VRFY, EXPN, TURN, QUIT and NOOP end a group. | `TestPipeline_Integration` |
| PIPE-CLIENT-07 | 3.1 | MUST | A blocking client checks the actual TCP window and keeps each group within it, or processes replies while writing. | n/a: not supported yet; Pipeliner assumes a fixed 4096-byte window, does not discover the actual window and does not read concurrently. Existing congestion tests prove only that configured window, not arbitrary transports or oversized single commands. Tracked by rest-mail/rest-mail-server#374. |
| PIPE-CLIENT-08 | 3.1 | Normative | Additional extension commands end a group unless their defining extension allows otherwise. | n/a: the client pipeline API exposes only RSET, MAIL and RCPT. Other commands use synchronous Client methods after Wait; extensions without client methods cannot be queued. |
| PIPE-SERVER-01 | 3.2(1) | MUST | Respond to commands in received order. | `TestRFC2920SynchronizationFlush`, `TestRFC2920Examples`, `TestPipelinedRepliesShareOneWrite` |
| PIPE-SERVER-02 | 3.2(2) | SHOULD | Buffer responses to grouped transaction commands for transmission together. | `TestPipelinedRepliesShareOneWrite` |
| PIPE-SERVER-03 | 3.2(3) | SHOULD | Accept DATA if and only if at least one RCPT was accepted, even when the last RCPT failed. | `TestRFC2920Examples` |
| PIPE-SERVER-04 | 3.2(4) | MUST NOT | Deliver nothing if an empty DATA transaction has no valid recipients. | `TestRFC2920Examples` |
| PIPE-SERVER-05 | 3.2(5) | MUST NOT | Do not buffer responses to EHLO, DATA, VRFY, EXPN, TURN, QUIT or NOOP behind later commands. | `TestRFC2920SynchronizationFlush`, `TestDataReplySentBeforeBody`, `TestQuitReplySentBeforeClose` |
| PIPE-SERVER-06 | 3.2(6) | MUST NOT | Do not buffer responses to unrecognized commands. | `TestRFC2920SynchronizationFlush` |
| PIPE-SERVER-07 | 3.2(7) | MUST | Send pending replies when local input is exhausted; a partial next line must not hold replies. | `TestSingleCommandReplyIsPrompt`, `TestPartialPipelinedLineDoesNotHoldReplies` |
| PIPE-SERVER-08 | 3.2(8) | MUST NOT | Do not assume future commands will arrive before responding to received commands. | `TestRFC2920Examples`, `TestSingleCommandReplyIsPrompt` |
| PIPE-SERVER-09 | 3.2(9) | MUST NOT | Do not discard buffered input when a command fails; preserve later commands and body bytes. | `TestRFC2920SynchronizationFlush`, `TestRFC2920Examples` |
| PIPE-SERVER-10 | 3.2(10) | SHOULD | Default response text identifies its command implicitly or explicitly. | `TestRFC2920ReplyText` |
| PIPE-POLICY-01 | 3.2(10) | SHOULD | Custom backend reply text should identify the command it answers. | n/a: host responsibility; custom SMTPError diagnostics are supplied by backend code and cannot be semantically classified by the library. |
| PIPE-EXAMPLE-01 | 4 | Normative | Exercise the RFC's successful multi-recipient and all-recipients-refused dialogues, including content followed by QUIT in one group. | `TestRFC2920Examples` |

The all-recipients-refused example uses RFC 5321's 503 sequencing response in
place of RFC 2920's illustrative 554. The server always refuses DATA without
recipients, so the conditional path of §3.2(4) cannot reach backend delivery.
`TestRFC2920EmptyDataRecovery` separately exercises the client against a peer
that incorrectly accepts that DATA command. SEND/SOML/SAML, EXPN and TURN are
not implemented; their refusal remains explicit (SMTP-CMD-07).


## CHUNKING and BINARYMIME transport (RFC 3030)

Sections below refer to RFC 3030. The server implements BDAT; the client has no
BDAT sender. These rows audit transport, not a host's MIME processing or relay
and notification lifecycle. Protocol tests supply synthetic binary octets;
validating the enclosed MIME object remains the caller's responsibility.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| CHUNK-EHLO-01 | 2 | Normative | Advertise parameterless CHUNKING and continue supporting DATA for suitable content. | `TestRFC3030Examples` |
| CHUNK-EHLO-02 | 3 | Normative | Advertise parameterless BINARYMIME only when enabled, together with CHUNKING. | `TestRFC3030Examples` |
| CHUNK-SYNTAX-01 | 2 | Normative | BDAT has a decimal octet count and at most one optional LAST argument; signs, nondecimal counts and extra arguments are rejected. SP/HTAB are accepted separators. | `TestRFC3030Arguments`, `FuzzRFC3030Arguments` |
| CHUNK-SYNTAX-02 | 2 | Normative | LAST is ASCII and case-insensitive; Unicode look-alikes are not valid markers. | `TestRFC3030Arguments`, `FuzzRFC3030Arguments` |
| CHUNK-DATA-01 | 2 | MUST | Consume the declared octets immediately after the command and acknowledge each successful chunk with 250. | `TestRFC3030Examples` |
| CHUNK-DATA-02 | 2, 3 | Normative | Chunk framing counts octets, without dot transparency, line-ending conversion or command-line length restrictions on body bytes. | `TestRFC3030Examples`, `TestRFC3030ReadAheadLimits` |
| CHUNK-DATA-03 | 2 | Normative | LAST completes one delivery; a zero-length LAST is valid and earlier chunks do not trigger delivery. | `TestRFC3030Examples`, `TestRFC3030NonLastDoesNotDeliver` |
| CHUNK-DATA-04 | 2 | MUST | Commands between/after chunks remain subject to command line limits, even if a valid body shares the same read buffer. | `TestRFC3030ReadAheadLimits` |
| CHUNK-STATE-01 | 2 | MUST | BDAT following LAST without a new envelope gets 503 and its payload is consumed as data. | `TestRFC3030RejectedChunksAreOpaque` |
| CHUNK-STATE-02 | 2 | MUST | DATA during an unfinished BDAT transaction gets 503; DATA and BDAT may be used in different transactions of the same session. | `TestRFC3030BinaryAndResetRules`, `TestRFC3030Examples` |
| CHUNK-STATE-03 | 2 | MUST | RSET between chunks abandons the accumulated body and permits a fresh transaction. | `TestRFC3030BinaryAndResetRules` |
| CHUNK-ERROR-01 | 2 | MUST | Consume a failed chunk before sending its error, including oversized and out-of-sequence chunks; payload is never interpreted as commands. | `TestRFC3030RejectedChunksAreOpaque`, `TestRFC3030DiscardBeforeReply` |
| CHUNK-ERROR-02 | 2 | MUST | Accept and discard chunks already pipelined after a failed chunk; RSET recovers the transaction. | `TestRFC3030RejectedChunksAreOpaque` |
| CHUNK-ERROR-03 | 2 | Normative | A truncated chunk is not delivered or acknowledged as complete; an incomplete discard cannot leave a reusable command stream. | `TestRFC3030TruncatedChunkNotDelivered`, `TestRFC3030DiscardBeforeReply`, `TestRFC3030DiscardTimeoutClosesConnection` |
| BINARY-BODY-01 | 3 | Normative | Accept BODY=BINARYMIME only when enabled; CHUNKING can also carry 7BIT and 8BITMIME messages. | `TestRFC3030BinaryAndResetRules` |
| BINARY-BODY-02 | 3 | MUST | DATA after BODY=BINARYMIME receives 503; the sender must reset that transaction. | `TestRFC3030BinaryAndResetRules` |
| BINARY-DATA-01 | 3 | MUST | Preserve all bits in each received BDAT octet through the backend reader, including NUL, high-bit bytes and dot sequences. | `TestRFC3030Examples` |
| CHUNK-EXAMPLE-01 | 4.1 | Normative | Transfer the RFC's 86-octet bodyless message in one LAST chunk. | `TestRFC3030Examples` |
| CHUNK-EXAMPLE-02 | 4.2 | Normative | Transfer the binary example's two chunk lengths (100000 and 324), two recipients and zero-length LAST; placeholder content is deterministic binary data. | `TestRFC3030Examples` |
| CHUNK-LIMIT-01 | 2 | Normative | The count grammar has no specified maximum. | n/a: current implementation accepts at most 2^32-1 octets per chunk; larger messages must use multiple chunks. Counts beyond that range receive 501. This is a documented implementation limitation, not full grammar conformance. |
| CHUNK-CLIENT-01 | 2, 3 | MUST | Send BDAT only after CHUNKING; stop sending after a failed chunk and issue RSET after failure, DATA mixing or a command after LAST. | n/a: no BDAT client API; external senders own these rules. The server drains already-pipelined chunks, but does not enforce a mandatory RSET latch. |
| BINARY-CLIENT-01 | 3 | MUST | Never send binary material without BINARYMIME negotiation and BODY=BINARYMIME. | n/a: no binary client sender; Client.Mail refuses BodyBinaryMIME even when advertised, as tested by MIME-CLIENT-03. External BDAT senders must negotiate. |
| BINARY-HOST-01 | 2, 3 | MUST | Canonicalize text MIME parts to CRLF and use the canonical representation for their content type. | n/a: transport treats bytes as opaque; the sender prepares valid MIME, including text charset rules. |
| BINARY-HOST-02 | 3 | MUST | Storage, delivery and relay preserve every bit of accepted binary messages. | n/a: backend reader preservation is tested; storage and next-hop transport are host responsibilities. EnableBINARYMIME must reflect those capabilities. |
| BINARY-HOST-03 | 3 | MUST | When the next hop lacks BINARYMIME, any MIME conversion must be lossless and produce valid 7bit/8bit MIME without nested transfer encodings, or use delivery-failure policy. | n/a: the library has no MIME converter, queue or binary client sender; host routing and notification policy remain unaudited. |
| BINARY-HOST-04 | 3 | Normative | Accept binary MIME content lacking the BINARYMIME body declaration and normally return it to the sender with a suitable DSN. | n/a: no MIME inspection or DSN generation; the transport accepts opaque content and leaves post-acceptance notification policy to the host. |
