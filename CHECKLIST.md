# SMTP RFC checklist

Every requirement [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321) (SMTP)
places on the parts of go-smtp that this slice covers: the server and client
core, item by item, with the tests that cover it. A section number alone is
RFC 5321. The list takes in the MUSTs and SHOULDs, and the normative behaviour
that carries no keyword (level "Normative"), such as the grammar.

An item that does not apply, or is a known gap, says "n/a" and why. CI checks
this file against the tests with `go run ./internal/checklist`; the format is
described in the [README](README.md#the-rfc-checklist).

Postfix XCLIENT (a non-IETF extension) is audited below for session state and
trust boundaries; its remaining syntax and metadata-only compatibility gaps
are explicit.
STARTTLS (RFC 3207), SIZE (RFC 1870), PIPELINING (RFC 2920),
CHUNKING/BINARYMIME (RFC 3030), 8BITMIME (RFC 6152), AUTH exchange rules
(RFC 4954 §4), DSN parameter/protocol and relay transport rules (RFC 3461 §§2–4, 5.1, 5.2.1–5.2.2, 5.4),
the SMTPUTF8 envelope (RFC 6531), the RRVS parameter (RFC 7293), DELIVERBY
transport (RFC 2852), MT-PRIORITY transport (RFC 6710) and LMTP
(RFC 2033) are audited below.
The remaining AUTH and DSN lifecycle rules remain for later slices.
RFC 6409 submission authentication (§4.3) is checked below; its remaining
requirements are not yet audited. Reply line lengths (§4.5.3.1.5)
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
| SMTP-CLI-02 | 2.4 | MUST | EHLO keywords in the reply are read case-insensitively. | `TestClientEHLOExtensionCaseInsensitive`, `TestClientSupportsAuthAndSizeFromEHLO` |
| SMTP-CLI-03 | 4.2.1 | MUST | A 4xx or 5xx reply is returned as an error carrying the code and text, and a 421 ends the session. | `TestBasic_SMTPError`, `TestHello_421Response`, `TestClientGreetingRefusedFailsEveryCall`, `TestNewClientStartTLSGreetingRefused`, `TestClientResetAndQuitRefused`, `TestClientSendMailStopsAtFirstFailure`, `TestToSMTPErrMalformedEnhancedCode` |
| SMTP-CLI-04 | 4.5.2 | MUST | The client doubles a leading `.` of each line it sends in DATA and ends the data with a line holding one `.`. | `TestRFC5321_ClientDotStuffing`, `TestEODClientDotStuffsAndNormalises` |
| SMTP-CLI-05 | 4.5.3.1.5 | MUST | A reply line longer than the client supports is an error, not a truncation. | `TestClient_TooLongLine` |
| SMTP-CLI-06 | 4.1.1.5 | MUST | A new MAIL starts with no recipients from the one before, and RSET clears them. | `TestClientMailClearsRcpts`, `TestPipelinerMailClearsRcpts`, `TestPipeline_Reset` |
| SMTP-CLI-07 | 2.2.2 | MUST | The client does not send a MAIL parameter the server did not advertise, or one out of range. | `TestClientMailParamsUnadvertised`, `TestClientMailParamsOutOfRange`, `TestClientMailRequireTLS` |
| SMTP-CLI-08 | n/a | Normative | The client can tell whether a connection it kept is still healthy before it reuses it. | `TestCheckConn_HealthyPlaintext`, `TestCheckConn_ServerClosedPlaintext`, `TestCheckConn_UnsolicitedData`, `TestCheckConn_BufferedData`, `TestCheckConn_TLS` |

## Extensions (one row each; clause-by-clause checks come in later slots)

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SMTP-EXT-01 | RFC 2920 | Normative | PIPELINING regression summary; the clause-by-clause RFC 2920 audit below records its fixed-window client limitation. | `TestPipeline_NoRoundTripDeadlock`, `TestPipeline_Integration`, `TestPipeline_NotSupported`, `TestPipeline_LargeGroupDoesNotDeadlock`, `TestPipeline_LMTPSeesOnlyAcceptedRecipients`, `TestPipeline_StalledServerTimesOut`, `TestPipeline_ServerHangupMidGroup`, `TestPipelinedRepliesShareOneWrite`, `TestSingleCommandReplyIsPrompt`, `TestPartialPipelinedLineDoesNotHoldReplies` |
| SMTP-EXT-02 | RFC 6152 | Normative | 8BITMIME summary: `BODY=8BITMIME` and `7BIT` are accepted, other values are refused without BINARYMIME. Clause-by-clause transport checks and host responsibilities are below. | `TestServer8BITMIME`, `TestServer_BODYInvalidValue` |
| SMTP-EXT-03 | RFC 1870 | Normative | SIZE summary: declared and actual sizes are checked against `MaxMessageBytes` (inclusive); oversized content is drained with a bound. The RFC 1870 audit is below. | `TestServerBadSize`, `TestServerTooBig`, `TestServerSizeLimit_ExactlyMaxAccepted`, `TestServerSizeLimit_OverMaxRejected`, `TestServerSizeLimit_RejectWithinLimitKeepsConnection`, `TestServerSizeLimit_OversizedKeepsConnection`, `TestServerSizeLimit_OverLimitDrainBounded`, `TestServerSizeLimit_LMTP_OverLimitDrainBounded`, `TestServerSizeLimit_LMTP_Fallback_OverLimitDrainBounded` |
| SMTP-EXT-04 | RFC 3461, xtext (RFC 3461 §4) | Normative | DSN regression summary: `RET`, `ENVID`, `NOTIFY` and `ORCPT`, with xtext encoding both ways. The protocol audit below records scope and host responsibilities. | `TestServerDSN`, `TestClientDSN`, `TestClientXtext`, `TestXtextRoundTrip`, `TestServer_xtextLiteralNonXchar`, `FuzzDecodeXtext`, `FuzzEncodeXtext` |
| SMTP-EXT-05 | RFC 3030 | Normative | CHUNKING and BINARYMIME summary: existing BDAT, reset, errors, size and shutdown regressions. RFC 3030 transport clauses and explicit scope limits are audited below. | `TestServer_Chunking`, `TestServer_Chunking_LMTP`, `TestServer_Chunking_Reset`, `TestServer_Chunking_ClosedInTheMiddle`, `TestServer_Chunking_EarlyError`, `TestServer_Chunking_EarlyErrorDuringChunk`, `TestServer_Chunking_tooLongMessage`, `TestServer_Chunking_OverLimitDiscardKeepsConnection`, `TestServer_Chunking_Binarymime`, `TestServer_Chunking_LineLimitAfterNonLastBdat`, `TestBDATShutdownRace`, `TestBdatReadTimeoutClosesConnection`, `TestEODBDATChunksIgnoreDotSequences`, `TestServerBdatUnicodeSpaceIsNotSeparator` |
| SMTP-EXT-06 | RFC 6531, 6533 | Normative | One row for the extension: SMTPUTF8: the parameter, UTF-8 addresses, `ORCPT` with UTF-8 (xtext and unitext), and the client's detection. The RFC 6531 envelope audit is below. | `TestServerSMTPUTF8`, `TestServerSMTPUTF8_Disabled`, `TestServerDSNUTF8AddressORCPT`, `TestServerDSNwithSMTPUTF8`, `TestSendMail_SMTPUTF8_Autodetect`, `TestSendMail_SMTPUTF8_NotAdvertised`, `TestIsASCII`, `TestUTF8AddrOracleCatchesMutants`, `TestUTF8AddrRFC6533Regressions`, `TestClientORCPTUTF8Encoding`, `FuzzDecodeUTF8AddrXtext`, `FuzzEncodeUTF8AddrXtext`, `FuzzEncodeUTF8AddrUnitext` |
| SMTP-EXT-07 | RFC 3207 | Normative | STARTTLS summary: parser, handshake, TLS state, close races and AUTH protection. The clause-by-clause audit is below. | `TestTLSClient`, `TestTLSConnState`, `TestStartTLSClosesOnHandshakeFailure`, `TestStartTLSCloseRace`, `TestStartTLSReplySentBeforeHandshake`, `TestParseCmdSTARTTLSExact`, `TestAuthTLSRequiredCode`, `TestNewClientStartTLS` |
| SMTP-EXT-08 | RFC 4954 | Normative | One row for the extension: AUTH: mechanisms, initial response, cancellation, a second AUTH, anonymous access, and read timeouts. The exchange rules have individual rows below; other clauses remain unaudited. | `TestServerAuthTwice`, `TestServerCancelSASL`, `TestServer_authDisabled`, `TestServer_anonymousUserError`, `TestServer_anonymousUserOK`, `TestServer_authParam`, `TestAuthRejectsExtraTokens`, `TestAuthFailed`, `TestClientAuthTrimSpace`, `TestAuthChallengeSentBeforeReadingResponse`, `TestAuthClientCancelReturns501`, `TestAuthContinuationReadTimeoutClosesConnection`, `TestServerAuthUnicodeSpaceIsNotSeparator`, `TestRFC4954_LongChallengeNotTruncated` |
| SMTP-EXT-09 | RFC 2033 | Normative | One row for the extension: LMTP: `LHLO`, one reply per recipient after the data, and the client side. The clauses of the RFC are not checked one by one yet. | `TestServer_LMTP`, `TestServer_LMTP_Early`, `TestServer_LMTP_Expand`, `TestServer_LMTP_DuplicatedRcpt`, `TestServer_Chunking_LMTP`, `TestLMTP`, `TestLMTPData`, `TestLMTPRcptLeakAcrossTransactions`, `TestLMTPDataErrorMessages` |
| SMTP-EXT-10 | RFC 7293 | Normative | RRVS summary: the `RRVS` parameter on RCPT. The RFC 7293 audit is below. | `TestServerRRVS`, `TestClientRRVS` |
| SMTP-EXT-11 | RFC 2852 | Normative | DELIVERBY summary: `BY` on MAIL only, in range; the detailed audit below separates transport from host delivery policy. | `TestServerDELIVERBY`, `TestClientDELIVERBY`, `TestClientDeliverByTruncatesToSeconds`, `TestParseDeliverByBoundaries`, `FuzzParseDeliverByArgument`, `TestServerDeliverByAndMTPriorityRejectedOnRcpt` |
| SMTP-EXT-12 | RFC 6710 | Normative | MT-PRIORITY summary: the MAIL parameter; the detailed RFC 6710 transport audit below separates syntax from host authorization and queue policy. | `TestServerMTPRIORITY`, `TestClientMTPRIORITY` |
| SMTP-EXT-13 | Postfix XCLIENT (not an IETF RFC) | Normative | XCLIENT lets trusted peers assert client identity; see the separate Postfix XCLIENT audit below for session state, host duties and syntax gaps. | `TestServerXClientTrusted`, `TestServerXClientUntrusted`, `TestServerXClientKeepsUnicodeSpaceInValue` |


## AUTH exchange (RFC 4954 §3, §4 and §8)

This slice checks command framing and the SASL challenge/response exchange,
including the PLAIN and empty EXTERNAL wire examples of §4.1. It does **not**
claim a complete RFC 4954 audit. The §5 MAIL AUTH trust/relay rules, §6 policy,
§7 trace headers and §14 TLS identity requirements remain unaudited. Existing
MAIL AUTH tests remain in SMTP-EXT-08. The host supplies the actual SASL
mechanisms and credential/identity policy through AuthSession.
SMTP-AUTH-24 installs a PLAIN backend and a verified STARTTLS client, with
insecure authentication disabled; the host still configures TLS and credentials.

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
| SMTP-AUTH-24 | RFC 4954 §4 | MUST | PLAIN over TLS is available for interoperability. | `TestRFC4954PlainOverTLS` |
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
SIZE-REPLY-03 proves a backend storage refusal reaches the wire as 452 and
does not start a transaction; storage accounting remains a backend duty.
The SMTPUTF8, RRVS and DELIVERBY length proofs use the default 2000-octet
command budget. Hosts lowering MaxLineLength must still budget every enabled
extension combination; these tests do not claim a universal combination audit.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SIZE-EHLO-01 | 3, 4 | Normative | Advertise SIZE and the fixed inclusive maximum as a decimal octet count. | `TestRFC1870Advertisement` |
| SIZE-EHLO-02 | 3, 7 | Normative | SIZE 0 means no configured fixed maximum; a bare SIZE does not convey a maximum. | `TestRFC1870Advertisement` |
| SIZE-EHLO-03 | 3, 7 | Normative | The client distinguishes a numeric maximum (including unlimited zero) from an absent or unusable maximum; only ASCII decimal digits are valid. | `TestRFC1870ClientLimits`, `FuzzRFC1870SizeValues`, `TestClientSupportsAuthAndSizeFromEHLO` |
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
| SIZE-REPLY-03 | 6.1 | MAY | Temporary storage shortage may be refused with 452 at MAIL time. | `TestRFC1870TemporaryStorageRefusal` |
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
| PIPE-CLIENT-01 | 3, 3.1 | Normative | The client sends a pipelined group only after discovering server support. | `TestPipeline_NotSupported`, `TestRFC2920ClientResponseCorrelation`, `TestPipelinerRejectsBeforeSending` |
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
| CHUNK-STATE-02 | 2 | MUST | DATA during an unfinished BDAT transaction gets 503; DATA and BDAT may be used in different transactions of the same session. | `TestRFC3030BinaryAndResetRules`, `TestRFC3030Examples`, `TestBDATResultAfterReset` |
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

## DSN parameters, protocol and relay transport (RFC 3461 §§2–4, 5.1, 5.2.1–5.2.2, 5.4)

This slice audits the SMTP parameters and their transport, not a complete MTA's
notification lifecycle. Sections below refer to RFC 3461 unless stated otherwise.
The former combined DSN-HOST-03/04 rows are split into individual relay
transport clauses below: a host passes the received options into the outbound
client, and both ordinary and pipelined SMTP paths preserve the requests.
Tests deliver across two real SMTP connections, inspect the outbound commands
and the next backend's metadata, and rewrite routing addresses independently of
ORCPT. They do not prove an autonomous relay or notification lifecycle; those
host duties remain explicit in DSN-HOST-09/10. Address types are compared
case-insensitively but their received spelling is retained for relays.
The §10.1 example tests its envelope and recipient requests; it does not claim
that the host generates the reports in §§10.6–10.9. RFC 6533's UTF-8 address
encoding remains in SMTP-EXT-06, not this RFC 3461 ASCII-address audit.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| DSN-EHLO-01 | 2–3 | Normative | DSN is advertised without arguments only when the host enables the capability. | `TestRFC3461Parameters`, `TestRFC3461Disabled` |
| DSN-SYNTAX-01 | 4.1 | MUST | NOTIFY has a value containing only case-insensitive ASCII SUCCESS, FAILURE, DELAY, or standalone NEVER; unknown and non-ASCII conditions are refused. | `TestRFC3461Parameters`, `TestRFC3461ClientParameters`, `FuzzRFC3461Notify` |
| DSN-SYNTAX-02 | 4.1; RFC 822 §2.7 | Normative | The 1# list permits repeated conditions and null elements but requires a non-null condition; NEVER cannot appear in any list. Backend conditions are unique and nonempty. | `TestRFC3461Parameters`, `TestRFC3461ClientParameters`, `FuzzRFC3461Notify` |
| DSN-SYNTAX-03 | 4.3 | MUST | RET has the case-insensitive ASCII value FULL or HDRS; absent RET remains unset for host policy. | `TestRFC3461Parameters`, `TestRFC3461ClientParameters` |
| DSN-SYNTAX-04 | 4.4 | MUST | ENVID has an xtext value decoding to printable US-ASCII, including spaces; its opaque value and absence reach the host unchanged. | `TestRFC3461Parameters`, `TestRFC3461ClientParameters` |
| DSN-SYNTAX-05 | 4.2 | MUST | RFC822 ORCPT has an address type, semicolon and xtext address decoding to printable US-ASCII; it is not required to match mailbox syntax or the current recipient. | `TestRFC3461Parameters`, `TestRFC3461ClientParameters` |
| DSN-SYNTAX-06 | 4.5 | MUST NOT | RET/ENVID cannot repeat within MAIL, nor NOTIFY/ORCPT within RCPT; repeats receive 501. | `TestRFC3461Parameters` |
| DSN-REPLY-01 | 5.1 | MUST | Valid DSN parameters do not change the SMTP policy result; malformed or duplicate parameters receive 501, and a rejected command leaves the connection usable. | `TestRFC3461Parameters`, `TestRFC3461BackendStatus` |
| DSN-REPLY-02 | 2–3 | Normative | A server with DSN disabled refuses its parameters without starting a MAIL transaction or accepting that recipient. | `TestRFC3461Disabled` |
| DSN-STATE-01 | 3, 4.1–4.4 | Normative | MAIL metadata belongs to the transaction and each recipient retains its own NOTIFY/ORCPT; RSET and a completed transaction do not leak metadata into the next message. | `TestRFC3461Parameters`, `TestRFC3461SubmissionExample` |
| DSN-CLIENT-01 | 2–4 | Normative | The client encodes printable identifiers/original addresses as xtext and never sends DSN parameters without advertised support; invalid API choices fail before any command is written. | `TestRFC3461ClientParameters` |
| DSN-LIMIT-01 | 5.4 | MUST | The default server accepts the ENVID, NOTIFY, ORCPT and RET minimum parameter allowances (100, 28, 500 and 8 characters). | `TestRFC3461ParameterSizes` |
| DSN-LIMIT-02 | 5.4 | MUST | The default server accepts a 1036-octet RCPT command including DSN parameters and CRLF. | `TestRFC3461ParameterSizes` |
| DSN-EXAMPLE-01 | 10.1 | Normative | The submission example preserves Alice's ENVID/RET and six recipients' different notification requests through DATA. | `TestRFC3461SubmissionExample` |
| DSN-SCOPE-01 | 4.2 | MUST | Registered address types beyond RFC822 must retain their defined printable representation. | n/a: not supported yet; decodeTypedAddress and the client accept only RFC822 and the separately tested RFC 6533 UTF-8 type. A registry/extensibility API is a future slice. |
| DSN-HOST-01 | 4.1, 4.3 | Normative | Absent NOTIFY means FAILURE or FAILURE,DELAY; absent RET permits headers or full content, and no DELAY requests no delayed report. | n/a: the host interprets unset options and notification policy; the library preserves absence rather than choosing defaults. |
| DSN-HOST-02 | 4.2, 5.4 | MUST | Initial submission and mailing-list redistribution use the current recipient as ORCPT. | n/a: callers distinguish new submission from relay and choose identifiers; the generic transport cannot infer that role or enforce equality during forwarding. |
| DSN-LIMIT-03 | 5.4 | SHOULD NOT | Submitting user agents generate ENVID parameters longer than 38 characters. | n/a: the generic client also serves relays and preserves foreign identifiers; a submitting UA must choose short IDs. |
| DSN-HOST-03 | 5.2.1(a) | MUST | When received MAIL options are passed to a DSN-capable next hop, preserve ENVID (including its absence and identifier case) across the server/client boundary. | `TestRFC3461RelayEnvelopeID` |
| DSN-RELAY-01 | 5.2.1(b) | MUST | When relaying received MAIL options to a DSN-capable peer, retain FULL/HDRS and do not invent RET when absent. | `TestRFC3461RelayReturn` |
| DSN-RELAY-02 | 5.2.1(c) | MUST | When relaying received RCPT options to a DSN-capable peer, retain each recipient's notification conditions and do not add NOTIFY when absent. | `TestRFC3461RelayNotify` |
| DSN-RELAY-03 | 5.2.1(d) | MUST | When relaying received RCPT options, retain the ORCPT address and address-type case even if the routing address changes; do not synthesize an absent ORCPT. | `TestRFC3461RelayOriginalRecipient` |
| DSN-RELAY-04 | 5.2.1(d) | MUST | If a host elects to add an absent ORCPT, the transport can carry the received RCPT address as the original recipient, independently of the rewritten outbound route. | `TestRFC3461RelayAddedOriginalRecipient` |
| DSN-HOST-04 | 5.2.2(a) | MUST NOT | Send ENVID, RET, NOTIFY or ORCPT to a next hop without DSN, including when relaying options received from a DSN-capable peer. | `TestRFC3461RelayNonDSN` |
| DSN-HOST-05 | 5.2.7–5.3 | MUST | Apply mailing-list, alias, confidential-forwarding and multi-recipient report rules; translate local/gateway requests and strip local control headers. | n/a: no alias/list expansion, gateway conversion or message-header processing in this transport library; host lifecycle audit remains. |
| DSN-HOST-06 | 5.4 | MUST | Accept command lines large enough for all enabled extension combinations. | n/a: default 2000-octet command budget covers the tested DSN minima; hosts overriding MaxLineLength or adding capabilities must budget their combined maximum. No universal extension-combination audit is claimed. |
| DSN-HOST-07 | 6.1 | MUST | Reports use a null sender, the original envelope sender as recipient, no RET, and only NEVER if NOTIFY is specified. | n/a: a caller constructing a DSN owns its envelope; generic MAIL/RCPT cannot distinguish reports from ordinary messages. |
| DSN-HOST-08 | 6.2–6.3 | MUST | Generate multipart delivery-status reports with the requested content and required envelope/recipient fields. | n/a: no report MIME generator in this library; host must implement and test report content, confidentiality and field requirements. |
| DSN-HOST-09 | 5.2, 5.2.1 | MUST NOT | Issue a DSN for a null reverse-path, even if a sender is present in message headers. | n/a: the library has no notification generator, durable queue or automatic relay. The host must suppress report loops, notify its postmaster safely, persist metadata and pass the received options to the outbound client; the relay transport tests prove only that last boundary. |
| DSN-HOST-10 | 5.2.2(b–f)–5.2.6 | MUST | Apply non-DSN next-hop, delivery, delay, failure and foreign-gateway reporting rules. | n/a: no report generator, delivery scheduler or gateway in this transport library. The host must inspect Extension("DSN"), recipient outcomes and received NOTIFY before choosing relayed/failed reports or suppressing them; omission of next-hop parameters alone is not reporting conformance. |

The existing xtext fuzz targets use independent grammar/encoding references and
remain in SMTP-EXT-04. FuzzRFC3461Notify checks the new list parser against an
ASCII grammar oracle. Reports, downgrade reporting, other registered address types
and the remaining lifecycle clauses are explicit scope/gap rows, not proof of
complete RFC 3461 conformance.

## SMTPUTF8 (RFC 6531)

Sections here refer to [RFC 6531](https://www.rfc-editor.org/rfc/rfc6531).
This slice audits the envelope: the EHLO keyword, the MAIL parameter, UTF-8
mailboxes and the per-transaction rules for non-ASCII addresses. RFC 6532
message headers, IDNA lookups and downgrade are host responsibilities; the
UTF-8 `ORCPT` encoding of RFC 6533 stays in SMTP-EXT-06.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| UTF8-EHLO-01 | 3.1 items 2–3 | MUST NOT | SMTPUTF8 is advertised without parameters, and only when the host enables it. | `TestRFC6531Advertisement` |
| UTF8-EHLO-02 | 3.1 item 8 | MUST | A server offering SMTPUTF8 also announces 8BITMIME. | `TestRFC6531Advertisement` |
| UTF8-MAIL-01 | 3.1 item 4, 3.4 | MUST | The MAIL parameter SMTPUTF8 does not accept a value; one is refused with 501 5.5.4. | `TestRFC6531ServerEnvelope`, `TestRFC6531ServerParameterValue` |
| UTF8-MAIL-02 | 3.1 item 4 | Normative | The parameter is accepted case-insensitively and reaches the backend as `MailOptions.UTF8`; it is refused with 504 when not advertised. | `TestRFC6531ServerEnvelope`, `TestRFC6531ServerDisabled`, `TestRFC6531ServerParameterValue` |
| UTF8-MAIL-03 | 3.1 item 4, 3.4 | MUST NOT | `SMTPUTF8=` with an empty value is refused. | `TestRFC6531ServerParameterValue` |
| UTF8-MAIL-04 | 3.1 item 5 | Normative | The MAIL command line may be 10 octets longer to carry the parameter. | `TestRFCExtendedCommandBudgets` |
| UTF8-ADDR-01 | 3.2, 3.3 | MUST | A server announcing SMTPUTF8 accepts a UTF-8 string wherever a mailbox appears, and passes it to the backend unchanged. | `TestRFC6531ServerEnvelope` |
| UTF8-ADDR-02 | 3.5 | Normative | Without SMTPUTF8 on MAIL, a non-ASCII reverse-path gets 550 5.6.7 and a non-ASCII forward-path gets 553 5.6.7, whether or not the extension is enabled. | `TestRFC6531ServerEnvelope`, `TestRFC6531ServerDisabled` |
| UTF8-ADDR-03 | 3.2; RFC 3629 | MUST | Addresses are UTF-8 strings: a mailbox with invalid UTF-8 octets is refused with 501 5.5.2. | `TestRFC6531ServerEnvelope` |
| UTF8-STATE-01 | 3.4 | Normative | SMTPUTF8 applies to its own transaction: RSET or a new MAIL without the parameter drops it, on server and client. | `TestRFC6531ServerEnvelope`, `TestRFC6531Client`, `TestRFC6531ServerParameterValue` |
| UTF8-CLIENT-01 | 3.2, 3.4 | MUST | The client sends a non-ASCII sender only with SMTPUTF8, and a non-ASCII recipient only in a transaction whose MAIL carried it; otherwise it refuses without writing. | `TestRFC6531Client`, `TestSendMail_SMTPUTF8_Autodetect`, `TestSendMail_SMTPUTF8_NotAdvertised` |
| UTF8-CLIENT-02 | 3.2 | MUST NOT | The client does not send SMTPUTF8 to a server that did not advertise it. | `TestSendMail_SMTPUTF8_NotAdvertised`, `TestRFC6531Client` |
| UTF8-CLIENT-03 | 3.1 item 3 | MUST | The client ignores any parameters on the SMTPUTF8 keyword. | `TestRFC6531Client` |
| UTF8-CLIENT-04 | 3.4 | SHOULD NOT | The client omits SMTPUTF8 when the envelope does not need it. | `TestSendMail_SMTPUTF8_Autodetect` |
| UTF8-VRFY-01 | 3.7.4.2 | MUST NOT | VRFY and EXPN replies contain no UTF-8 unless the client sent SMTPUTF8; the server's VRFY reply (252) and EXPN refusal are always ASCII. | `TestRFC6531VrfyRepliesStayASCII` |
| UTF8-REPLY-01 | 3.7.4.1 | MUST NOT | Without SMTPUTF8 on MAIL, no 251 or 551 reply carries a non-ASCII mailbox. | n/a: host responsibility: the library sends no 251 or 551 itself; a backend returning a custom `SMTPError` chooses its text. |
| UTF8-BODY-01 | 3.2, 3.1 item 10 | MUST NOT | No RFC 6532 internationalized header is sent to a server without SMTPUTF8. | n/a: gap: Data does not inspect content; callers must set `MailOptions.UTF8` for an internationalized message. |
| UTF8-DOWN-01 | 3.2 | Normative | A sender facing a server without SMTPUTF8 rejects, bounces or downgrades the message. | n/a: host policy: the client returns an error; there is no queue, bounce or downgrade implementation. |
| UTF8-DNS-01 | 3.2 | MUST | Domain names looked up in DNS follow IDNA (Unicode-aware lookup or A-labels). | n/a: the library performs no DNS lookups; the host's dialer and routing do. |
| UTF8-EHLO-03 | 3.7.1 | MUST | EHLO domain names and the server's EHLO response use LDH labels or A-labels. | n/a: host configuration: `Client.Hello` and `Server.Domain` take the name the host supplies. |
| UTF8-TRACE-01 | 3.7.3, 3.1 item 11 | Normative | Trace fields use the UTF8SMTP/UTF8SMTPA/UTF8SMTPS WITH keywords. | n/a: the library writes no Received fields; the host adds trace headers. |
| UTF8-DSN-01 | 3.6; RFC 6533 | MUST | A server offering DSN with SMTPUTF8 implements RFC 6533's UTF-8 address type. | `TestServerDSNUTF8AddressORCPT`, `TestServerDSNwithSMTPUTF8`, `TestClientORCPTUTF8Encoding` |

## RRVS (RFC 7293)

Sections here refer to [RFC 7293](https://www.rfc-editor.org/rfc/rfc7293).
This slice audits the SMTP extension: the EHLO keyword, the RCPT parameter's
grammar and the client's sending rules. The ownership check, relaying and the
`Require-Recipient-Valid-Since` header field belong to the host, which receives
the timestamp and the no-support action in `RcptOptions`.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| RRVS-EHLO-01 | 3.1 | Normative | RRVS is advertised without parameters, and only when the host enables it. | `TestRFC7293Server` |
| RRVS-SYN-01 | 3.1; RFC 3339 §5.6 | Normative | The value is an RFC 3339 date-time with seconds and an offset (`Z` or `±hh:mm`, case-insensitive `T`/`Z`, leap second 60); anything else gets 501 5.5.4. | `TestRFC7293ParseArgument`, `TestRFC7293Server`, `TestServerRRVS` |
| RRVS-SYN-02 | 3.1 | MUST NOT | A value with time-secfrac is refused. | `TestRFC7293ParseArgument`, `TestRFC7293Server` |
| RRVS-SYN-03 | 3.1 | Normative | The only no-support actions are `;R` and `;C`; any other suffix, including an empty one, gets 501 5.5.4. | `TestRFC7293ParseArgument`, `TestServerRRVS` |
| RRVS-SRV-01 | 3.1, 5.1.1 | MUST | The timestamp (in UTC) and the action reach the backend, and an absent action stays absent, so a relay can preserve it as sent. | `TestRFC7293Server`, `TestServerRRVS` |
| RRVS-SRV-02 | 3.1 | Normative | The parameter is refused with 504 5.5.4 when RRVS is not advertised. | `TestRFC7293Server` |
| RRVS-LEN-01 | 3.1 | Normative | The RCPT command line may be 33 octets longer to carry the parameter. | `TestRFCExtendedCommandBudgets` |
| RRVS-CLI-01 | 3.1 | MUST NOT | The client sends the timestamp in UTC without time-secfrac, and a no-support action only when the caller set one; an unknown action or a year outside 0000–9999 is refused before writing. | `TestRFC7293Client`, `TestClientRRVS` |
| RRVS-CLI-02 | 5.1.1, 6 | MUST | To a server without RRVS, the client refuses a recipient whose action is reject or absent, without writing anything. | `TestRFC7293Client` |
| RRVS-CLI-03 | 5.1.1, 6 | Normative | With the action `C`, the client sends the recipient to a server without RRVS without the parameter. | `TestRFC7293Client` |
| RRVS-OWN-01 | 5, 5.1 | MUST | A receiver checks continuous ownership since the timestamp, ignores it for role accounts and returns 550 (X.7.17/X.7.18/X.7.19) when the check fails or cannot be done. | n/a: host responsibility: the library holds no mailbox history; the backend's `Rcpt` returns the `SMTPError`. |
| RRVS-RELAY-01 | 5.1.1, 6 | MUST | A relay whose next hop lacks RRVS rejects (550 to DATA or a DSN) unless the action is `C`, and preserves the action when it relays. | n/a: host responsibility: the library has no queue; `RRVS-CLI-02` is the client half. |
| RRVS-HDR-01 | 3.2, 4, 5.2, 6.1 | Normative | The `Require-Recipient-Valid-Since` header field is parsed, checked, removed and converted to or from the parameter. | n/a: host responsibility: Data does not inspect message content. |
| RRVS-CLOCK-01 | 5.3 | MUST | Generators and receivers synchronise their clocks, for example with NTP. | n/a: the library has no clock policy; the host's system clock is used. |


## DELIVERBY (RFC 2852)

Sections refer to [RFC 2852](https://www.rfc-editor.org/rfc/rfc2852).
This audits the SMTP transport and the envelope examples in §6. Enabling
DELIVERBY promises the host implements the delivery and notification semantics;
passing a relative duration to `Session.Mail` does not enforce a deadline.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| BY-EHLO-01 | 2, 3 | Normative | Advertise DELIVERBY only when enabled, with an optional fixed minimum for return mode. | `TestRFC2852Server` |
| BY-SYN-01 | 4 | MUST | BY is a MAIL parameter with a required value, one optional sign and one to nine ASCII decimal digits in seconds. | `TestRFC2852Server`, `TestRFC2852CaseInsensitive`, `FuzzParseDeliverByArgument` |
| BY-SYN-02 | 4 | Normative | Modes N and R and optional trace T are case-insensitive ABNF literals; other suffixes are refused. | `TestRFC2852Server`, `TestRFC2852CaseInsensitive`, `FuzzParseDeliverByArgument` |
| BY-SYN-03 | 4 | SHOULD | Notify mode permits zero and negative times; return mode requires a positive time, otherwise 501 5.5.4. | `TestRFC2852Server`, `TestRFC2852CaseInsensitive`, `FuzzParseDeliverByArgument` |
| BY-SRV-01 | 3, 4 | Normative | A valid return deadline below the fixed server minimum receives a 55z permanent failure (555); the minimum does not restrict notify mode. | `TestRFC2852Server` |
| BY-SRV-02 | 2, 3, 4 | Normative | The message deadline, mode and trace reach Mail; BY is refused on RCPT and when disabled. | `TestRFC2852Server` |
| BY-STATE-01 | 4 | Normative | Refused requests do not reach the backend; RSET and a new MAIL do not reuse an earlier deadline. | `TestRFC2852Server` |
| BY-CLI-01 | 3, 4.1.4.1 | MUST NOT | Return-mode mail is not sent when its remaining time is below the next hop's advertised minimum. | `TestRFC2852ClientMinimum` |
| BY-CLI-02 | 2, 4.1.4.1 | Normative | Parse the minimum before future comma-separated options; refuse malformed minima for return mode without writing MAIL. | `TestRFC2852ClientMinimum` |
| BY-EXAMPLE-01 | 6 | Normative | Accept the 120-second original and 98-second relayed envelopes; refuse the 240-second next-hop minimum and accept 30. | `TestRFC2852Server`, `TestRFC2852ClientMinimum` |
| BY-LEN-01 | 2(5) | Normative | Allow 17 extra octets on MAIL for BY. | `TestRFCExtendedCommandBudgets` |
| BY-CLOCK-01 | 4 | Normative | Convert relative time to an absolute deadline on receipt, without extending ordinary retention or treating it as a delivery start time. | n/a: host owns the clock and queue; Mail receives only a duration and must capture receipt time. |
| BY-DSN-01 | 4.1.1 | Normative | Successful delivery honors requested SUCCESS notifications. | n/a: host owns DSN generation and recipient notification options. |
| BY-DSN-02 | 4.1.2 | MUST | Before expiry, permanent failure produces failed DSNs for recipients with default or FAILURE notification policy. | n/a: host owns delivery outcome and DSN generation. |
| BY-RETRY-01 | 4.1.2 | SHOULD | Temporary failure before expiry follows site retry policy while preserving deadline rules. | n/a: library has no retry queue. |
| BY-EXPIRE-01 | 4.1.3 | MUST | At return-mode expiry stop delivery and issue failed DSNs with 5.4.7, subject to recipient notification policy. | n/a: host must enforce expiry and generate reports; transport does neither. |
| BY-EXPIRE-02 | 4.1.3 | MUST | At notify-mode expiry issue delayed DSNs with 4.4.7 for default or DELAY policy; delivery should continue. | n/a: host owns expiry, retries and reports. |
| BY-RELAY-01 | 4.1.4 | MUST | Relay with time remaining recomputed near MAIL transmission, preserving mode and trace; expired relay is notify-only. | n/a: callers must compute remaining Time; client has no absolute deadline or queue. |
| BY-TRACE-01 | 4.1.4 | SHOULD | Trace requests generate nonterminal relayed DSNs except for NEVER recipients. | n/a: host owns trace reports and notification policy. |
| BY-RELAY-02 | 4.1.4.1 | MUST NOT | Return-mode mail cannot relay to a peer without DELIVERBY. | n/a: client refuses unadvertised BY, but host owns alternate-hop selection and failure DSNs. |
| BY-RELAY-03 | 4.1.4.2 | MUST | Notify-mode fallback to an unextended peer generates relayed DSNs before expiry and adjusts DSN DELAY requests as specified. | n/a: explicit gap: client conservatively refuses all unadvertised BY; host must choose fallback and generate reports. |
| BY-GATEWAY-01 | 4.1.5 | Normative | Foreign gateways preserve equivalent deadline semantics or apply unextended-peer rules. | n/a: no foreign gateway implementation in this library. |
| BY-DSN-03 | 4.1, 5 | SHOULD | Deadline-related DSNs include Arrival-Date and Deliver-By-Date in the prescribed date format. | n/a: host supplies DSN messages; transport does not inspect their content. |
| BY-MX-01 | 7 | SHOULD NOT | Clients avoid trying multiple MX hosts merely to discover DELIVERBY support. | n/a: host chooses MX routes; Client connects to one chosen peer. |
| BY-MX-02 | 7 | Normative | MX minimum advertisements account for downstream minima and normal relay latency. | n/a: host configures MinimumDeliverByTime from its routing policy. |


## MT-PRIORITY transport (RFC 6710)

Section numbers below refer to [RFC 6710](https://www.rfc-editor.org/rfc/rfc6710).
This is a transport audit, not a claim that enabling the flag implements a
priority service. The host must authorize sources before accepting upgraded
priorities, implement its assignment policy, and preserve metadata across queues
and hops. `MailOptions.MTPriority` is the original requested value, not an
internally rounded service class. A nil option leaves the default/policy choice
to the backend. These host duties and configuration gaps are explicit below.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| PRI-EHLO-01 | 3(2–3), 7 | Normative | Advertise MT-PRIORITY when enabled, optionally followed by the configured policy name; no name means the server withholds its policy. | `TestRFC6710Server` |
| PRI-SYN-01 | 3(5), 4.1(1), 7 | MUST | Accept exactly zero or one optionally negative nonzero ASCII digit; reject malformed values and duplicate parameters without invoking Mail. | `TestRFC6710Server`, `FuzzRFC6710Priority` |
| PRI-LEN-01 | 3(6) | Normative | Permit 15 additional octets on MAIL for the priority parameter, with the default line budget. | `TestRFC6710LongMailAndLMTP` |
| PRI-SRV-01 | 3(5), 4.1(4), 5.1 | Normative | The priority is one MAIL parameter for the whole message, not a per-recipient RCPT parameter; disabled support refuses it. | `TestRFC6710Server` |
| PRI-STATE-01 | 4.1(4), 5 | Normative | Preserve all 19 exact requested priority values for the backend, including values not individually supported by a named policy. | `TestRFC6710Server` |
| PRI-STATE-02 | 4.1(4–5) | Normative | A refused parameter never starts a transaction; a nested MAIL cannot replace it, and reset, EHLO or completed DATA clears it; omission reaches Mail as nil. | `TestRFC6710Server` |
| PRI-CLI-01 | 3(3,5), 4.2(1), 5 | MUST | Serialize the explicitly supplied priority unchanged, regardless of an absent or unknown policy name; refuse API values outside -9..9 before writing. | `TestRFC6710Client`, `TestRFC6710ExampleEnvelope` |
| PRI-CLI-02 | 4.3(1) | Normative | Do not send MT-PRIORITY to a peer that did not advertise it; explicit options fail locally and the caller may retry with the option omitted. | `TestRFC6710Client` |
| PRI-EXAMPLE-01 | 8 | Normative | Reproduce the priority-3 submission and relay envelopes with ENVID=QQ314159 and BY=125;R or BY=120;R. | `TestRFC6710ExampleEnvelope`, `TestRFC6710Client` |
| PRI-STATUS-01 | 4.1, 5, 10 | Normative | Preserve backend policy refusal codes, including X.7.15 for a too-low priority and 552 X.7.16 for priority-specific size limits; refusal does not start a transaction. | `TestRFC6710BackendStatuses` |
| PRI-STATUS-02 | 4.1, 10 | SHOULD | A backend can report reassignment with a custom 250 X.3.6 and the new priority at the start of the text, while accepting the transaction. | `TestRFC6710BackendStatuses` |
| PRI-LMTP-01 | 3(7), 6 | Normative | LMTP can advertise the extension and expose the original requested priority to a host delivery/filtering engine. | `TestRFC6710LongMailAndLMTP` |
| PRI-PROFILE-01 | 7, 10.1(1) | Normative | A policy name is 1..20 ASCII letters, digits, hyphen, underscore or dot. | n/a: known configuration gap: MtPriorityProfile is advertised verbatim; the host must supply a valid name. |
| PRI-TRACE-01 | 4.1(2), 7 | SHOULD | Include the PRIORITY clause when inserting Received trace fields. | n/a: host constructs Received fields; transport does not edit message headers. |
| PRI-LOG-01 | 4.1(3) | SHOULD | Include the received priority in transaction logs. | n/a: host owns message transaction logging and receives the exact priority in Mail. |
| PRI-DEFAULT-01 | 4.1(5) | Normative | Without an explicit priority use site policy, with default 0. | n/a: Mail receives nil; host chooses policy and must apply the default. |
| PRI-AUTH-01 | 4.1, 11 | MUST NOT | Do not allow positive priorities from untrusted or unauthorized sources. | n/a: mandatory host authorization policy; enabling the extension alone does not gate positive values, even after SMTP AUTH. Mail must reject or lower them using the connection's trust context. |
| PRI-REASSIGN-01 | 4.1 | MAY | Site policy may raise or lower a requested or omitted priority; an MSA may refuse it. | n/a: host owns policy decisions; transport preserves backend status replies but does not assign priorities. |
| PRI-RELAY-01 | 4.2(1), 5 | MUST | Relay the determined priority to conforming next hops, retaining the unrounded value rather than the internal service class. | n/a: host owns stored metadata and relay construction; Client only serializes supplied MailOptions. |
| PRI-ALIAS-01 | 4.4 | SHOULD | Preserve the priority for expanded or translated recipients. | n/a: aliases and mailing lists are host responsibilities. |
| PRI-GATEWAY-01 | 4.5 | SHOULD | Foreign gateways map equivalent priorities or follow non-conforming-peer rules. | n/a: no foreign gateway in this transport library. |
| PRI-DSN-01 | 4.6 | SHOULD | Generated delivery reports use the source message's priority. | n/a: host generates DSNs and retains the original metadata. |
| PRI-DSN-02 | 4.6 | Normative | Relayed DSNs follow ordinary priority authorization rules rather than automatic elevation. | n/a: host owns message classification and policy; transport does not inspect DATA for DSNs. |
| PRI-LEVEL-01 | 5 | MUST | Implement every distinct level of the selected assignment policy, rounding unsupported service classes upward (capped at the highest) internally. | n/a: host owns the scheduling/service-class policy; selecting a profile name alone supplies no scheduling implementation. |
| PRI-ORDER-01 | 5.1 | Normative | Prefer higher-priority queued messages, retaining ordinary ordering within each level; retry/expiration intervals may be more aggressive. | n/a: transport has no queue, scheduler, retry or expiration machinery. |
| PRI-GREY-01 | 5.1 | Normative | Authorized priority senders avoid greylisting except for explicit policy restrictions or misconfiguration. | n/a: greylisting and source trust policy belong to the host. |
| PRI-TIME-01 | 5.2 | Normative | DELIVERBY and priority can be combined without requiring either extension to enable the other. | n/a: host selects deadlines per priority; the example tests only verify combined parameter transport. |
| PRI-MX-01 | 9.1 | Normative | Configure MX peers consistently or disable priority service to avoid inconsistent delivery. | n/a: DNS and multi-server deployment configuration are outside this library. |
| PRI-POLICY-01 | 9.2, 10.1–10.2, Apps. A–C | Normative | Document and consistently deploy the assignment policy, its levels, retry/expiry/size limits and trust rules; register additional policies as appropriate. | n/a: host deployment and policy-registration duties; the built-in constants name policies without implementing their schedulers. |


## LMTP (RFC 2033)

Sections refer to [RFC 2033](https://datatracker.ietf.org/doc/html/rfc2033).
This audits the LMTP differences from ESMTP, including the §4.2 example
addresses, message and mixed results. Existing SMTP, PIPELINING, DATA and
CHUNKING parser tests/fuzzers apply to the shared machinery. LMTP introduces
no separate parser. Successful delivery is a host promise: transport success
alone does not prove durable storage. The client API returns collected results
when CloseWithLMTPResponse finishes; it does not expose a streaming callback.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| LMTP-HELLO-01 | 4.1 | Normative | LHLO replaces EHLO, has its extension semantics and requires a domain; MAIL requires a successful greeting. | `TestRFC2033GreetingAndSequence` |
| LMTP-HELLO-02 | 4.1 | MUST NOT | An LMTP server must not accept HELO or EHLO (500 recommended); SMTP refuses LHLO to detect configuration mistakes. | `TestRFC2033GreetingAndSequence` |
| LMTP-HELLO-03 | 4.1 | Normative | The LMTP client uses LHLO and does not downgrade to SMTP HELO on a 500 or 502 refusal. | `TestRFC2033ClientNoSMTPFallback` |
| LMTP-DATA-01 | 4.2 | MUST | DATA without any successful RCPT fails with 503, including when all recipients were refused or a prior transaction has ended. | `TestRFC2033GreetingAndSequence`, `TestRFC2033RecipientReplies` |
| LMTP-DATA-02 | 4.2 | Normative | After the final dot, issue exactly one reply per successful RCPT, in original RCPT order, with no aggregate reply or reply for refused recipients. | `TestRFC2033RecipientReplies` |
| LMTP-DATA-03 | 4.2 | Normative | Repeated successful RCPT commands for the same forward-path each receive their own reply. | `TestRFC2033RecipientReplies` |
| LMTP-DATA-04 | 4.2 | Normative | A multiline reply counts as one recipient reply. | `TestRFC2033RecipientReplies`, `TestRFC2033ClientPartialReplies` |
| LMTP-DATA-05 | 4.2 | Normative | A single-status backend or unset per-recipient status expands its result to every accepted RCPT. | `TestRFC2033FallbackAndUnsetStatuses` |
| LMTP-EXAMPLE-01 | 4.2 | Normative | The chris/pat/jones/green example rejects jones at RCPT, accepts pat at DATA and temporarily refuses green with 452. | `TestRFC2033RecipientReplies` |
| LMTP-BDAT-01 | 4.3 | Normative | BDAT LAST with accepted recipients returns one ordered reply for each accepted RCPT. | `TestRFC2033RecipientReplies`, `TestRFC2033BDATRecipientRepliesFlushed` |
| LMTP-BDAT-02 | 4.3 | Normative | Duplicate forward-paths and multiline replies retain per-RCPT counting for BDAT LAST. | `TestRFC2033RecipientReplies`, `TestRFC2033BDATRecipientRepliesFlushed` |
| LMTP-BDAT-03 | 4.3 | Normative | A non-LAST BDAT command returns exactly one reply. | `TestRFC2033RecipientReplies` |
| LMTP-BDAT-04 | 4.3 | Normative | BDAT LAST expands a fallback backend or unset status result to all accepted recipients. | `TestRFC2033FallbackAndUnsetStatuses`, `TestRFC2033BDATRecipientRepliesFlushed` |
| LMTP-BDAT-05 | 4.3 | Normative | BDAT LAST with no successful RCPT returns zero replies. | n/a: known gap: the shared SMTP handler drains the chunk and returns 503; LMTP does not yet override it. |
| LMTP-EXT-01 | 5 | MUST | The LMTP server implements and advertises PIPELINING. | `TestRFC2033GreetingAndSequence`, `TestRFC2033RecipientReplies` |
| LMTP-EXT-02 | 5 | MUST | The LMTP server implements and advertises ENHANCEDSTATUSCODES. | `TestRFC2033GreetingAndSequence`, `TestRFC2033RecipientReplies` |
| LMTP-EXT-03 | 5 | SHOULD | The LMTP server implements 8BITMIME. | `TestRFC2033GreetingAndSequence` |
| LMTP-BDAT-06 | 4.3 | Normative | Even failed LAST chunks report individual outcomes for accepted recipients. | n/a: known gap: early size-limit/backend/transport errors use the shared single-reply SMTP path rather than the normal LAST per-recipient result path. |
| LMTP-FLUSH-01 | 5 | SHOULD | Send each DATA recipient reply as soon as available, flushing before waiting for a slower recipient. | `TestServer_LMTP_Early` |
| LMTP-FLUSH-02 | 5 | SHOULD | Send BDAT LAST recipient replies as soon as available, flushing in RCPT order before waiting for slower recipients or the backend's return. | `TestRFC2033BDATRecipientRepliesFlushed` |
| LMTP-CLIENT-01 | 4.2, 5 | MUST | Preserve received recipient successes and failures when the connection closes before all replies arrive. | `TestRFC2033ClientPartialReplies` |
| LMTP-CLIENT-02 | 4.2 | Normative | The client consumes multiline replies as one response before matching the next recipient. | `TestRFC2033ClientPartialReplies`, `TestRFC2033ClientPositiveCompletion` |
| LMTP-CLIENT-03 | 5 | MUST | On disconnect treat recipients without replies as temporary failures. | n/a: known API gap: partial results and the transport error are returned, but no synthetic 4xx entry is added for unanswered recipients; caller must treat them as temporary failures. |
| LMTP-CLIENT-04 | 5 | SHOULD | Deliver received results to the caller as they arrive. | n/a: current synchronous API collects results until completion or failure; no per-reply callback. |
| LMTP-CLIENT-06 | 4, 4.2 | Normative | Classify every 2xx final recipient reply as positive completion. | `TestRFC2033ClientPositiveCompletion`, `TestRFC2033ClientClosePositiveCompletion`, `TestRFC2033ClientPartialReplies` |
| LMTP-CLIENT-05 | 4.2, 4.3 | Normative | Expose independent outcomes for duplicate accepted paths. | n/a: known API limitation: wire replies are consumed separately but result maps are keyed by address, so duplicate outcomes may collapse; use distinct transactions when each outcome must be retained. |
| LMTP-DURABLE-01 | 4.2, 4.3 | MUST NOT | After accepting responsibility, do not lose messages to host crashes or predictable resource shortages. | n/a: mandatory host duty: persist delivery or relay responsibility before returning nil or SetStatus(nil); the library has no durable spool. |
| LMTP-DEFAULT-01 | 5 | Normative | LMTP listen helpers default to a Unix-domain socket rather than the SMTP TCP network. | `TestRFC2033DefaultNetwork` |
| LMTP-DEPLOY-01 | 1, 5 | MUST NOT | Do not use LMTP on TCP port 25. | n/a: host must enforce this on supplied listeners and explicit Network/Addr; the default network is unix, tested by TestRFC2033DefaultNetwork. |
| LMTP-DEPLOY-02 | 1, 5 | SHOULD | Use LMTP only by prior arrangement, avoid wide-area networks and prefer SMTP for fast queueing receivers capable of notifications. | n/a: host deployment/topology decision; the library supports both protocols without choosing the receiver role. |


## Postfix XCLIENT: session state and trust boundaries

Source: [Postfix XCLIENT specification](https://www.postfix.org/XCLIENT_README.html)
([upstream source mirror](https://github.com/vdukhovni/postfix/blob/master/postfix/proto/XCLIENT_README.html)),
audited 2026-10-21. XCLIENT is **not an IETF RFC**. Section names below refer
to headings in that document. This slice verifies session/transaction state,
trust, pipelining and the published conversation. Attribute-value validation
and xtext decoding are still incomplete; HELO/PROTO are retained as metadata
rather than effective protocol state. The rows below record those gaps
rather than claiming complete Postfix compatibility. Existing acceptance of
legacy unencoded values (including Unicode whitespace as value content) is
unchanged. The shared SMTP token parsers and their fuzz targets are unchanged.
Rows marked "Library integration" or "Library safeguard" describe this API
and its safety guarantees, rather than extra Postfix protocol requirements.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| XC-EHLO-01 | Command syntax | Normative | EHLO advertises XCLIENT with the supported identity fields ADDR, NAME, PROTO, HELO and LOGIN only to authorized peers. | `TestXClientTrustConfiguration` |
| XC-SYNTAX-01 | Command syntax | Normative | Commands/attribute names are case-insensitive and at least one name=value pair is required. | `TestXClientRejectedCommandIsAtomic`, `TestXClientReplacesSession` |
| XC-SYNTAX-02 | Command syntax; reply codes | Normative | Malformed fields and unknown attributes receive 501. | `TestXClientRejectedCommandIsAtomic` |
| XC-SYNTAX-03 | Command syntax | Normative | Attribute values use RFC 1891 xtext encoding. | n/a: not supported yet: values remain literal, so +HH is not decoded; legacy unencoded values are accepted as before. A separate syntax/parser slice must add decoding and fuzz coverage. |
| XC-SYNTAX-04 | Command syntax (NAME) | Normative | NAME denotes a hostname, [UNAVAILABLE] or [TEMPUNAVAIL]. | n/a: not supported yet: NAME is exposed literally without hostname/sentinel validation; sentinel spellings and meaning are the host's responsibility. |
| XC-SYNTAX-05 | Command syntax (ADDR) | Normative | ADDR is IPv4, IPv6 prefixed IPV6:, or [UNAVAILABLE], without surrounding address brackets. | n/a: not supported yet: ADDR is exposed literally without address validation or prefix/sentinel normalization; the host must validate before use. |
| XC-SYNTAX-06 | Command syntax (PROTO) | Normative | PROTO specifies SMTP or ESMTP. | n/a: not supported yet: the value is exposed literally without restricting its grammar; it does not switch this connection's SMTP/LMTP mode. |
| XC-SYNTAX-07 | Command syntax (HELO) | Normative | HELO carries the original client's HELO argument or [UNAVAILABLE]. | n/a: not supported yet: the value is retained as metadata without argument/sentinel validation or normalization. |
| XC-SYNTAX-08 | Command syntax (LOGIN) | Normative | LOGIN carries a SASL login or [UNAVAILABLE]. | n/a: host defines the identity mapping and unavailable sentinel policy; XClient().Login is metadata and does not authenticate a Session automatically. |
| XC-SYNTAX-09 | Command syntax (PORT, DESTADDR, DESTPORT) | Normative | Port and destination attributes carry their specified address/decimal/sentinel values. | n/a: not supported yet: accepted for legacy compatibility but neither advertised nor surfaced; full validation and API support remain future work. |
| XC-SYNTAX-10 | Command syntax, notes 1-2 | Normative | NAME/HELO allow 255 characters; sentinel and IPV6: spellings are case-insensitive. | n/a: not supported yet: no per-attribute length validation or sentinel normalization; callers interpret literal fields. |
| XC-SYNTAX-11 | Command syntax, note 1 | MUST NOT | The sender must not exceed the 512-character SMTP command limit and should split assertions across commands. | n/a: no XCLIENT client API; external proxy must observe 512 octets including CRLF. Server uses its configurable MaxLineLength (default 2000), not a specific XCLIENT 512-octet limit. |
| XC-ORDER-01 | Command syntax; reply codes | MUST NOT | XCLIENT is refused with 503 between successful MAIL and completion or RSET, including after RCPT and between BDAT chunks; refusal leaves delivery intact. | `TestXClientRefusedDuringTransaction` |
| XC-ORDER-02 | Command syntax | MAY | XCLIENT can be pipelined with PIPELINING; responses retain command order and the client should put XCLIENT last in a group. | `TestXClientPipelinedExample` |
| XC-STATE-01 | Server response | Normative | A successful XCLIENT returns a fresh 220 and resets the protocol to the initial greeting stage (see XC-STATE-07 for the effective HELO/PROTO gap). | `TestXClientReplacesSession`, `TestXClientPipelinedExample` |
| XC-STATE-02 | Library integration | Normative | Backend session/authentication state belongs to the old identity: close that session and create a new one on the next greeting. | `TestXClientReplacesSession`, `TestXClientPreservesTLS` |
| XC-STATE-03 | Server response | MUST NOT | Keep the most recent asserted attributes, including HELO and PROTO, across the protocol reset. | `TestXClientReplacesSession`, `TestXClientRefusedDuringTransaction`, `TestXClientPipelinedExample` |
| XC-STATE-04 | Library integration | Normative | Old SMTP authentication must not authenticate a newly asserted client; it can authenticate after a new greeting. | `TestXClientReplacesSession` |
| XC-STATE-05 | Library safeguard | Normative | Deliver accumulated identity attributes to the new backend; preserve identity snapshots already given to previous sessions. | `TestXClientReplacesSession` |
| XC-STATE-06 | Library safeguard | Normative | A command refused with 501 does not partially update identity, greeting, authentication or backend session state. | `TestXClientRejectedCommandIsAtomic` |
| XC-STATE-07 | Server response | MUST NOT | Preserve the effective HELO/PROTO attributes supplied with XCLIENT. | n/a: partial support: XClient().Helo/Proto survive as metadata, but Hostname is cleared and a fresh HELO/EHLO is required to create the replacement backend. Unlike Postfix, an asserted HELO does not itself satisfy the greeting requirement and PROTO does not select effective protocol state. |
| XC-TLS-01 | Server response | MUST NOT | Keep the negotiated TLS session and do not advertise STARTTLS over an already encrypted connection. | `TestXClientPreservesTLS` |
| XC-TLS-02 | Server response | MAY | Client-certificate information can affect access decisions after XCLIENT. | n/a: host policy via TrustXCLIENT and Backend.NewSession using TLSConnectionState; this slice verifies TLS retention rather than certificate access rules. |
| XC-SEC-01 | Security; reply codes | MUST | Only authorized peers may assert identity; disabled extension, missing callback and trust refusal get 550. | `TestXClientTrustConfiguration`, `TestXClientTrustRechecked` |
| XC-SEC-02 | Command syntax, note 1; Security | Normative | Re-evaluate authorization when advertising or accepting XCLIENT; host policy can revoke access after identity is asserted. | `TestXClientTrustRechecked` |
| XC-SEC-03 | Purpose; Security | Normative | Asserted attributes can change access permissions, logging and audit trails. | n/a: host must implement those decisions in TrustXCLIENT and the replacement Backend.NewSession; RemoteAddr remains the real transport peer, and enabling XCLIENT alone does not change relay permissions or trust policy. |
| XC-REPLY-01 | Server response; reply codes | Normative | Connection-level access policy may reject the asserted identity with an appropriate code, including 421/disconnect when unable to continue. | n/a: no immediate per-XCLIENT backend rejection hook; the fresh Backend.NewSession runs after HELO/EHLO and may return an SMTPError (including a terminating 421), so pre-220 access rejection is not supported yet. |
| XC-CACHE-01 | SMTP connection caching | Normative | Attributes persist across deliveries, ordinary RSET and EHLO; cached-connection users must reset them when changing clients. | `TestXClientReplacesSession`, `TestXClientPipelinedExample` |
| XC-EXAMPLE-01 | XCLIENT Example | Normative | The published EHLO, NAME/ADDR assertion, fresh greeting, EHLO, MAIL, RCPT, DATA and QUIT conversation succeeds. | `TestXClientRefusedDuringTransaction`, `TestXClientPipelinedExample` |

## Submission authentication (RFC 6409 §§3.2, 4.3, 7)

This slice checks [RFC 6409 §4.3](https://datatracker.ietf.org/doc/html/rfc6409#section-4.3)'s
authentication-required error and recovery,
not full RFC 6409 conformance. The generic server also handles relay: merely
listening on port 587 does not enable submission policy. A submission backend
must authorize `Mail` using its successful AUTH state or independent trusted
credentials, returning `ErrAuthRequired` otherwise. `AllowInsecureAuth` controls
whether AUTH is allowed over plaintext; it does not require authentication.
The tests use a backend with that policy and a plaintext in-memory pipe.

| ID | Section | Level | Requirement | Tests |
|----|---------|-------|-------------|-------|
| SUB-AUTH-01 | RFC 6409 §4.3 | Normative | Authentication-required MAIL rejection uses 530; failed MAIL leaves no transaction and successful AUTH permits retry. | `TestRFC6409SubmissionAuthentication` |
| SUB-AUTH-02 | RFC 6409 §4.3 | MUST | By default, reject unauthenticated MAIL unless independent authentication or authorization is established. | n/a: host policy; the generic relay/submission server has no submission mode. Backends must enforce this in Mail; the test backend demonstrates the contract, not automatic enforcement. |
| SUB-AUTH-03 | RFC 6409 §§4.3, 7 | MUST | Submission supports AUTH; independently authorized sessions may submit without it. DATA and BDAT use the same authorized envelope. | `TestRFC6409SubmissionAuthentication` |
| SUB-NULL-01 | RFC 6409 §3.2 | MUST NOT | A null reverse path alone does not cause submission rejection. | `TestRFC6409SubmissionAuthentication` |

Remaining RFC 6409 audit: port selection, return-path determination, domain and
header validation, rejection policy, logging, timeouts, extension applicability,
message modifications and delivery/relay responsibilities. No header rewriting,
DNS qualification or submission-specific policy is supplied by this change.
