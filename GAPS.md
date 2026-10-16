# Gaps against Go Coraza

Found at `6b073b5`, comparing with Go Coraza at `3fc3ae2` (2026-10-14) and with OWASP CRS v4.30.0 (`e03a4f6`), the CRS
version Go Coraza's regression tests run. Items marked **(measured)** come from loading Go Coraza's
`coraza.conf-recommended`, CRS's `crs-setup.conf.example` and `rules/*.conf` with `Parser::skip_failed_directives()`:
93 directives were skipped. The rest come from comparing the names Go registers with ours, or from reading the code.

Detection is not a gap: on the 335,284 inputs of libinjection's sample files (decoded and raw), libperfusion gives the
same SQLi verdicts and fingerprints as libinjection-go v0.3.4, the version Go Coraza pins, and flags 32 more XSS inputs,
none fewer.

Suggested order: 1 → 2 → 3 → 6, then 4 and 5. The first three items of 1 account for 80 of the 93 skipped directives.

## 1. CRS rules dropped at load (measured)

- [x] **Find data files next to the config that names them.** 20 rules are dropped because `@pmFromFile` can't find
  CRS's `.data` files.
  - `PmFromFile::read_file_with_fallback` (`src/operators/pattern.rs:255`) tries the working directory, then
    hard-coded guesses (`../coraza-coreruleset/rules/@owasp_crs`, `/etc/coraza/rules`, …). `@ipMatchFromFile` tries
    only the working directory (`src/operators/ip.rs:202`).
  - Go hands each operator the directory of the file being parsed (`internal/seclang/rule_parser.go:193`).
  - Done: `OperatorEnum::with_context` takes an `OperatorContext` whose `base_dir` the parser sets to the
    directory of the rule's file; `@pmFromFile` and `@ipMatchFromFile` resolve a relative path against it, as Go
    does, and the hard-coded guesses are gone. Outside the parser (`OperatorEnum::new`, `compile_sec_rule`), a
    relative path stays relative to the working directory. The CRS load check now skips 73 directives.
- [x] **Negated variables inside a rule.** Found while working on the next item: `!ARGS:id` became a variable of its
  own that selected `id` and then excluded it, so it matched nothing, while the rule's `ARGS` still inspected `id`.
  CRS's own exclusions, such as `REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/` on 941100, had no effect.
  - Done: a negated element excludes its key from the collection's earlier variables in the list, as Go's
    `AddVariableNegation` does; one without a key is a compile error.
- [x] **`SecRuleUpdateTargetById` and `SecRuleUpdateTargetByTag`.** 55 skipped: all of CRS's false-positive
  exclusions in `REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf`, such as `!REQUEST_COOKIES:/^_ga(?:_\w+)?$/` on 941100.
  - These add targets or exclusions to a rule. `WafBuilder::update_rule_variables_by_id` (`src/waf.rs:436`) replaces
    the rule's variables, so it doesn't fit as it is.
  - Done: both apply the variable list to each matching rule's own variables, as if appended to them, through the
    same `VariableList` the rule compiler uses. Ids and inclusive ranges can be mixed; a single id must name an
    existing rule. Unlike Go, which returns after the first single id, every listed id and range is updated.
    ModSecurity's third argument (a target to replace) is not supported, as in Go. The CRS load check now skips 18
    directives.
- [x] **`SecDefaultAction`, and a `block` that follows it.** 5 skipped: the `phase:N,log,auditlog,pass` defaults of
  `crs-setup.conf.example`.
  - `block` always denies with 403 (`src/actions/disruptive.rs:179`). `WafBuilder::set_default_actions` stores
    actions that rule evaluation never reads: only tests call `Waf::get_default_actions` (`src/waf.rs:209`).
  - So the first CRS rule that matches denies the request, rather than adding to the anomaly score that 949110
    compares with the threshold. This is from reading the code; not probed.
  - Done: `SecDefaultAction` is parsed and validated as in Go (a phase and a disruptive action; no metadata
    actions or `t:`; one per phase). Each rule compiled after it merges its actions with its phase's defaults: the
    defaults' other actions first, then the rule's own but `block`, then the defaults' disruptive action if the rule
    has no other. Phase 2 has Go's built-in `log,auditlog,pass` until set. A `block` left in a rule (a phase without
    defaults) does nothing at runtime, as in Go. `WafBuilder::set_default_actions` and `Waf::get_default_actions`
    are removed. With CRS loaded, a scratch probe now sees a benign request pass and two attacks denied by 949110;
    the load check skips 13 directives.
- [x] **Variables `ARGUMENTS_LIMIT_REACHED`, `URI_PARSE_ERROR` and `MULTIPART_DUPLICATE_PART_HEADER`.** 4 skipped:
  Coraza's own rules 200003 (`MULTIPART_STRICT_ERROR`, which names the last one in its `logdata`), 200004, 200005
  and 200009 in `coraza.conf-recommended`.
  - Done: the three variables exist, start at `0` as in Go, and are set by the engine.
    - `SecArgumentsLimit` was never enforced. `Transaction::add_get_argument`, `add_post_argument` and
      `add_response_argument` now drop an argument once its collection holds the limit's worth of values (each
      value of a repeated key counts, as in Go) and set `ARGUMENTS_LIMIT_REACHED`. Every body processor goes through
      them, which also puts JSON and multipart arguments in `ARGS`: before, only urlencoded ones got there.
    - `URI_PARSE_ERROR` is set for a URI that Go's `url.ParseRequestURI` would reject: control characters, invalid
      `%`-escapes in the path, or neither `*`, an absolute path nor an absolute URL. Host validation is not
      replicated.
    - A multipart part that repeats a header or a `Content-Disposition` parameter sets
      `MULTIPART_DUPLICATE_PART_HEADER` and `MULTIPART_STRICT_ERROR`, as in Go.
    - The CRS load check now skips 9 directives.
- [x] **Transformation `removeCommentsChar`.** 1 skipped: 942190.
  - Done: ported from Go, with its test vectors; it removes the markers `/*`, `*/`, `<!--`, `-->`, `--` and `#` and
    keeps what they enclose. The CRS load check now skips 8 directives.
- [x] **Configuration directives.** 8 skipped: `SecAuditLogFormat`, `SecAuditLogParts`, `SecAuditLogType`,
  `SecAuditLogRelevantStatus`, `SecRxPreFilter`, `SecRequestBodyJsonDepthLimit`, `SecResponseBodyJsonDepthLimit`
  and `SecResponseBodyMimeType`.
  - Done: all eight are validated as in Go and set `WafConfig`. Transactions now share their WAF's
    `Arc<WafConfig>`, which carries the settings below to them.
    - `SecResponseBodyMimeType`: the response body is stored and inspected only for a listed content type (none by
      default, as in Go) or with `ctl:forceResponseBodyVariable`; `Transaction::is_response_body_processable` tells
      a connector which.
    - `SecRequestBodyJsonDepthLimit`/`SecResponseBodyJsonDepthLimit`: a deeper JSON body is a body error. serde_json
      still rejects nesting past 128, whatever the limit.
    - `SecAuditLogFormat`, `SecAuditLogParts`, `SecAuditLogType`, `SecAuditLogRelevantStatus`: stored for the
      embedder, as the library writes no audit log (see section 4).
    - `SecRxPreFilter`: checked, and has no effect. In Go it only speeds `@rx` up, which the regex engine here does
      on its own.
    - The CRS load check now skips nothing.

## 2. Accepted but ignored

- [x] **`ctl` commands that do nothing.** `requestBodyProcessor`, `responseBodyProcessor`, `auditEngine`,
  `auditLogParts`, `debugLogLevel`, `hashEngine` and `hashEnforcement` parse to `CtlCommand::NotImplemented`
  (`src/actions/ctl.rs:81`-`96`).
  - The body parser is chosen by a prefix match on `Content-Type` instead. So rule 200006 of
    `coraza.conf-recommended`, which sends `application/*+json` bodies to the JSON parser, has no effect.
  - Done for `requestBodyProcessor` and `responseBodyProcessor`. As in Go, `REQBODY_PROCESSOR` decides which
    processor parses the request body: the first `Content-Type` sets it to `URLENCODED` or `MULTIPART`, and
    `ctl:requestBodyProcessor` to any processor until the request body phase. JSON and XML are no longer chosen by
    content type alone. `ctl:forceRequestBodyVariable` falls back to `URLENCODED`. `ctl:responseBodyProcessor`
    sets `RESBODY_PROCESSOR`, whose processor then parses the response body instead of storing it in
    `RESPONSE_BODY`. A processor failing sets `REQBODY_ERROR`, `REQBODY_PROCESSOR_ERROR` and their messages, or
    the `RESBODY_*` ones. Unlike Go, an unknown processor name is a compile error.
  - Done for the rest: `auditEngine`, `auditLogParts` and `debugLogLevel` change the transaction's own copy of
    the WAF's setting. The first two decide the transaction's audit log entry; the library writes no debug log, so
    an embedder's logger reads the level with `Transaction::debug_log_level`. `hashEngine` and `hashEnforcement`
    have no effect, as in Go ("not supported yet"). A transaction now takes all its `ctl`-changeable settings from
    the WAF in one place.
- [x] **`SecRequestBodyAccess` and `SecResponseBodyAccess` are not enforced.** Found while working on 1.6: bodies are
  stored and processed whatever the setting, while Go skips them (and defaults both to `Off`, as `WafConfig` does).
  - Done: as in Go, a request body is stored and parsed only with request body access and when not empty, and a
    response body only with response body access and a processable content type; the phase's rules run either way.

- [x] **Body limits are not enforced.** Found while working on section 3: `SecRequestBodyLimit`,
  `SecResponseBodyLimit` and their `…LimitAction` were stored and ignored, and `WafConfig` defaulted the response
  action to `Reject` where Go has `ProcessPartial`.
  - Done: as in Go, a body that reaches its limit sets `INBOUND_DATA_ERROR` or `OUTBOUND_DATA_ERROR`; `Reject` then
    interrupts the transaction (413 for a request, 500 for a response, outside any rule) before that phase's rules,
    and `ProcessPartial` inspects only the first `limit` bytes. Go counts a body exactly at the limit as reaching
    it, and so does this.
- [x] **`SecUploadFileLimit` and `SecUploadFileMode` are not enforced.** Both are parsed into `WafConfig`
  (`upload_file_limit`, `upload_file_mode`), and nothing reads them: a multipart body stores any number of files in
  `SecUploadDir`, and `MULTIPART_FILE_LIMIT_EXCEEDED` is never set.
  - Not a gap: Go parses both and enforces neither (its `SecUploadFileLimit` is "parsed but not yet enforced", see
    corazawaf/coraza#1686). Uploads are now stored as Go's `os.CreateTemp` stores them, with mode 0600 and never
    replacing an existing file, where they had the umask's default mode.

## 3. Variables that parse but are never set

Found while working on 1.4: the list in 5 compared only names. 65 variables parse, but `Transaction::collection`
(`variable_storage!` in `src/transaction/mod.rs`) maps them to nothing, so a rule on them never matches and a macro
naming them expands to nothing. CRS v4.30.0 uses the ones below.

- [x] **`REQUEST_URI` held only the path.** Go and ModSecurity keep the query string (`/search?q=1`); every CRS rule
  on `REQUEST_URI` saw less than it should.
  - Done: `REQUEST_URI` is the request URI without its fragment.
- [x] **`XML`.** 354 uses, as `XML:/*` and `XML://@*` in most request rules. In Go it is the same collection as
  `REQUEST_XML`, which the XML body processor fills.
  - Done: `XML` reads `REQUEST_XML`.
- [x] **`MATCHED_VAR`, `MATCHED_VAR_NAME`, `MATCHED_VARS` and `MATCHED_VARS_NAMES`.** Mostly in `logdata`, but 13
  chained rules inspect `MATCHED_VAR(S)`.
  - Done: as in Go, each value a rule or chain link matches sets `MATCHED_VAR` and `MATCHED_VAR_NAME` (`ARGS:id`)
    and joins `MATCHED_VARS` before the rule's actions run; `MATCHED_VARS` is emptied before each rule, so a chain
    sees its parent's matches. `MATCHED_VARS_NAMES` is the keys of `MATCHED_VARS`, through a new names view
    (`VariableCollection::Names`) that the next item reuses.
- [x] **The names variables:** `ARGS_NAMES` (190 uses), `REQUEST_COOKIES_NAMES` (165), `REQUEST_HEADERS_NAMES`,
  `ARGS_GET_NAMES`, and the unused `ARGS_POST_NAMES` and `RESPONSE_HEADERS_NAMES`.
  - Done: each is a names view of the collection it names, read on demand, so it can't fall out of step.
- [x] **`REQBODY_PROCESSOR`, `ARGS_COMBINED_SIZE`, `UNIQUE_ID` and `MULTIPART_INVALID_QUOTING`.** `REQBODY_PROCESSOR`
  is done, with the `ctl` body processors in section 2.
  - Done for the rest: `UNIQUE_ID` is the transaction id; `ARGS_COMBINED_SIZE` the bytes in the keys and values
    of `ARGS_GET` and `ARGS_POST`, computed as each phase's rules start; `MULTIPART_INVALID_QUOTING` (and
    `MULTIPART_STRICT_ERROR`) flags a quoted `filename*`, as in Go.
  - `REQBODY_PROCESSOR` drives 901340/901350 and three 920 rules.
  - `UNIQUE_ID` drives CRS's sampling (901450).
- [x] **The rest, which CRS doesn't use.**
  - `ARGS_PATH`, `AUTH_TYPE`, `DURATION`, `ENV`, `FILES_TMP_CONTENT`, `FULL_REQUEST`, `FULL_REQUEST_LENGTH`, `GEO`,
    `HIGHEST_SEVERITY`, `INBOUND_DATA_ERROR`, `IP`, `JSON`, `OUTBOUND_DATA_ERROR`, `PATH_INFO`, `REMOTE_HOST`, `RULE`,
    `SESSIONID`, `STATUS_LINE`, `URLENCODED_ERROR`, `USERID`.
  - The other `MULTIPART_*` flags and `MULTIPART_FILENAME`/`MULTIPART_NAME`.
  - `REQBODY_PROCESSOR_ERROR(_MSG)` and `RESBODY_*` are done, with the `ctl` body processors in section 2.
  - `TIME` and the `TIME_*` parts.
  - Done for `ENV`: `setenv` sets it. Unlike Go, it no longer sets the process environment too: that is undefined
    behaviour while other threads may read the environment, and its `unsafe` block claimed it was sound because
    Go does it.
  - Done for `RULE`, `HIGHEST_SEVERITY` and `TIME*`, as in Go: `RULE` describes each rule as it is evaluated,
    `HIGHEST_SEVERITY` starts at 255 and follows matching rules' severities, and the `TIME*` variables hold when
    the transaction started, in UTC where Go uses local time. `URLENCODED_ERROR`, `FULL_REQUEST_LENGTH`,
    `DURATION`, `MULTIPART_DATA_AFTER` and `OUTBOUND_DATA_ERROR` are `0`, as Go sets them and (but for the last)
    never changes them.
  - Done for `ARGS_PATH`, `MULTIPART_NAME` and `MULTIPART_FILENAME`: `Transaction::add_path_argument` (Go's
    `AddPathRequestArgument`) adds to `ARGS_PATH` and `ARGS` within the argument limit, and the multipart processor
    records each part's name and file name.
  - Done for `INBOUND_DATA_ERROR` and `OUTBOUND_DATA_ERROR`, with the body limits in section 2.
  - What remains is what Go doesn't set either, so a rule on it never matches in Go too: `AUTH_TYPE`,
    `FILES_TMP_CONTENT`, `FULL_REQUEST`, `GEO` (for `@geoLookup`, section 5), `IP`, `JSON`, `PATH_INFO`,
    `REMOTE_HOST`, `SESSIONID`, `STATUS_LINE`, `USERID`, and the `MULTIPART_*` flags other than those above.

## 4. Other missing directives

Go Coraza has 69 `Sec*` directives; we have 26. Section 1 covers 11 of the 43 missing.

- [x] **The other directives that do something in Go.**
  - `SecRuleRemoveById`, `SecRuleRemoveByMsg`, `SecRuleRemoveByTag`. `RuleGroup::delete_by_*`
    (`src/rules/group.rs:139`-`200`) already does the work.
  - `SecRuleUpdateActionById`.
  - `SecDebugLog`.
  - `SecDataset`, which `@pmFromDataset` and `@ipMatchFromDataset` need.
  - `SecAuditLogDirMode`, `SecAuditLogFileMode`, `SecAuditLogStorageDir`.
  - `SecIgnoreRuleCompilationErrors`, `SecRemoteRulesFailAction`, `SecResponseBodyMimeTypesClear`.
  - Done for `SecRuleRemoveById` (ids and ranges), `SecRuleRemoveByMsg`, `SecRuleRemoveByTag` and
    `SecRuleUpdateActionById`, which applies its actions to existing rules without the `SecDefaultAction` defaults,
    a disruptive one replacing the rule's. As for `SecRuleUpdateTargetById`, every listed id is updated, where Go
    stops after the first single one.
  - Done for `SecDataset`, with the `@pmFromDataset` and `@ipMatchFromDataset` operators of section 5 that read
    its datasets through `OperatorContext::datasets`.
  - Done for the rest. `SecDebugLog`, `SecAuditLogDirMode`, `SecAuditLogFileMode` and `SecAuditLogStorageDir`
    set `WafConfig` for the embedder. `SecResponseBodyMimeTypesClear` empties the response content types; the parser
    now knows which directives take no argument. `SecRemoteRulesFailAction` is checked and has no effect, as
    `SecRemoteRules` isn't supported here or in Go. `SecIgnoreRuleCompilationErrors On` skips later failing
    directives, as `Parser::skip_failed_directives` does, where Go records it and doesn't act on it.
- [x] **Accept the directives Go accepts and ignores,** so configs written for Go Coraza load: `SecArgumentSeparator`,
  `SecConnEngine`, `SecConnReadStateLimit`, `SecConnWriteStateLimit`, `SecCookieFormat`, `SecGsbLookupDb`,
  `SecHashEngine`, `SecHashKey`, `SecHashMethodPm`, `SecHashMethodRx`, `SecHashParam`, `SecHttpBlKey`,
  `SecPcreMatchLimit`, `SecPcreMatchLimitRecursion`, `SecRulePerfTime`, `SecRuleScript`, `SecRuleUpdateTargetByMsg`,
  `SecTmpDir` and `SecUnicodeMap`. In Go, `SecRemoteRules` is an error ("not implemented").
  - Done: they are accepted with any argument and ignored, and `SecRemoteRules` fails with "not supported". The
    parser now knows all 69 of Go's directives.
- [x] **Audit logging.** Found while working on 1.6: Go writes audit logs itself, in its `Native`, `JSON`,
  `JSONLegacy` and `OCSF` formats, to `Serial`, `Concurrent`, `HTTPS` and `Syslog` writers. The library writes none;
  `examples/ftw_server*.rs` write their own.
  - Done for Go's error log line: `MatchedRule` now records the rule (with its file, line, raw text and
    `accuracy`), every value it and its chain matched with `msg` and `logdata` expanded for it, and its disruptive
    action; `MatchedRule::error_log` writes the line Go writes, which the async FTW example now logs for each rule
    with `log`. Parsing counts lines from 1 in each file, where included files used to continue the count.
  - Done for the audit log itself: `Transaction::audit_log` builds the entry as Go's `AuditLog()` does, in the
    parts `SecAuditLogParts` or `ctl:auditLogParts` give; `process_logging` writes it with `SecAuditEngine On`, or
    `RelevantOnly` as Go decides, and returns write errors where Go logs them. Formats `Native`, `JSON` and
    `JSONLegacy`; writers `Serial` (including `/dev/stdout` and `/dev/stderr`) and `Concurrent`, opened when the
    WAF is built. Timestamps are in UTC. `HTTPS` is refused when the WAF is built, as it needs an HTTP client with
    TLS that no dependency provides.
  - Done for the rest: the `OCSF` format, built as Go fills in OCSF 1.2.0's Web Resources Activity event (checked
    against Go's output for a sample entry), with the transaction's real highest severity where Go always writes
    `emergency`; and the `Syslog` writer, framed as Go's `log/syslog` does, over UDP, TCP, a Unix socket or the
    local syslog. Only `HTTPS` remains unsupported.

## 5. Operators, actions and names

None of these is used by CRS v4.30.0.

- [ ] **Operators:** `@geoLookup`, `@inspectFile`, `@ipMatchFromDataset`, `@pmFromDataset`, `@rbl`, `@restpath`,
  `@validateNid` and `@validateSchema`.
  - `@ipMatchFromDataset` and `@pmFromDataset` are done, with `SecDataset` in section 4.
  - Done for `@geoLookup` (which, as in Go, matches unconditionally), `@inspectFile` (runs a program, as Go does,
    with its 10 s timeout), `@rbl` (500 ms DNS lookup; unlike Go, no TXT record is read, as the standard library
    resolves addresses only), `@restpath` (fills `ARGS_PATH`) and `@validateNid` (`cl` and `us`, with Go's test
    vectors).
  - Left: `@validateSchema`, which needs a JSON Schema validator. Go uses `kaptinlin/jsonschema`; a Rust one would
    be a new dependency, which is your call.
- [x] **Action:** `accuracy`.
  - Done with the error log line of section 4, which prints it.
- [x] **Variables:** `MULTIPART_FILENAME_CHARSET` and `MULTIPART_FILENAME_LANGUAGE`.
  - Done: as in Go, a part's RFC 5987 `filename*=charset'language'value` gives its file name, percent-decoded,
    with `filename` kept in `MULTIPART_FILENAME` when different, and its charset and language in these two
    variables; a malformed one sets `MULTIPART_STRICT_ERROR`. `filename*` was ignored before.
- [x] **Go's spellings.**
  - `RES_BODY_ERROR`, `RES_BODY_ERROR_MSG`, `RES_BODY_PROCESSOR`, `RES_BODY_PROCESSOR_ERROR` and
    `RES_BODY_PROCESSOR_ERROR_MSG`: ours were `RESBODY_*`.
  - `FILES_TMPNAMES`: ours was `FILES_TMP_NAMES`.
  - Done: the variables now have Go's names; the old ones, which neither Go nor ModSecurity uses, are gone.
  - Correction: `t:normalisePath` and `t:normalisePathWin` were listed here by mistake. Both spellings were already
    accepted (`transformations::by_name`); the comparison that produced this list read only the first name of each
    `match` arm.

## 6. Measure

- [x] **Load CRS with nothing skipped.** Re-run the load check above until `Parser::skipped()` is empty.
  - Done: CRS v4.30.0 with Go's `coraza.conf-recommended` and `crs-setup.conf.example` loads with nothing
    skipped (709 `SecRule`/`SecAction` directives), as of 1.6; checked again at `420abaf`.
- [x] **Undefined behaviour in transformations.** Found while setting up the FTW run, which it stopped: the FTW
  server died on a JSON request. `t:urlDecode` (and the argument parsing that uses it), `t:hexDecode`,
  `t:base64Decode(Ext)`, `t:md5` and `t:sha1` turned bytes that aren't UTF-8 into `&str` without checking, in
  `unsafe` blocks whose comments said the bytes might not be UTF-8. Plain traffic triggers it (`t:base64Decode` on
  `bar`).
  - Done: they now replace invalid sequences with U+FFFD (`transformations::text_from_bytes`), and the unsafe
    `utils::strings::wrap_unsafe` is removed.
- [x] **Values are text, so bytes are lost.** Go Coraza's values are bytes. Here, what a transformation produces
  that isn't UTF-8 becomes U+FFFD, so `t:sha1,t:hexEncode` (CRS 901320 and 901410) and `t:md5,t:hexEncode` don't
  give the digest in hex, and `%ff` doesn't stay one byte. A fix would carry bytes through a rule's transformations
  and turn them into text only for the operator.
  - Done: transformations take and return bytes (`Transformation` is `fn(&[u8]) -> TransformationResult`), and a
    rule's chain turns its result into text once, for the operator. Those that read characters (`t:lowercase`,
    `t:uppercase`, `t:removeWhitespace`, `t:utf8toUnicode`) replace each byte that isn't part of one with U+FFFD,
    as Go does. `t:normalisePath` now cleans paths as Go's `path.Clean` does, on `/` whatever the platform, rather
    than with `path-clean`, which follows the platform's separators.
  - Go's transformation tests (`internal/transformations/testdata`, 348 cases for the transformations both have):
    333 passed before, 342 after. The 6 left are the next item.
  - Left: collection values are still text, so `?a=%ff` puts U+FFFD in `ARGS:a` where Go keeps the byte; operators
    see the U+FFFD too.
- [x] **Transformations behind Go's current ones.** Found while porting the above. Go Coraza has since changed:
  - `t:urlDecodeUni`: `%uHHHH` outside full-width ASCII is mapped to its best-fit ASCII (`%u201c` is `"`, `%u00e9`
    is `e`, `unicode_bestfit.go`); ours keeps the low byte, as ModSecurity does. 4 of Go's tests.
  - `t:cssDecode`: an escape decodes to its whole code point in UTF-8 (`\123` is `ģ`); ours keeps the low byte, as
    ModSecurity does. 2 of Go's tests.
  - `t:normalisePathWin`: it strips an NTFS stream suffix (`file.txt::$DATA`) and trailing dots and spaces from each
    element, as Windows does when it opens the file.
  - `t:cmdLine`: it reports a change only when a byte changed (a lone space doesn't).
  - Done: all four as in Go; the best-fit table is Go's (`transformations/unicode_bestfit.rs`). `t:urlDecodeUni`
    also reports a change only when it decoded something, as Go does. Go's transformation tests: 348 of 348 pass;
    the 15 others name transformations neither implements (`parity*7bit`, `sqlHexDecode`).
- [x] **`@rx` and `@pm` compiled for every value.** Found while running the FTW tests, which took about half a
  second per request. Both used the regular expression or matcher built at load time only when called without a
  transaction, which rules never do.
  - Done: they use it whenever the pattern has no macro. CRS's 669 rules cost 464 ms on a plain `GET` before,
    under 1 ms after.
- [x] **`t:compressWhitespace` panicked on some non-ASCII values.** Found by the FTW tests: `?ssrf=acap://①②⑦.⓪.⓪.①`
  (934120-23) killed the server's task. The transformation took the bytes 0x85 and 0xA0 (Latin-1 whitespace) for
  whitespace even inside a character (`①` is `e2 91 a0`), and sliced the text there. `t:compressWhitespace` and
  `t:cmdLine` also turned each byte after it into a character of its own (`é` became `Ã©`).
  - Done: `t:compressWhitespace` reads characters, as Go Coraza now does; `t:cmdLine` copies bytes.
- [x] **Regex keys didn't match case-insensitive collections when written in uppercase.** Found by the FTW tests:
  922110 never fired (17 tests), as `TX:/MULTIPART_HEADERS_CONTENT_TYPES_*/` never matched the lowercase TX keys.
  Go lowercases a regex key's pattern unless the variable's keys are case-sensitive (`ARGS` and its kin).
  - Done: such a regex ignores case instead, for selecting and for excluding (`!REQUEST_HEADERS:/^X-/`). Unlike
    Go's lowercasing, this leaves escapes such as `\D` alone. Which variables have case-sensitive keys is now one
    method (`RuleVariable::has_case_sensitive_keys`), which the transaction's collections follow too.
- [x] **Multipart parameters were split on every `;`.** Found by the FTW tests: 920120 fired on 19 of its negative
  tests, whose part names hold HTML entities (`name="zzz&auml;&euml;zzz"`): the name was cut at the first `;`,
  leaving `"zzz&auml` with its opening quote.
  - Done: as in Go Coraza, a `;` inside a quoted string doesn't end the parameter, and a backslash escapes only
    RFC 2045's special characters, as Go's `mime` package unquotes (`"C:\dev\x.txt"` keeps its backslashes).
- [x] **`REQUEST_BODY` held every body.** Found by the FTW tests: the Java rules (944100 to 944210, about 30 tests)
  fired on XML bodies whose element and attribute names hold the strings they look for, through `REQUEST_BODY`.
  Go Coraza, like ModSecurity, sets `REQUEST_BODY` and `REQUEST_BODY_LENGTH` only in the URLENCODED and RAW body
  processors, so not for XML, JSON or multipart bodies; CRS forces URLENCODED (901340) for bodies without one.
  - Done: as in Go; `REQUEST_BODY_LENGTH` is `0` until then.
- [x] **`REQUEST_FILENAME` and `REQUEST_BASENAME` were not decoded.** Found by the FTW tests: CRS's "RCE in last
  path segment" tests (one in most of the 932xxx rules, about 30) send `/path/with/%3Bid`, which Go Coraza reads
  as `/path/with/;id`.
  - Done: as in Go, they hold the path of the URL `url.ParseRequestURI` reads, `%`-decoded (`+` stays), or the raw
    path when the URI doesn't parse (`URI_PARSE_ERROR`); an absolute URL's path is its own (`/a` for
    `http://host/a`), and a path ending with `/` is its own basename.
- [x] **Cookies without `=` were dropped.** Found by the FTW tests (933100-89, 941190-3, 942480-2): Go Coraza keeps
  `Cookie: 'msdasql'` as a cookie named `'msdasql'` with an empty value.
  - Done: cookies are parsed as Go does: a pair without `=` is a name; only control characters and spaces are
    trimmed (U+00A0 stays, as a backend keeps it); a bare `=` is skipped.
- [x] **`@rx` differed from Go's.** Found by the FTW tests: 942420 to 942432 (8 tests) spell `‘`, `’` and `´` by
  their UTF-8 bytes (`\x{e2}\x80[\x98\x99]`), which Go Coraza matches on bytes when the escapes spell bytes that
  aren't UTF-8; here they were characters (U+00E2...) and never matched. Go's default build also compiles every
  pattern in multiline mode (`(?sm)`), ours in `(?s)` only. And a group that didn't take part ended the capture,
  leaving the later `TX.N` unset, where Go sets it empty.
  - Done: all three as in Go. Go captures `TX.0` to `TX.8`; this keeps ModSecurity's `TX.0` to `TX.9`.
- [x] **`MULTIPART_PART_HEADERS` held two rebuilt headers.** Found by the FTW tests: 922120, which looks for the
  deprecated `Content-Transfer-Encoding`, never fired, as only `Content-Disposition` (rebuilt from the parsed name
  and file name) and `Content-Type` were listed.
  - Done: as in Go Coraza, every header of a part, `Name: value` with the name canonical (`Content-Type` for
    `CoNtEnT-TyPe`) and the value as sent.
- [x] **`ctl:ruleRemoveTarget*` had no effect.** Found by the FTW tests (941180-7): the removed targets were recorded
  in the transaction but no rule consulted them, so CRS 941010, which removes `REQUEST_FILENAME` from the XSS rules
  for plain paths, did nothing, nor would any exclusion written this way.
  - Done: as in Go Coraza, a rule (and its chain's links, under its id) leaves out the keys removed from it, also
    when counting (`&ARGS`). The key can be a `/regex/`, as in Go; names and patterns match whatever the key's case.
- [x] **`t:htmlEntityDecode` gave up on a value at its first problem.** Found by the FTW tests (941110-9,
  944150-22, 944151-22): the `htmlescape` crate rejects a whole value for one unterminated or unknown reference
  (`&lt;script&gt` ends without `;`), and knows HTML4's names only (`&lcub;` is HTML5), so nothing was decoded.
  - Done: references are decoded as Go Coraza decodes them, with Go's `html.UnescapeString`, ported with its table
    of HTML5 names (`transformations/html_entities.rs`); `htmlescape` is no longer a dependency. Go's
    transformation tests still pass in full.
- [x] **Run CRS v4.30.0's FTW tests and record the pass rate.** `ftw-runner/` drives
  `examples/ftw_server_async.rs`.
  - Go Coraza's CI runs all 5,260 tests (`testing/coreruleset`, go-ftw v2.5.0). It ignores 7 (`.ftw.yml`) and changes the expected
    result of 14 (`.ftw-overrides.yml`).
  - Done: the server now runs all four phases, answers `/reflect` as CRS's albedo backend, and writes Go Coraza's
    error log line for each matched rule with `log`, which go-ftw reads, as Go's CRS harness does. Headers reach the
    WAF as Go's `net/http` hands them over (canonical names; values need not be ASCII). The runner stops the server
    when tests fail (it was left running) and writes the failed tests' IDs with `--failed-out`.
  - Result at `136cb54` plus the header fix, with go-ftw v2.1.0 and the rules of Go's harness
    (`coraza.conf-recommended`, its test settings, `crs-setup.conf.example`, `rules/*.conf`): **5,185 of 5,231
    passed (99.1%)**, 46 failed. The first full run, at `ecca3df`, passed 5,053; the fixes recorded above in this
    section came from it.
    - 9 are tests Go's CI ignores (3) or overrides (6). Of the overridden, 4 meet Go's changed expectation;
      920290-1 doesn't (Go's own TODO), and 920430-8 needs a 505 that the server can't send.
    - 29 are the test server's: hyper rejects 28 request lines for their URI before the WAF sees them (a raw `<`,
      `>` or `"`, for instance), and rewrites 920100-16's absolute-form `http://localhost` with a path.
    - 8 are the engine's: 920250-1 to 4, 941310-1, 12 and 13, 944200-1, all bytes that aren't UTF-8 in arguments or
      bodies, the next item.
- [x] **Collection values are text.** Left from the bytes item above, and the FTW tests' last 8 failures of the
  engine: `?param=%c0%af` puts U+FFFD in `ARGS:param`, so `@validateUtf8Encoding` (920250) sees valid UTF-8, and a
  body's `\xbc` (941310) or Java's `\xac\xed` (944200) never reach the operators as bytes. Go's values are bytes.
  A fix would keep values as bytes in the collections, and give operators bytes (transformations already have
  them), turning them into text only for macros and logs. It touches the collections, the 32 operators, macros,
  `setvar` and the body processors.
  - Done: collections store their values as bytes (`Map` lends them out; its `get` and `entries` give text), a
    rule's chain hands its bytes to the operator unchanged, and operators take `&[u8]`. Those that read text do so
    through `transformations::text_of`, which replaces invalid sequences with U+FFFD only when there are some.
    Argument values from the query string, urlencoded and multipart bodies keep the bytes they decode to, and
    `@validateUtf8Encoding` checks them (it always returned false).
  - FTW at `4447016`: **5,193 of 5,231 passed (99.3%)**, 38 failed. The 8 above now pass; no other test changed.
  - Left: argument names are text (`?%ff=1` puts U+FFFD in `ARGS_NAMES`). Single-value variables are text, so
    `REQUEST_BODY` and `MATCHED_VAR` replace bytes that aren't UTF-8. A JSON body becomes text before it is parsed,
    so its values do too (whether Go's gjson keeps such bytes is unverified).
- [ ] **The FTW server's HTTP library rejects request lines Go's accepts.** 29 FTW tests never reach the WAF (above).
  Go's harness uses `net/http`. A server reading requests with `httparse`, already in the dependency tree through
  hyper, rather than hyper's strict `Uri`, would let them through; it would be an optional dependency of the
  `async-server` feature.

## 7. Body processing

Found at `ee1d995`, comparing with Go Coraza at `3fc3ae2`: by reading `internal/bodyprocessors` and
`internal/corazawaf/transaction.go`, and by feeding the same inputs to Go's `readXML` (copied out of
`internal/bodyprocessors/xml.go`) and to this crate through `Parser`.

- [x] **`RESPONSE_XML` is never set.** Not a gap: Go declares it but never writes it either, and its XML processor's
  `ProcessResponse` does nothing. As in Go, a response body with a processor (`ctl:responseBodyProcessor=XML`) is
  not kept in `RESPONSE_BODY` either.
- [x] **The XML processor reads XML differently from Go's.** `parse_xml` (`src/body_processors/xml.rs`) stops at its
  first error and never fails; Go's non-strict `encoding/xml` decoder fails on what it can't read, which sets
  `REQBODY_ERROR`, and reads some input quick-xml drops. 7 of 14 probe inputs differ:
  - Go fails where this crate keeps what it read before the error, without `REQBODY_ERROR`: invalid UTF-8, a NUL
    character, an end tag closing nothing open (`<a></b>`), an invalid name (`<1bad>`). Go then sets neither key of
    `REQUEST_XML`.
  - Go keeps what this crate drops: the value of an unquoted attribute (`<a attr=unquoted>`), a text node with an
    unknown entity (`&unknown; entity`, kept as written), every value of a repeated attribute (`b="1" b="2"`). A
    payload in any of these never reaches rules on `REQUEST_XML` or `XML`.
  - Done: the processor reads XML with a port of Go's decoder (`src/body_processors/xml/decoder.rs`), set up as Go
    Coraza sets it up, HTML 4's entities (`&copy;`) included, in place of quick-xml. Of 200,000 generated inputs, it
    reads each as Go Coraza's `readXML` does, and fails on the same ones, with the same message but for an invalid
    name that isn't UTF-8 (lossy here).
- [x] **`FILES` holds one of a file's two names.** For a part with both `filename` and `filename*` naming different
  files, Go adds both to `FILES` and `FILES_SIZES`, "so a rule catches whichever one a given backend actually
  resolves" (`TestMultipartFilenameStar`); this crate adds the `filename*` one, and the other only to
  `MULTIPART_FILENAME`. With `filename="evil.php"; filename*=UTF-8''benign.txt`, `FILES` holds `benign.txt`, so the
  CRS rules on `FILES` (920120, 920121, 933110, 933111, 933220, 944140) never see `evil.php`, which a backend reading
  `filename` stores.
  - Done: as in Go, the other name joins `FILES` and `FILES_SIZES` too.
- [x] **`FILES`, `FILES_NAMES` and `FILES_TMPNAMES` are keyed by the part's name.** Go adds each value under the key
  `""` (`filesCol.Add("", filename)`). CRS reads them whole, so only `MATCHED_VAR_NAME` differs (`FILES:upload` here,
  `FILES` in Go), and a rule selecting `FILES:upload` matches here but not in Go.
  - Done: as in Go, each value is under the key `""`.
- [x] **Uploads are stored and checked differently.**
  - Without `SecUploadDir`, Go stores each uploaded file in the system's temporary directory
    (`os.CreateTemp("", "crzmp*")`, which reads `TMPDIR`); this crate in `/tmp`, the default of
    `WafConfig::upload_dir`. First recorded as storing none: that default was missed.
    - Done: as in Go, an empty `upload_dir`, now the default, is the system's temporary directory.
  - Go rejects `SecUploadKeepFiles` without `SecUploadDir` ("SecUploadDir is required when SecUploadKeepFiles is
    enabled"); this crate keeps the files in the temporary directory.
    - Done: as in Go, that configuration is an error.
  - Go requires `SecUploadDir` to be writable (`IsDirWritable` creates a file in it); this crate, that it exists.
    - Done: as in Go, the directive checks by writing a file in it.
  - If the directory is gone when a file is uploaded, Go fails the body (`MULTIPART_STRICT_ERROR`,
    `REQBODY_ERROR`); this crate's `save_to_temp` creates it.
    - Done: as in Go, a file that can't be stored fails the body, and the directory isn't made.
- [ ] **`SecUploadKeepFiles RelevantOnly` is rejected.** Found at `62872e3`. Go takes `On`, `Off` and `RelevantOnly`,
  which keeps a transaction's uploaded files only when a rule that logs (one without `nolog`) matched
  (`Transaction.Close`); this crate takes `On` and `Off` only, so a configuration with `RelevantOnly` fails to load.
- [ ] **Body processor error messages have an extra prefix.** Found at `62872e3`. Go's `REQBODY_ERROR_MSG` is the
  processor's name and its error (`XML: XML syntax error on line 1: ...`), and `REQBODY_PROCESSOR_ERROR_MSG` the
  error alone; this crate puts the error's kind before the error in both (`XML: malformed xml: XML syntax error ...`),
  from `BodyProcessorError`'s `Display`, for every processor (`malformed json: `, `invalid multipart encoding: `),
  and in `RES_BODY_ERROR_MSG` and `RES_BODY_PROCESSOR_ERROR_MSG` too. Whether the rest of the JSON and multipart
  messages is Go's is unverified.

FTW at `62872e3`, after these fixes: 5,193 of 5,231 passed, and the same 38 failed as before them (`0fe42f2`) and
before the XML fix (`b222f27`).

## 8. Checks to run

Go Coraza's own suites that haven't been run against this crate, found at `62872e3`. Go Coraza's `main` is 8 commits
past `3fc3ae2`, at `f4bca98` (2026-10-16); only `a66ffcf` (#1682) changes behaviour, in a cache of transformation
results this crate doesn't have. The rest are documentation, dependency updates and refactors.

- [ ] **Go's operator tests.** `internal/operators/testdata`: 3,934 cases in 29 JSON files, to run as Go's
  transformation tests were (section 6).
- [ ] **Go's engine profiles.** `testing/engine`: 89 tests in 138 stages, each a request with the rules it must and
  must not trigger, on `ctl`, chains across phases, `setvar`, macro expansion, `skip`, and JSON, XML, multipart and
  response bodies. They're Go values (`profile.RegisterProfile`); a Go program can write them out as JSON for a Rust
  test to run.
- [ ] **The JSON body processor against Go's.** As the XML one was (section 7): the same inputs to Go Coraza's JSON
  processor (gjson) and to this crate's (serde_json). They may differ in how keys are named, numbers written, and
  duplicate keys and bytes that aren't UTF-8 read (unverified).
