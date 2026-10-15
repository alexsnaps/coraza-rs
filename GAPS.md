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
    the WAF's setting (`Transaction::audit_engine`, `audit_log_parts`, `debug_log_level`), which an embedder's
    logger can read; the library itself writes neither log. `hashEngine` and `hashEnforcement` have no effect, as in
    Go ("not supported yet"). A transaction now takes all its `ctl`-changeable settings from the WAF in one place.
- [x] **`SecRequestBodyAccess` and `SecResponseBodyAccess` are not enforced.** Found while working on 1.6: bodies are
  stored and processed whatever the setting, while Go skips them (and defaults both to `Off`, as `WafConfig` does).
  - Done: as in Go, a request body is stored and parsed only with request body access and when not empty, and a
    response body only with response body access and a processable content type; the phase's rules run either way.
    A transaction made with `Transaction::new`, outside a WAF, keeps request body access on.

- [x] **Body limits are not enforced.** Found while working on section 3: `SecRequestBodyLimit`,
  `SecResponseBodyLimit` and their `…LimitAction` were stored and ignored, and `WafConfig` defaulted the response
  action to `Reject` where Go has `ProcessPartial`.
  - Done: as in Go, a body that reaches its limit sets `INBOUND_DATA_ERROR` or `OUTBOUND_DATA_ERROR`; `Reject` then
    interrupts the transaction (413 for a request, 500 for a response, outside any rule) before that phase's rules,
    and `ProcessPartial` inspects only the first `limit` bytes. Go counts a body exactly at the limit as reaching
    it, and so does this.

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
- [ ] **Values are text, so bytes are lost.** Go Coraza's values are bytes. Here, what a transformation produces
  that isn't UTF-8 becomes U+FFFD, so `t:sha1,t:hexEncode` (CRS 901320 and 901410) and `t:md5,t:hexEncode` don't
  give the digest in hex, and `%ff` doesn't stay one byte. A fix would carry bytes through a rule's transformations
  and turn them into text only for the operator.
- [x] **`@rx` and `@pm` compiled for every value.** Found while running the FTW tests, which took about half a
  second per request. Both used the regular expression or matcher built at load time only when called without a
  transaction, which rules never do.
  - Done: they use it whenever the pattern has no macro. CRS's 669 rules cost 464 ms on a plain `GET` before,
    under 1 ms after.
- [ ] **Run CRS v4.30.0's FTW tests and record the pass rate.** Not run yet; `ftw-runner/` drives
  `examples/ftw_server_async.rs`.
  - Go Coraza's CI runs all 5,260 tests (`testing/coreruleset`). It ignores 7 (`.ftw.yml`) and changes the expected
    result of 14 (`.ftw-overrides.yml`).
