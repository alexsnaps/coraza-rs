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
- [ ] **Transformation `removeCommentsChar`.** 1 skipped: 942190.
- [ ] **Configuration directives.** 8 skipped: `SecAuditLogFormat`, `SecAuditLogParts`, `SecAuditLogType`,
  `SecAuditLogRelevantStatus`, `SecRxPreFilter`, `SecRequestBodyJsonDepthLimit`, `SecResponseBodyJsonDepthLimit`
  and `SecResponseBodyMimeType`.

## 2. Accepted but ignored

- [ ] **`ctl` commands that do nothing.** `requestBodyProcessor`, `responseBodyProcessor`, `auditEngine`,
  `auditLogParts`, `debugLogLevel`, `hashEngine` and `hashEnforcement` parse to `CtlCommand::NotImplemented`
  (`src/actions/ctl.rs:81`-`96`).
  - The body parser is chosen by a prefix match on `Content-Type` instead. So rule 200006 of
    `coraza.conf-recommended`, which sends `application/*+json` bodies to the JSON parser, has no effect.

## 3. Variables that parse but are never set

Found while working on 1.4: the list in 5 compared only names. 65 variables parse, but `Transaction::collection`
(`variable_storage!` in `src/transaction/mod.rs`) maps them to nothing, so a rule on them never matches and a macro
naming them expands to nothing. CRS v4.30.0 uses the ones below.

- [x] **`REQUEST_URI` held only the path.** Go and ModSecurity keep the query string (`/search?q=1`); every CRS rule
  on `REQUEST_URI` saw less than it should.
  - Done: `REQUEST_URI` is the request URI without its fragment.
- [ ] **`XML`.** 354 uses, as `XML:/*` and `XML://@*` in most request rules. In Go it is the same collection as
  `REQUEST_XML`, which the XML body processor fills.
- [ ] **`MATCHED_VAR`, `MATCHED_VAR_NAME`, `MATCHED_VARS` and `MATCHED_VARS_NAMES`.** Mostly in `logdata`, but 13
  chained rules inspect `MATCHED_VAR(S)`.
- [ ] **The names variables:** `ARGS_NAMES` (190 uses), `REQUEST_COOKIES_NAMES` (165), `REQUEST_HEADERS_NAMES`,
  `ARGS_GET_NAMES`, and the unused `ARGS_POST_NAMES` and `RESPONSE_HEADERS_NAMES`.
- [ ] **`REQBODY_PROCESSOR`, `ARGS_COMBINED_SIZE`, `UNIQUE_ID` and `MULTIPART_INVALID_QUOTING`.**
  - `REQBODY_PROCESSOR` drives 901340/901350 and three 920 rules.
  - `UNIQUE_ID` drives CRS's sampling (901450).
- [ ] **The rest, which CRS doesn't use.**
  - `ARGS_PATH`, `AUTH_TYPE`, `DURATION`, `ENV`, `FILES_TMP_CONTENT`, `FULL_REQUEST`, `FULL_REQUEST_LENGTH`, `GEO`,
    `HIGHEST_SEVERITY`, `INBOUND_DATA_ERROR`, `IP`, `JSON`, `OUTBOUND_DATA_ERROR`, `PATH_INFO`, `REMOTE_HOST`, `RULE`,
    `SESSIONID`, `STATUS_LINE`, `URLENCODED_ERROR`, `USERID`.
  - The other `MULTIPART_*` flags and `MULTIPART_FILENAME`/`MULTIPART_NAME`.
  - `REQBODY_PROCESSOR_ERROR(_MSG)`, `RESBODY_*`.
  - `TIME` and the `TIME_*` parts.

## 4. Other missing directives

Go Coraza has 69 `Sec*` directives; we have 26. Section 1 covers 11 of the 43 missing.

- [ ] **The other directives that do something in Go.**
  - `SecRuleRemoveById`, `SecRuleRemoveByMsg`, `SecRuleRemoveByTag`. `RuleGroup::delete_by_*`
    (`src/rules/group.rs:139`-`200`) already does the work.
  - `SecRuleUpdateActionById`.
  - `SecDebugLog`.
  - `SecDataset`, which `@pmFromDataset` and `@ipMatchFromDataset` need.
  - `SecAuditLogDirMode`, `SecAuditLogFileMode`, `SecAuditLogStorageDir`.
  - `SecIgnoreRuleCompilationErrors`, `SecRemoteRulesFailAction`, `SecResponseBodyMimeTypesClear`.
- [ ] **Accept the directives Go accepts and ignores,** so configs written for Go Coraza load: `SecArgumentSeparator`,
  `SecConnEngine`, `SecConnReadStateLimit`, `SecConnWriteStateLimit`, `SecCookieFormat`, `SecGsbLookupDb`,
  `SecHashEngine`, `SecHashKey`, `SecHashMethodPm`, `SecHashMethodRx`, `SecHashParam`, `SecHttpBlKey`,
  `SecPcreMatchLimit`, `SecPcreMatchLimitRecursion`, `SecRulePerfTime`, `SecRuleScript`, `SecRuleUpdateTargetByMsg`,
  `SecTmpDir` and `SecUnicodeMap`. In Go, `SecRemoteRules` is an error ("not implemented").

## 5. Operators, actions and names

None of these is used by CRS v4.30.0.

- [ ] **Operators:** `@geoLookup`, `@inspectFile`, `@ipMatchFromDataset`, `@pmFromDataset`, `@rbl`, `@restpath`,
  `@validateNid` and `@validateSchema`.
- [ ] **Action:** `accuracy`.
- [ ] **Variables:** `MULTIPART_FILENAME_CHARSET` and `MULTIPART_FILENAME_LANGUAGE`.
- [ ] **Go's spellings.**
  - `RES_BODY_ERROR`, `RES_BODY_ERROR_MSG`, `RES_BODY_PROCESSOR`, `RES_BODY_PROCESSOR_ERROR` and
    `RES_BODY_PROCESSOR_ERROR_MSG`: ours are `RESBODY_*`.
  - `FILES_TMPNAMES`: ours is `FILES_TMP_NAMES` (`src/types/variables.rs:297`).
  - `t:normalisePath` and `t:normalisePathWin`, which Go accepts alongside the `normalize` spellings.

## 6. Measure

- [ ] **Load CRS with nothing skipped.** Re-run the load check above until `Parser::skipped()` is empty.
- [ ] **Run CRS v4.30.0's FTW tests and record the pass rate.** Not run yet; `ftw-runner/` drives
  `examples/ftw_server_async.rs`.
  - Go Coraza's CI runs all 5,260 tests (`testing/coreruleset`). It ignores 7 (`.ftw.yml`) and changes the expected
    result of 14 (`.ftw-overrides.yml`).
