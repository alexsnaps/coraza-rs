# Gaps against Go Coraza

What is still open at `62872e3`, comparing with Go Coraza at `3fc3ae2` and with OWASP CRS v4.30.0 (`e03a4f6`), the CRS
version Go Coraza's regression tests run. Go Coraza's `main` has since moved to `f4bca98` (2026-10-16) with nothing to
port: of its 8 newer commits, only `a66ffcf` (#1682) changes behaviour, in a cache of transformation results this
crate doesn't have. What was closed is in [PORTING_LOG.md](PORTING_LOG.md), phases 12 to 18.

Where things stand: CRS v4.30.0, with Go's `coraza.conf-recommended` and `crs-setup.conf.example`, loads with nothing
skipped, and 5,193 of its 5,231 FTW tests pass (go-ftw v2.1.0, the rules of Go's harness); none of the 38 failures is
the engine's (section 2). Go's transformation tests pass in full (348). On libinjection's 335,284 sample inputs,
libperfusion gives the same SQLi verdicts and fingerprints as libinjection-go v0.3.4, the version Go Coraza pins, and
flags 32 more XSS inputs, none fewer.

## 1. Differences from Go

- [ ] **Some values are text, where Go's are bytes.** Collection values are bytes, as in Go, but:
  - argument names are text (`?%ff=1` puts U+FFFD in `ARGS_NAMES`);
  - single-value variables are text, so `REQUEST_BODY`, `MATCHED_VAR` and the body error messages replace bytes that
    aren't UTF-8 (an invalid XML name that isn't UTF-8 is quoted with U+FFFD, where Go keeps its bytes);
  - a JSON body becomes text before it is parsed, so its values do too (whether Go's gjson keeps such bytes is
    unverified).
- [ ] **`SecUploadKeepFiles RelevantOnly` is rejected.** Go takes `On`, `Off` and `RelevantOnly`, which keeps a
  transaction's uploaded files only when a rule that logs (one without `nolog`) matched (`Transaction.Close`); this
  crate takes `On` and `Off` only, so a configuration with `RelevantOnly` fails to load.
- [ ] **Body processor error messages have an extra prefix.** Go's `REQBODY_ERROR_MSG` is the processor's name and its
  error (`XML: XML syntax error on line 1: ...`), and `REQBODY_PROCESSOR_ERROR_MSG` the error alone; this crate puts
  the error's kind before the error in both (`XML: malformed xml: XML syntax error ...`), from `BodyProcessorError`'s
  `Display`, for every processor (`malformed json: `, `invalid multipart encoding: `), and in `RES_BODY_ERROR_MSG` and
  `RES_BODY_PROCESSOR_ERROR_MSG` too. Whether the rest of the JSON and multipart messages is Go's is unverified.
- [ ] **`SecRequestBodyJsonDepthLimit` and `SecResponseBodyJsonDepthLimit` past 128.** serde_json rejects nesting
  deeper than 128 whatever the limit, so a higher limit fails such a body where Go reads it.
- [ ] **`URI_PARSE_ERROR` doesn't check the host.** It is set for what Go's `url.ParseRequestURI` rejects (control
  characters, invalid `%`-escapes in the path, a URI that is neither `*`, an absolute path nor an absolute URL), but
  Go's validation of the host isn't replicated.
- [ ] **`@rbl` reads no TXT record.** It looks the address up (500 ms DNS timeout), as Go does, but the standard
  library resolves addresses only.
- [ ] **`@validateSchema` is missing.** It needs a JSON Schema validator. Go uses `kaptinlin/jsonschema`; a Rust one
  would be a new dependency, which is your call. CRS v4.30.0 doesn't use it.
- [ ] **The `HTTPS` audit log writer is refused** when the WAF is built: it needs an HTTP client with TLS, which no
  dependency provides. Go's other formats and writers are supported.

## 2. The FTW test server

`examples/ftw_server_async.rs`, which `ftw-runner/` drives. Of the 38 FTW tests that fail, 29 are the server's (below)
and 9 are tests Go's CI ignores (3, `.ftw.yml`) or expects another result of (6, `.ftw-overrides.yml`). Of those 6, 4
meet Go's expectation, 920290-1 doesn't (Go's own TODO), and 920430-8 is the server's (below).

- [ ] **Its HTTP library rejects request lines Go's accepts.** 29 FTW tests never reach the WAF: hyper rejects 28
  request lines for their URI (a raw `<`, `>` or `"`, for instance), and rewrites 920100-16's absolute-form
  `http://localhost` with a path. Go's harness uses `net/http`. A server reading requests with `httparse`, already in
  the dependency tree through hyper, rather than hyper's strict `Uri`, would let them through; it would be an optional
  dependency of the `async-server` feature.
- [ ] **920430-8 needs a 505**, which the server can't send.
- [ ] **It is untested, and never sets the connection.** It has no tests, and never calls
  `Transaction::process_connection`, so `REMOTE_ADDR` and the rest stay empty: each of its error log lines reads
  `[client ""]`.

## 3. Checks to run

Go Coraza's own suites that haven't been run against this crate.

- [ ] **Go's operator tests.** `internal/operators/testdata`: 3,934 cases in 29 JSON files, to run as Go's
  transformation tests were.
- [ ] **Go's engine profiles.** `testing/engine`: 89 tests in 138 stages, each a request with the rules it must and
  must not trigger, on `ctl`, chains across phases, `setvar`, macro expansion, `skip`, and JSON, XML, multipart and
  response bodies. They're Go values (`profile.RegisterProfile`); a Go program can write them out as JSON for a Rust
  test to run.
- [ ] **The JSON body processor against Go's.** As the XML one was: the same inputs to Go Coraza's JSON processor
  (gjson) and to this crate's (serde_json). They may differ in how keys are named, numbers written, and duplicate keys
  and bytes that aren't UTF-8 read (unverified).

## 4. Housekeeping

- [ ] **75 `doc_*` unit tests.** The doc examples of the items `558c0d8` made internal, kept as unit tests. Several
  repeat the module's own tests (`doc_eq_type` and `test_eq_valid_values` in `src/operators/simple.rs` both check
  leading zeros); keep each case once.
- [ ] **Stale docs.**
  - `examples/ftw_server.rs`'s module doc says it writes ModSecurity-compatible audit logs; it writes Go Coraza's
    error log lines, through `Parser::on_error_log`.
  - `ftw-runner/main.go:42` says to build the server with `cargo build --example ftw_server`; it starts
    `ftw_server_async`'s release build (`cargo build --release --example ftw_server_async --features async-server`).
  - `cargo doc` warns of an unclosed HTML tag, `<KeyValue>`, at `src/collection/map.rs:29`.

## 5. Differences kept on purpose

Not gaps to close, but where this crate knowingly differs from Go.

- `SecRuleUpdateTargetById`, `SecRuleUpdateTargetByTag` and `SecRuleUpdateActionById` update every listed id and
  range, where Go stops after the first single id.
- `ctl:requestBodyProcessor` and `ctl:responseBodyProcessor` with an unknown processor are a compile error.
- `SecIgnoreRuleCompilationErrors On` skips later failing directives, as `Parser::skip_failed_directives` does, where
  Go records it and doesn't act on it.
- `setenv` sets `ENV` but not the process environment, which is undefined behaviour while other threads may read it.
- The `TIME*` variables and audit log timestamps are in UTC, where Go uses local time.
- The `OCSF` audit log has the transaction's highest severity, where Go always writes `emergency`.
- A regex key on a collection with case-insensitive keys (`TX:/^FOO/`) ignores case, where Go lowercases the pattern,
  which also changes escapes such as `\D`.
- `@rx` captures `TX.0` to `TX.9`, as ModSecurity does; Go captures `TX.0` to `TX.8`.
