# Coraza

This is a port of [Coraza](https://github.com/corazawaf/coraza)... cause, "I did consider rewriting it in **Rust**"

>[!WARNING]
> This is work in progress... sort of an experiment to some extent.
> I'm sorry for this!

A web application firewall library: it evaluates ModSecurity's SecLang rules, such as the
[OWASP Core Rule Set](https://coreruleset.org) (CRS), against HTTP transactions, aiming at Go Coraza's behaviour.

## Usage

The crate isn't on crates.io; depend on the repository:

```toml
[dependencies]
coraza = { git = "https://github.com/alexsnaps/coraza-rs" }
```

Build a WAF once from SecLang (`Parser::from_file` takes files and globs, such as CRS's `rules/*.conf`), share it
between threads, and run each request through a transaction:

```rust
use coraza::seclang::Parser;

let mut parser = Parser::new();
parser.from_string(r#"
    SecRuleEngine On
    SecRule ARGS "@contains attack" "id:1,phase:1,deny,status:403"
"#)?;
let waf = parser.into_waf()?;

let mut tx = waf.new_transaction();
tx.process_connection("192.0.2.1", 54321, "10.0.0.1", 80);
tx.process_uri("/search?q=attack", "GET", "HTTP/1.1");
tx.add_request_header("Host", "example.com");
if let Some(interruption) = tx.process_request_headers() {
    // Answer with interruption.status (403 here), without forwarding the request
}
```

A transaction goes through five phases, each called once, in order, and each returning the interruption if a rule
stopped the transaction:

1. `process_request_headers`, after `process_connection`, `process_uri` and `add_request_header`
2. `process_request_body`, even for an empty body
3. `process_response_headers`, after `add_response_header`
4. `process_response_body`
5. `process_logging`, which also writes the audit log; it runs on drop if not called

`Parser::on_error_log` is handed each matched rule that logs, whose `error_log()` is Go Coraza's error log line.
`examples/simple.rs` is a complete run (`cargo run --example simple`); `examples/ftw_server_async.rs` puts the WAF in
front of an HTTP server (`--features async-server`).

The terms used in the code and docs (transaction, phase, interruption, body processor...) are defined in
[CONTEXT.md](CONTEXT.md).

## Compatibility

- CRS v4.30.0, with Go Coraza's `coraza.conf-recommended` and CRS's `crs-setup.conf.example`, loads with nothing
  skipped.
- CRS's FTW regression tests, with the rules and settings of Go Coraza's harness: **5,193 of 5,231 pass (99.3%)**.
  Of the 38 that fail, 29 never reach the WAF, as the test server's HTTP library rejects their request line, and 9
  are tests Go Coraza's own CI ignores or expects another result of. To run them, see
  [ftw-runner/README.md](ftw-runner/README.md).
- Go Coraza's transformation tests pass in full (348). SQLi and XSS detection is
  [libperfusion](https://github.com/alexsnaps/libperfusion), a port of libinjection: on libinjection's 335,284 sample
  inputs, it gives libinjection-go's SQLi results, and flags 32 more XSS inputs, none fewer.

What still differs from Go Coraza, and the checks still to run, are in [GAPS.md](GAPS.md).

## Performance

Go Coraza's CRS benchmarks (`testing/coreruleset`), ported with the same configuration and requests
(`benches/crs.rs`): CRS v4.30.0, one request at a time, median time per run.

| Benchmark                      | This crate | Go Coraza |             |
|--------------------------------|-----------:|----------:|-------------|
| Compile CRS                    |     219 ms |     83 ms | 2.7× slower |
| `GET` request                  |    0.66 ms |   1.73 ms | 2.6× faster |
| Form `POST`                    |    0.83 ms |   2.33 ms | 2.8× faster |
| Form `POST` with a 10 KB value |     3.6 ms |    111 ms | 31× faster  |

This crate allocates 2.5 to 4 times as often as Go Coraza does. Measured on 2026-10-16 on an AMD Ryzen 9 7900
(Linux), at `13fe366` and Go Coraza `3fc3ae2` (Go 1.26).

## Development

```sh
cargo test
CRS_DIR=../coreruleset CORAZA_GO_DIR=../coraza cargo bench --bench crs
```

The benchmarks need a CRS checkout and a Go Coraza one (see `benches/crs.rs`). How the port came about is in
[PORTING_LOG.md](PORTING_LOG.md).

## License

Apache-2.0 ([LICENSE](LICENSE)). The files ported from Go's standard library are BSD-3-Clause, as their headers say.
