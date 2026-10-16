# FTW Integration Plan - Running CRS Tests Against Coraza-RS

The plan written on 2026-03-25 (`b518c9b`) for running CRS's go-ftw regression tests against this crate, and how it
turned out. It is done: the current state is in [FTW_INTEGRATION_STATUS.md](FTW_INTEGRATION_STATUS.md), and how to
run the tests in [ftw-runner/README.md](ftw-runner/README.md). The original, with its code stubs, is in the git
history; the stubs used APIs that no longer exist (`Waf::add_rule`, a server-side SecLang reader, a hand-written
audit log).

## Architecture

As planned, and as built: a Go program embeds go-ftw as a library, starts a pre-built Rust server, and runs the tests
against it; go-ftw tells from a log file which rules each request matched.

```
┌───────────────────────────────────────────┐
│  ftw-runner/main.go (Go)                  │
│  - go-ftw v2.1.0 as a library             │
│  - starts and stops the server            │
│  - runs the YAML tests, reports results   │
└─────────────────────┬─────────────────────┘
                      │ HTTP requests
                      ▼
┌───────────────────────────────────────────┐
│  examples/ftw_server_async.rs (Rust)      │
│  - loads the rules with seclang::Parser   │
│  - runs each request through the WAF      │
│  - answers as CRS's albedo backend        │
└─────────────────────┬─────────────────────┘
                      │ Parser::on_error_log
                      ▼
┌───────────────────────────────────────────┐
│  /tmp/coraza-ftw-audit.log                │
│  Go Coraza's error log lines, go-ftw's    │
│  X-CRS-Test markers; go-ftw reads them    │
└───────────────────────────────────────────┘
```

## Planned, and done

| Planned (2026-03-25)                                                  | Done                                                                                                                                                                                |
|-----------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| A Rust HTTP server, `examples/ftw_server.rs`, on hyper and tokio      | `examples/ftw_server_async.rs` (hyper and tokio, `async-server` feature), which the runner starts; `examples/ftw_server.rs` stayed a simpler, single-threaded server, tested with the crate. |
| The server loads CRS rules                                            | Through `seclang::Parser`, `Include`s and globs included (`dc9a7f5`); the servers' own SecLang readers are gone.                                                                   |
| Each request goes through all 5 phases                                | The four phases and logging, as Go Coraza's CRS harness runs them, logging also when interrupted; the backend answers `/reflect` as CRS's albedo does (`41a911b`).                  |
| The server writes ModSecurity-style audit logs for go-ftw            | go-ftw reads Go Coraza's error log lines, which the WAF hands the server through `Parser::on_error_log` (`0fe42f2`). The audit log is the library's own, as `SecAuditLog*` sets it. |
| A Go harness in `main.go`, `server.go` and `config.go`                | One `main.go`, with go-ftw's configuration built in memory, and `--failed-out` to list the failed tests.                                                                            |
| CRS rules copied into the repository                                  | Rules and tests come from a CRS v4.30.0 checkout, loaded with Go Coraza's `coraza.conf-recommended` by `crs-test.conf`, as Go's harness loads them.                                |
| 60–70% of the tests pass, without `@detectSQLi` and `@detectXSS`      | 5,193 of 5,231 (99.3%), with both operators (libperfusion); none of the 38 failures is the engine's.                                                                               |
| 4 days                                                                | First runs on 2026-03-25–27 (PR #1); Go's setup and 99.3% on 2026-10-15–16 (PRs #4 to #13).                                                                                         |

## Not done

- **CI.** The FTW tests don't run on each change.
- **The 29 tests the server never passes to the WAF**, as hyper rejects their request line, and 920430-8, which needs
  a 505: [GAPS.md](GAPS.md), section 2.

Benchmarking against Go, a planned enhancement, is done separately: `benches/crs.rs` ports Go Coraza's CRS benchmarks,
and the [README](README.md) gives the results.
