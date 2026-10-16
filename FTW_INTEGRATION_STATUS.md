# FTW Integration Status

As of 2026-10-16 (`62872e3`): CRS v4.30.0's FTW regression tests run against this crate as Go Coraza's CRS harness
(`testing/coreruleset`) runs them, and **5,193 of 5,231 pass (99.3%)**. None of the 38 failures is the engine's.
How to run them, and the results per rule file, are in [ftw-runner/README.md](ftw-runner/README.md); what was planned
in March, and how it turned out, in [FTW_INTEGRATION_PLAN.md](FTW_INTEGRATION_PLAN.md).

## What runs

- **`ftw-runner/main.go`**, the harness. It embeds go-ftw v2.1.0 as a library, with its configuration built in
  memory; starts the release build of `ftw_server_async`; runs the YAML tests of `--test-dir`; stops the server, also
  when tests fail; and writes the failed tests' IDs with `--failed-out`.
- **`examples/ftw_server_async.rs`**, the server (hyper and tokio, behind the `async-server` feature). It loads the
  `--rules` config with `seclang::Parser`, `Include`s and globs included, and handles each request as Go's harness
  does:
  - it reads the body and runs the four phases and logging, logging also for an interrupted request; the backend
    answers in between, for `/reflect` as CRS's albedo does (status, headers and body from the request's JSON), and
    with `OK` otherwise;
  - headers reach the WAF as Go's `net/http` hands them over: canonical names, and values that need not be ASCII;
  - go-ftw reads which rules matched from Go Coraza's error log lines, which the WAF hands to the server through
    `Parser::on_error_log`, with go-ftw's `X-CRS-Test` marker, in `/tmp/coraza-ftw-audit.log`.
- **`crs-test.conf`** (in [ftw-runner/README.md](ftw-runner/README.md)) loads what Go's harness loads, in the same
  order: Go Coraza's `coraza.conf-recommended`, the test settings of rule 900005 and the marker rule, then CRS's
  `crs-setup.conf.example` and `rules/*.conf`.
- **`examples/ftw_server.rs`** is a simpler, single-threaded server, whose tests run with the crate's; the runner
  doesn't use it, and it doesn't answer `/reflect`.

## Results over time

| Date       | Commit    | Passed of 5,231 | What changed                                                                       |
|------------|-----------|----------------:|------------------------------------------------------------------------------------|
| 2026-03-27 | `df91834` |               — | The whole suite runs against the async server (PR #1); no pass rate was recorded.  |
| 2026-10-15 |           |           5,053 | First full run of CRS v4.30.0's tests, while closing the gaps against Go (PR #4).  |
| 2026-10-15 | `41a911b` |           5,185 | The fixes that run found, and the server handling requests as Go's harness does.   |
| 2026-10-16 | `4447016` |           5,193 | Argument values keep the request's bytes (8 tests).                                |
| 2026-10-16 | `62872e3` |           5,193 | Unchanged after the architecture refactors and the body processing fixes.          |

The fixes the October runs found are listed in [PORTING_LOG.md](PORTING_LOG.md), phase 14.

## The 38 failures

- **29 are the test server's.** hyper rejects 28 request lines for their URI (a raw `<`, `>` or `"`, for instance),
  so the WAF never sees them, and rewrites 920100-16's absolute-form `http://localhost` with a path.
- **9 are tests Go Coraza's CI sets aside too.** It ignores 920100-5, 920430-5 and 920610-2 (`.ftw.yml`), and changes
  the expected result of 920100-8, 920270-4, 920274-1, 920290-1, 920430-8 and 920620-1 (`.ftw-overrides.yml`). All
  but two meet Go's changed expectation: 920290-1 doesn't in Go either (its own TODO), and 920430-8 needs a 505 the
  server can't send.

Go Coraza's CI runs 5,260 tests, with go-ftw v2.5.0.

## Still open

In [GAPS.md](GAPS.md), section 2: reading requests with a parser that accepts what hyper rejects (29 tests), the 505,
and the server's own tests (it has none, and never calls `Transaction::process_connection`). The FTW tests don't run
in CI.
