# FTW Test Runner for Coraza-RS

This Go program acts as a test harness for running [go-ftw](https://github.com/coreruleset/go-ftw) tests against the Rust implementation of Coraza.

## Architecture

```
┌───────────────────┐
│   Go Test Runner  │
│   (this program)  │
└─────────┬─────────┘
          │
          │ spawns & manages
          ▼
┌───────────────────┐      HTTP       ┌──────────────┐
│  Rust FTW Server  │◄─────────────── │    go-ftw    │
│  (coraza-rs WAF)  │                 │ test runner  │
└───────────────────┘                 └──────────────┘
          │
          │ writes
          ▼
┌───────────────────┐
│   Error Log File  │
│ (go-ftw reads it) │
└───────────────────┘
```

## Prerequisites

1. **Rust toolchain** - To build the FTW server
2. **Go 1.25+** - To run this test harness. It uses go-ftw (v2.1.0) as a library, so there is nothing else to
   install.
3. **For the CRS tests** - A checkout of [CRS](https://github.com/coreruleset/coreruleset) (its rules and
   `tests/regression/tests`) and Go Coraza's
   [`coraza.conf-recommended`](https://github.com/corazawaf/coraza/blob/main/coraza.conf-recommended)

## Usage

### Basic Usage

```bash
# Build the server first
cargo build --release --example ftw_server_async --features async-server

cd ftw-runner
go run main.go
```

This will:
1. Start the Rust FTW server, without rules, on localhost:8080
2. Run the tests in `../../coraza-coreruleset/tests`, or basic health checks if that directory doesn't exist
3. Stop the server

### With CRS Tests

```bash
go run main.go \
  --rules /path/to/crs-test.conf \
  --test-dir /path/to/coreruleset/tests/regression/tests \
  --failed-out /tmp/ftw-failed.txt
```

Flags:
- `--rules` - Config file the server loads
- `--test-dir` - Directory of go-ftw YAML tests, searched recursively
- `--max-tests` - Run only the first N test files (0, the default, runs all)
- `--failed-out` - File to write the IDs of the failed tests to, one per line

The server listens on port 8080. For each request it writes Go Coraza's error log line for every matched rule with
`log` to `/tmp/coraza-ftw-audit.log`, which go-ftw reads to check which rules matched.

`crs-test.conf` loads what Go Coraza's CRS test harness (`testing/coreruleset/coreruleset_test.go`) loads, in the
same order:

```apache
Include /path/to/coraza/coraza.conf-recommended

SecResponseBodyMimeType text/plain

# Rule 900005 from https://github.com/coreruleset/coreruleset/blob/v4.0/dev/tests/regression/README.md#requirements
SecAction "id:900005,\
  phase:1,\
  nolog,\
  pass,\
  ctl:ruleEngine=DetectionOnly,\
  ctl:ruleRemoveById=910000,\
  setvar:tx.blocking_paranoia_level=4,\
  setvar:tx.crs_validate_utf8_encoding=1,\
  setvar:tx.arg_name_length=100,\
  setvar:tx.arg_length=400,\
  setvar:tx.total_arg_length=64000,\
  setvar:tx.max_num_args=255,\
  setvar:tx.max_file_size=64100,\
  setvar:tx.combined_file_sizes=65535"

# Write the value from the X-CRS-Test header as a marker to the log
# Requests with X-CRS-Test header will not be matched by any rule. See https://github.com/coreruleset/go-ftw/pull/133
SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" \
  "id:999999,\
  phase:1,\
  pass,\
  t:none,\
  log,\
  msg:'X-CRS-Test %{MATCHED_VAR}',\
  ctl:ruleRemoveById=1-999999"

Include /path/to/coreruleset/crs-setup.conf.example
Include /path/to/coreruleset/rules/*.conf
```

## Development

### Server Implementation

The Rust FTW server is at `../examples/ftw_server_async.rs` and provides:
- HTTP server for receiving test requests (hyper), answering `/reflect` as CRS's albedo backend
- WAF processing with rule evaluation, in all four phases
- Go Coraza's error log line for every matched rule with `log`, which go-ftw reads
- Support for FTW test requirements

hyper rejects some request lines go-ftw sends (a raw `<`, `>` or `"` in the URI, a missing or unknown HTTP version),
which then never reach the WAF.

### Adding Tests

To add new test cases:
1. Create YAML test files following the FTW schema
2. Place them in a test directory
3. Run with `--test-dir <directory>`

See [go-ftw documentation](https://github.com/coreruleset/go-ftw) for test format.

## Results

CRS v4.30.0's regression tests, run with go-ftw v2.1.0 and the `crs-test.conf` above: **5,185 of 5,231 pass
(99.1%)**.

| Rule file                                       | Tests | Passed |
|-------------------------------------------------|------:|-------:|
| REQUEST-901-INITIALIZATION                      |    18 |     18 |
| REQUEST-911-METHOD-ENFORCEMENT                  |     8 |      8 |
| REQUEST-913-SCANNER-DETECTION                   |     9 |      9 |
| REQUEST-920-PROTOCOL-ENFORCEMENT                |   428 |    414 |
| REQUEST-921-PROTOCOL-ATTACK                     |   117 |    114 |
| REQUEST-922-MULTIPART-ATTACK                    |    47 |     47 |
| REQUEST-930-APPLICATION-ATTACK-LFI              |    83 |     82 |
| REQUEST-931-APPLICATION-ATTACK-RFI              |    42 |     42 |
| REQUEST-932-APPLICATION-ATTACK-RCE              |  1089 |   1082 |
| REQUEST-933-APPLICATION-ATTACK-PHP              |   442 |    442 |
| REQUEST-934-APPLICATION-ATTACK-GENERIC          |   282 |    275 |
| REQUEST-941-APPLICATION-ATTACK-XSS              |   263 |    256 |
| REQUEST-942-APPLICATION-ATTACK-SQLI             |  1032 |   1029 |
| REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION |    47 |     46 |
| REQUEST-944-APPLICATION-ATTACK-JAVA             |  1176 |   1175 |
| REQUEST-949-BLOCKING-EVALUATION                 |     5 |      3 |
| RESPONSE-950-DATA-LEAKAGES                      |    14 |     14 |
| RESPONSE-951-DATA-LEAKAGES-SQL                  |    22 |     22 |
| RESPONSE-952-DATA-LEAKAGES-JAVA                 |    10 |     10 |
| RESPONSE-953-DATA-LEAKAGES-PHP                  |    19 |     19 |
| RESPONSE-954-DATA-LEAKAGES-IIS                  |     7 |      7 |
| RESPONSE-955-WEB-SHELLS                         |    10 |     10 |
| RESPONSE-956-DATA-LEAKAGES-RUBY                 |    17 |     17 |
| RESPONSE-959-BLOCKING-EVALUATION                |     3 |      3 |
| RESPONSE-980-CORRELATION                        |     3 |      3 |
| REQUEST-999-COMMON-EXCEPTIONS-AFTER             |    38 |     38 |

Of the 46 that fail:
- **9 are tests Go Coraza's CI sets aside too.** It ignores 920100-5, 920430-5 and 920610-2 (`.ftw.yml`), and
  changes the expected result of 920100-8, 920270-4, 920274-1, 920290-1, 920430-8 and 920620-1
  (`.ftw-overrides.yml`); all but 920290-1 and 920430-8 meet Go's changed expectation.
- **29 are the test server's.** hyper rejects 28 request lines for their URI (see above), so the WAF never sees
  them, and rewrites 920100-16's absolute-form `http://localhost` URI.
- **8 are the engine's:** 920250-1 to 4, 941310-1, 12 and 13, and 944200-1. They send bytes that aren't UTF-8,
  which the engine's collections hold as text.

Go Coraza's CI runs 5,260 tests, with go-ftw v2.5.0.

## Troubleshooting

### Server binary not found
```bash
# The runner starts ../target/release/examples/ftw_server_async; build it with
cargo build --release --example ftw_server_async --features async-server
```

### Server won't start
```bash
# Check if port 8080 (serverPort in main.go) is in use
lsof -i :8080
```

### Tests fail to connect
```bash
# Verify server is running
curl http://localhost:8080/

# Check the log lines go-ftw reads
tail -f /tmp/coraza-ftw-audit.log
```

## Next Steps

1. Read requests with a parser that accepts the request lines hyper rejects (29 tests; see `../GAPS.md`)
2. Keep collection values as bytes (8 tests; see `../GAPS.md`)
3. Integrate into CI/CD pipeline
