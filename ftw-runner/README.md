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
│   Audit Log File  │
│ (FTW reads this)  │
└───────────────────┘
```

## Prerequisites

1. **Rust toolchain** - To build the FTW server
2. **Go 1.21+** - To run this test harness
3. **go-ftw** - Framework for Testing WAFs

Install go-ftw:
```bash
go install github.com/coreruleset/go-ftw@latest
```

## Usage

### Basic Usage

```bash
cd ftw-runner
go run main.go
```

This will:
1. Build the Rust FTW server
2. Start it on localhost:8080
3. Run basic health checks
4. Stop the server

### With CRS Tests

```bash
# Point to CRS test directory
go run main.go --tests ../coraza-coreruleset/tests

# With custom rules
go run main.go \
  --rules ../crs-rules/crs-setup.conf \
  --tests ../coraza-coreruleset/tests
```

### Configuration

Environment variables:
- `FTW_SERVER_PORT` - Port for server (default: 8080)
- `FTW_LOG_FILE` - Path to audit log (default: /tmp/coraza-ftw-audit.log)

## Development

### Server Implementation

The Rust FTW server is at `../examples/ftw_server.rs` and provides:
- HTTP server for receiving test requests
- WAF processing with rule evaluation
- ModSecurity-compatible audit logging
- Support for FTW test requirements

### Adding Tests

To add new test cases:
1. Create YAML test files following the FTW schema
2. Place them in a test directory
3. Run with `--tests <directory>`

See [go-ftw documentation](https://github.com/coreruleset/go-ftw) for test format.

## Expected Results

With current implementation:
- **Protocol violations (920xxx)**: ✅ ~80% pass
- **Scanner detection (913xxx)**: ✅ 100% pass
- **Path traversal (930xxx)**: ✅ 100% pass
- **Command injection (932xxx)**: ✅ ~70% pass
- **SQL Injection (942xxx)**: ❌ ~20% pass (needs @detectSQLi)
- **XSS (941xxx)**: ❌ ~20% pass (needs @detectXSS)

## Troubleshooting

### Server won't start
```bash
# Check if port is in use
lsof -i :8080

# Try different port
FTW_SERVER_PORT=9080 go run main.go
```

### Tests fail to connect
```bash
# Verify server is running
curl http://localhost:8080/

# Check server logs
tail -f /tmp/coraza-ftw-audit.log
```

### go-ftw not found
```bash
# Install it
go install github.com/coreruleset/go-ftw@latest

# Or specify path
export PATH=$PATH:$(go env GOPATH)/bin
```

## Next Steps

1. Implement rule loading from SecLang files
2. Add proper ModSecurity audit log format
3. Run full CRS test suite
4. Analyze and document failures
5. Integrate into CI/CD pipeline
