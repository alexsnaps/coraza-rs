# FTW Integration Plan - Running CRS Tests Against Coraza-RS

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│              Go Test Runner (ftw-runner)                    │
│  - Imports go-ftw as library (no external binary needed)   │
│  - Starts pre-built Rust server binary                     │
│  - Runs FTW tests programmatically                         │
│  - Collects and reports results                            │
└────────────────────┬────────────────────────────────────────┘
                     │
                     │ 1. Executes pre-built binary
                     │ 2. Waits for ready signal
                     ▼
┌─────────────────────────────────────────────────────────────┐
│         Rust HTTP Server (ftw_server binary)                │
│  - Pre-built: cargo build --example ftw_server             │
│  - Listens on localhost:8080                                │
│  - Loads CRS rules via SecLang parser                       │
│  - Processes HTTP requests through WAF                      │
│  - Writes audit logs to file                                │
└────────────────────┬────────────────────────────────────────┘
                     │
                     │ HTTP requests
                     │ (from embedded FTW)
                     ▼
          ┌──────────────────────┐
          │  Coraza-RS WAF       │
          │  - Rule evaluation   │
          │  - Phase processing  │
          │  - Interruptions     │
          └──────────────────────┘
```

## Components to Build

### 1. Rust HTTP Server (`coraza-ftw-server`)

**Location:** `coraza-rs/examples/ftw_server.rs`

**Responsibilities:**
- Start HTTP server on configurable port (default 8080)
- Load CRS rules from SecLang files
- Process each HTTP request through WAF
- Write ModSecurity-compatible audit logs
- Support configuration via command-line args

**Key Features:**
```rust
// Load rules from file
let rules = parse_seclang_file("crs-setup.conf")?;
let mut waf = Waf::new(config)?;
for rule in rules {
    waf.add_rule(rule)?;
}

// Process request
let mut tx = waf.new_transaction();
tx.process_uri(&uri, &method, "HTTP/1.1");
// ... add headers, process body, etc.

// Write audit log
if let Some(interruption) = tx.interruption() {
    write_audit_log(&tx, &interruption)?;
}
```

**Audit Log Format:**
FTW expects ModSecurity-style audit logs. We need to write:
```
[timestamp] [rule_id] [file "path"] [line "linenum"] [id "rule_id"]
[msg "message"] [severity "X"] [tag "tag1"] [tag "tag2"]
```

### 2. Go Integration Program

**Location:** Create new directory `coraza-rs/ftw-runner/`

**Structure:**
```
ftw-runner/
├── main.go           # Main test harness
├── server.go         # Rust server lifecycle management
├── config.go         # FTW configuration generator
└── go.mod            # Go dependencies
```

**Responsibilities:**
- Verify Rust server binary exists (pre-built separately)
- Start server as subprocess
- Generate `.ftw.yaml` config pointing to server
- Run FTW tests using go-ftw library (imported as dependency)
- Collect and report results
- Gracefully shutdown server

**Key Change:** No build step - assumes `cargo build --example ftw_server` already run
**Key Change:** go-ftw is a Go module dependency, not an external binary

### 3. FTW Configuration

**Auto-generated `.ftw.yaml`:**
```yaml
logfile: /tmp/coraza-ftw-audit.log
logmarkerheadername: X-CRS-Test
testoverride:
  overrides:
    dest_addr: "localhost"
    port: 8080
mode: "default"
```

## Implementation Steps

### Phase 1: Rust HTTP Server (Days 1-2)

**Step 1.1: Create Basic HTTP Server**
```bash
cargo new --example ftw_server
```

Dependencies needed:
```toml
[dependencies]
hyper = { version = "1.0", features = ["full"] }
tokio = { version = "1.0", features = ["full"] }
```

**Step 1.2: Integrate WAF Processing**
- Load CRS rules
- Create transaction per request
- Process all 5 phases
- Return appropriate HTTP status

**Step 1.3: Implement Audit Logging**
- Create ModSecurity-compatible log format
- Write to file specified via CLI arg
- Include rule ID, message, severity, tags

### Phase 2: Go Test Harness (Days 2-3)

**Step 2.1: Server Lifecycle Management**
```go
type Server struct {
    cmd    *exec.Cmd
    port   int
    logfile string
}

func (s *Server) Start() error {
    // Verify binary exists (built separately)
    if _, err := os.Stat("../target/debug/examples/ftw_server"); err != nil {
        return fmt.Errorf("server binary not found - run: cargo build --example ftw_server")
    }

    // Start pre-built server
    s.cmd = exec.Command("../target/debug/examples/ftw_server",
        "--port", fmt.Sprintf("%d", s.port),
        "--logfile", s.logfile,
        "--rules", "./crs-setup.conf")

    // Wait for server ready
    return s.waitForReady()
}
```

**Step 2.2: FTW Integration (Using Library)**
```go
import (
    "github.com/coreruleset/go-ftw/v2/config"
    "github.com/coreruleset/go-ftw/v2/runner"
    "github.com/coreruleset/go-ftw/v2/test"
)

func runFTW() error {
    // Load config
    cfg, err := config.NewConfigFromFile(".ftw-rust.yaml")
    if err != nil {
        return err
    }

    // Load tests
    tests := loadTestsFromDirectory("../coraza-coreruleset/tests")

    // Run tests using go-ftw library
    res, err := runner.Run(cfg, tests, &runner.RunnerConfig{}, output)

    // Report results
    fmt.Printf("Passed: %d, Failed: %d\n",
        len(res.Stats.Run)-len(res.Stats.Failed),
        len(res.Stats.Failed))

    return err
}
```

**Step 2.3: Result Collection**
- Parse FTW output
- Report pass/fail counts
- Identify failing tests

### Phase 3: CRS Rules Loading (Day 3)

**Challenge:** Load actual CRS v4 rules

**Options:**

**Option A: Use coraza-coreruleset embedded FS (from Go codebase)**
- Copy CRS files to coraza-rs
- Load via SecLang parser

**Option B: Download CRS v4 at runtime**
- Script to fetch from GitHub
- Parse and load

**Recommended:** Option A - copy minimal CRS files needed for testing

### Phase 4: Testing & Validation (Day 4)

**Step 4.1: Run Simple Tests**
```bash
cd ftw-runner
go run main.go --rules-dir ../crs-rules --test-dir ../test-basic
```

**Step 4.2: Run Full CRS Test Suite**
```bash
go run main.go \
  --rules-dir ../coraza-coreruleset/rules \
  --test-dir ../coraza-coreruleset/tests
```

**Step 4.3: Analyze Results**
- Expected: ~60-70% pass rate (missing @detectSQLi, @detectXSS)
- Document which tests fail and why
- Validate that pattern-based rules work

## Directory Structure

```
coraza-rs/
├── examples/
│   └── ftw_server.rs          # Rust HTTP server
├── ftw-runner/
│   ├── main.go                 # Go test harness
│   ├── server.go               # Server lifecycle
│   ├── config.go               # FTW config gen
│   ├── go.mod
│   └── README.md
├── crs-rules/                  # CRS v4 rules (copied)
│   ├── crs-setup.conf.example
│   └── rules/
│       └── *.conf
└── FTW_INTEGRATION_PLAN.md     # This file
```

## Code Stubs

### Rust Server Example

```rust
// examples/ftw_server.rs
use std::net::SocketAddr;
use std::sync::Arc;
use hyper::{Body, Request, Response, Server, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use coraza::waf::Waf;
use coraza::config::WafConfig;

#[tokio::main]
async fn main() {
    let waf = Arc::new(load_waf().await.expect("Failed to load WAF"));

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));

    let make_svc = make_service_fn(move |_conn| {
        let waf = Arc::clone(&waf);
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                handle_request(req, Arc::clone(&waf))
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);
    println!("FTW server listening on {}", addr);

    server.await.expect("Server error");
}

async fn handle_request(
    req: Request<Body>,
    waf: Arc<Waf>,
) -> Result<Response<Body>, hyper::Error> {
    let mut tx = waf.new_transaction();

    // Process request through WAF
    tx.process_uri(req.uri().path(), req.method().as_str(), "HTTP/1.1");

    for (name, value) in req.headers() {
        tx.add_request_header(
            name.as_str(),
            value.to_str().unwrap_or("")
        );
    }

    if let Some(interruption) = tx.process_request_headers() {
        write_audit_log(&tx, &interruption);
        return Ok(Response::builder()
            .status(interruption.status)
            .body(Body::from("Blocked by WAF"))
            .unwrap());
    }

    // Process body if present
    let body_bytes = hyper::body::to_bytes(req.into_body()).await?;
    if !body_bytes.is_empty() {
        if let Ok(Some(interruption)) = tx.process_request_body(&body_bytes) {
            write_audit_log(&tx, &interruption);
            return Ok(Response::builder()
                .status(interruption.status)
                .body(Body::from("Blocked by WAF"))
                .unwrap());
        }
    }

    // Simulate response
    let response_body = b"OK";
    tx.add_response_header("Content-Type", "text/plain");

    if let Some(interruption) = tx.process_response_headers(200, "HTTP/1.1") {
        write_audit_log(&tx, &interruption);
        return Ok(Response::builder()
            .status(interruption.status)
            .body(Body::from("Blocked by WAF"))
            .unwrap());
    }

    if let Some(interruption) = tx.process_response_body(response_body) {
        write_audit_log(&tx, &interruption);
        return Ok(Response::builder()
            .status(interruption.status)
            .body(Body::from("Blocked by WAF"))
            .unwrap());
    }

    tx.process_logging();

    Ok(Response::new(Body::from("OK")))
}
```

### Go Test Harness Example

```go
// ftw-runner/main.go
package main

import (
    "fmt"
    "os"
    "os/exec"
    "time"
)

func main() {
    server := &Server{
        port:    8080,
        logfile: "/tmp/coraza-ftw-audit.log",
    }

    fmt.Println("Building Rust server...")
    if err := server.Build(); err != nil {
        fmt.Fprintf(os.Stderr, "Build failed: %v\n", err)
        os.Exit(1)
    }

    fmt.Println("Starting Rust server...")
    if err := server.Start(); err != nil {
        fmt.Fprintf(os.Stderr, "Start failed: %v\n", err)
        os.Exit(1)
    }
    defer server.Stop()

    fmt.Println("Waiting for server ready...")
    time.Sleep(2 * time.Second)

    fmt.Println("Running FTW tests...")
    if err := runFTW(); err != nil {
        fmt.Fprintf(os.Stderr, "FTW failed: %v\n", err)
        os.Exit(1)
    }

    fmt.Println("Tests complete!")
}
```

## Expected Results

### Passing Tests (60-70%)
- Protocol enforcement (920xxx)
- Scanner detection (913xxx)
- Path traversal (930xxx)
- Command injection (932xxx) - pattern-based
- LFI/RFI (931xxx)
- PHP injection (933xxx)
- Session attacks (943xxx)

### Failing Tests (30-40%)
- SQL Injection (942xxx) - needs @detectSQLi
- XSS (941xxx) - needs @detectXSS
- Some advanced CRS features we haven't implemented

### Success Criteria
- ✅ Server starts and loads CRS rules
- ✅ FTW can connect and send requests
- ✅ Pattern-based rules trigger correctly
- ✅ Audit logs are written in correct format
- ✅ At least 60% of CRS tests pass
- ✅ No crashes or panics during test run

## Next Steps

1. **Create examples/ftw_server.rs** - Basic HTTP server
2. **Add hyper/tokio dependencies** - HTTP server framework
3. **Implement audit logging** - ModSecurity-compatible format
4. **Create ftw-runner Go package** - Test harness
5. **Copy minimal CRS rules** - For testing
6. **Run first test** - Validate architecture
7. **Iterate and debug** - Fix issues, improve coverage

## Timeline

- **Day 1:** Rust HTTP server skeleton + WAF integration
- **Day 2:** Audit logging + Go test harness
- **Day 3:** CRS rules loading + first test run
- **Day 4:** Debug, analyze results, documentation

**Estimated Total:** 4 days to full FTW integration

## Benefits

1. **Validation:** Prove Rust implementation matches Go behavior
2. **Regression Testing:** Catch bugs early with CRS test suite
3. **Coverage Measurement:** Know exactly which CRS rules work
4. **Confidence:** Official CRS tests passing = production-ready
5. **Documentation:** Test results show what's implemented

## Future Enhancements

- CI/CD integration (run FTW tests on every commit)
- Performance benchmarking against Go implementation
- Test result dashboard
- Automatic issue creation for failing tests
- Coverage tracking over time
