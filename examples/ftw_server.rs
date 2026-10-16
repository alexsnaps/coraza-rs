// SPDX-License-Identifier: Apache-2.0

//! FTW Test Server
//!
//! HTTP server for running go-ftw (Framework for Testing WAFs) tests against coraza-rs.
//!
//! This server:
//! - Loads CRS rules via SecLang parser
//! - Processes HTTP requests through the WAF
//! - Writes ModSecurity-compatible audit logs
//! - Supports FTW test requirements
//!
//! Usage:
//!   cargo run --example ftw_server -- \
//!     --port 8080 \
//!     --logfile /tmp/coraza-audit.log \
//!     --rules crs-setup.conf
//!
//! Run with: cargo run --example ftw_server

use std::fs::OpenOptions;
use std::io::Write as IoWrite;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use coraza::config::WafConfig;
use coraza::seclang::Parser;
use coraza::transaction::{Interruption, Transaction};
use coraza::types::RuleEngineStatus;
use coraza::waf::Waf;

/// The log FTW reads: request markers and Go Coraza's error log lines.
type Logfile = Arc<Mutex<std::fs::File>>;

// Note: We'll use a simple HTTP server for now
// In production, we'd use hyper/axum/tokio
// For this example, we'll use std::net for simplicity

fn main() {
    println!("🛡️  Coraza FTW Test Server\n");

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let port = get_arg(&args, "--port").unwrap_or("8080".to_string());
    let logfile = get_arg(&args, "--logfile").unwrap_or("/tmp/coraza-ftw-audit.log".to_string());
    let rules_file = get_arg(&args, "--rules");

    println!("📝 Configuration:");
    println!("   Port: {}", port);
    println!("   Logfile: {}", logfile);
    if let Some(ref rules) = rules_file {
        println!("   Rules: {}", rules);
    }
    println!();

    let logfile: Logfile = Arc::new(Mutex::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&logfile)
            .expect("Failed to open logfile"),
    ));

    // Base configuration; directives in the rules file override it
    let mut parser = Parser::new();
    *parser.config_mut() = WafConfig {
        rule_engine: RuleEngineStatus::On,
        request_body_access: true,
        response_body_access: true,
        request_body_limit: 1048576, // 1MB
        web_app_id: "ftw-test".to_string(),
        ..WafConfig::default()
    };
    // Keep loading past directives this engine doesn't support yet, so a full CRS still loads
    parser.skip_failed_directives();
    log_errors_to(&mut parser, &logfile);

    // Load rules if specified
    if let Some(rules_path) = &rules_file {
        println!("📋 Loading rules from {}...", rules_path);
        if let Err(e) = parser.from_file(rules_path) {
            eprintln!("❌ Failed to load rules: {}", e);
            std::process::exit(1);
        }
        for e in parser.skipped() {
            eprintln!("⚠️  Warning: skipped {}", e);
        }
    } else {
        println!("⚠️  No rules file specified, WAF running without rules\n");
    }

    let waf = parser.into_waf().expect("Failed to create WAF");
    if rules_file.is_some() {
        println!("✅ Loaded {} rules\n", waf.rule_count());
    }

    // Create shared state
    let waf = Arc::new(waf);

    // Start HTTP server
    let addr: SocketAddr = format!("127.0.0.1:{}", port)
        .parse()
        .expect("Invalid address");

    println!("🚀 Server listening on http://{}", addr);
    println!("💡 Ready to accept FTW test requests\n");
    println!("Press Ctrl+C to stop\n");

    // Note: This is a placeholder
    // In a real implementation, we'd use hyper/axum/actix-web
    // For now, we'll create a simple proof-of-concept structure

    simple_http_server(addr, waf, logfile);
}

/// Simple HTTP server (placeholder - needs async runtime in real implementation)
fn simple_http_server(addr: SocketAddr, waf: Arc<Waf>, logfile: Logfile) {
    use std::net::TcpListener;

    let listener = TcpListener::bind(addr).expect("Failed to bind");

    println!("⚠️  Warning: Using simple sync HTTP server for demo");
    println!("   In production, this should use hyper/tokio\n");

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let waf = Arc::clone(&waf);
                let logfile = Arc::clone(&logfile);

                if let Err(e) = handle_request(&mut stream, waf, logfile) {
                    eprintln!("Request handling error: {}", e);
                }
            }
            Err(e) => {
                eprintln!("Connection error: {}", e);
            }
        }
    }
}

/// Handle a single HTTP request through the WAF
fn handle_request(
    stream: &mut std::net::TcpStream,
    waf: Arc<Waf>,
    logfile: Logfile,
) -> std::io::Result<()> {
    use std::io::{BufRead, BufReader, Read};

    let reader = BufReader::new(stream.try_clone()?);
    let mut lines = reader.lines();

    // Parse request line
    let request_line = match lines.next() {
        Some(Ok(line)) => line,
        _ => return Ok(()),
    };

    println!("📨 {}", request_line);

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        return send_response(stream, 400, "Bad Request");
    }

    let method = parts[0];
    let uri = parts[1];
    let protocol = parts[2];

    // Create transaction
    let mut tx = waf.new_transaction();

    // Process request URI
    tx.process_uri(uri, method, protocol);

    // Parse and add headers
    let mut content_length = 0;
    let mut marker_header = None;

    while let Some(Ok(line)) = lines.next() {
        if line.is_empty() {
            break; // End of headers
        }

        if let Some(colon_pos) = line.find(':') {
            let name = &line[..colon_pos].trim();
            let value = &line[colon_pos + 1..].trim();

            // Track Content-Length
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().unwrap_or(0);
            }

            // Track FTW marker header
            if name.eq_ignore_ascii_case("X-CRS-Test") {
                marker_header = Some(value.to_string());
            }

            tx.add_request_header(name, value);
        }
    }

    // Before the request's own error log lines, which FTW looks for after it
    if let Some(marker) = &marker_header {
        write_marker(&logfile, marker)?;
    }

    let interruption = run_transaction(&mut tx, || {
        let mut body = Vec::new();
        if content_length > 0 {
            let mut limited_reader =
                BufReader::new(stream.try_clone()?).take(content_length as u64);
            limited_reader.read_to_end(&mut body)?;
        }
        Ok(body)
    })?;

    // As Go Coraza's HTTP middleware does, whether or not the transaction was interrupted
    tx.process_logging()?;

    match interruption {
        Some(interruption) => send_blocking_response(stream, &interruption),
        None => send_response(stream, 200, "OK"),
    }
}

/// Runs `tx`'s phases, with the request body `read_body` reads once its headers passed,
/// and a simulated `200 OK` response; the interruption, if one stops them.
fn run_transaction(
    tx: &mut Transaction,
    read_body: impl FnOnce() -> std::io::Result<Vec<u8>>,
) -> std::io::Result<Option<Interruption>> {
    if let Some(interruption) = tx.process_request_headers() {
        return Ok(Some(interruption));
    }

    // Phase 2 runs with or without a body
    let body = read_body()?;
    if let Some(interruption) = tx.process_request_body(&body) {
        return Ok(Some(interruption));
    }

    tx.add_response_header("Content-Type", "text/plain");
    if let Some(interruption) = tx.process_response_headers(200, "HTTP/1.1") {
        return Ok(Some(interruption));
    }
    Ok(tx.process_response_body(b"OK"))
}

/// Send HTTP response
fn send_response(stream: &mut std::net::TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    use std::io::Write;

    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        _ => "Error",
    };

    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
        status,
        status_text,
        body.len(),
        body
    );

    stream.write_all(response.as_bytes())
}

/// Send blocking response when WAF interrupts
fn send_blocking_response(
    stream: &mut std::net::TcpStream,
    interruption: &Interruption,
) -> std::io::Result<()> {
    println!(
        "🚫 Blocked by rule {}: {}",
        interruption.rule_id, interruption.action
    );
    send_response(stream, interruption.status, "Blocked by WAF")
}

/// Get command line argument value
fn get_arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|pos| args.get(pos + 1))
        .cloned()
}

/// Has the WAF write Go Coraza's error log line to `logfile` for each matched rule with
/// `log`, as its CRS test harness reads it.
fn log_errors_to(parser: &mut Parser, logfile: &Logfile) {
    let logfile = Arc::clone(logfile);
    parser.on_error_log(move |matched| {
        let mut file = logfile.lock().unwrap();
        // A line FTW can't read fails the test that looks for it
        let _ = writeln!(file, "{}", matched.error_log());
    });
}

/// Writes the FTW marker of a request, by which FTW finds the request's lines.
fn write_marker(logfile: &Logfile, marker: &str) -> std::io::Result<()> {
    let mut file = logfile.lock().unwrap();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    writeln!(file, "[{}] [X-CRS-Test \"{}\"]", timestamp, marker)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    use super::*;

    fn waf(rules: &str) -> Waf {
        let mut parser = Parser::new();
        parser.from_string(rules).expect("rules should parse");
        parser.into_waf().expect("config should be valid")
    }

    /// The response the server sends for `request`.
    fn respond(waf: Waf, request: &str) -> String {
        respond_logging_to(
            waf,
            request,
            Arc::new(Mutex::new(tempfile::tempfile().unwrap())),
        )
    }

    /// The response the server sends for `request`, writing FTW's log to `logfile`.
    fn respond_logging_to(waf: Waf, request: &str, logfile: Logfile) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client.write_all(request.as_bytes()).unwrap();
        let (mut server, _) = listener.accept().unwrap();

        handle_request(&mut server, Arc::new(waf), logfile).unwrap();
        drop(server);

        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    fn requests_without_a_body_run_the_request_body_phase() {
        // As in Go's connectors; CRS blocks on the inbound anomaly score in phase 2
        let waf = waf(r#"SecRule REQUEST_METHOD "@streq GET" "id:1,phase:2,deny,status:403""#);

        let response = respond(waf, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");

        assert!(response.starts_with("HTTP/1.1 403 "), "{response}");
    }

    #[test]
    fn interrupted_requests_run_the_logging_phase() {
        let dir = tempfile::tempdir().unwrap();
        let audit_log = dir.path().join("audit.log");
        let waf = waf(&format!(
            r#"
            SecAuditEngine On
            SecAuditLog {}
            SecRule REQUEST_METHOD "@streq GET" "id:1,phase:1,deny,status:403"
            "#,
            audit_log.display()
        ));

        let response = respond(waf, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");

        assert!(response.starts_with("HTTP/1.1 403 "), "{response}");
        // The logging phase writes the audit log
        let audit = std::fs::read_to_string(&audit_log).unwrap_or_default();
        assert!(!audit.is_empty(), "no audit log entry");
    }

    #[test]
    fn the_marker_comes_before_the_error_log_lines_of_its_request() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ftw.log");
        let logfile: Logfile = Arc::new(Mutex::new(std::fs::File::create(&path).unwrap()));
        let mut parser = Parser::new();
        log_errors_to(&mut parser, &logfile);
        parser
            .from_string(
                r#"SecRule REQUEST_METHOD "@streq GET" "id:1,phase:1,deny,status:403,log""#,
            )
            .unwrap();
        let waf = parser.into_waf().unwrap();

        let request = "GET / HTTP/1.1\r\nHost: localhost\r\nX-CRS-Test: abc\r\n\r\n";
        respond_logging_to(waf, request, logfile);

        let log = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 2, "{log}");
        assert!(lines[0].ends_with(r#"[X-CRS-Test "abc"]"#), "{log}");
        assert!(lines[1].contains(r#"[id "1"]"#), "{log}");
    }
}
