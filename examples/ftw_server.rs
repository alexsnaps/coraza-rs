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
use coraza::types::RuleEngineStatus;
use coraza::waf::Waf;

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
    let logfile = Arc::new(Mutex::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&logfile)
            .expect("Failed to open logfile"),
    ));

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
fn simple_http_server(addr: SocketAddr, waf: Arc<Waf>, logfile: Arc<Mutex<std::fs::File>>) {
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
    logfile: Arc<Mutex<std::fs::File>>,
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

    // Phase 1: Request Headers
    if let Some(interruption) = tx.process_request_headers() {
        write_audit_log(&logfile, &tx, &interruption, marker_header.as_deref())?;
        return send_blocking_response(stream, &interruption);
    }

    // Read request body if present
    let mut body = Vec::new();
    if content_length > 0 {
        let mut limited_reader = BufReader::new(stream.try_clone()?).take(content_length as u64);
        limited_reader.read_to_end(&mut body)?;
    }

    // Phase 2: Request Body
    if !body.is_empty() {
        match tx.process_request_body(&body) {
            Ok(Some(interruption)) => {
                write_audit_log(&logfile, &tx, &interruption, marker_header.as_deref())?;
                return send_blocking_response(stream, &interruption);
            }
            Err(e) => {
                eprintln!("Error processing request body: {}", e);
                return send_response(stream, 500, "Internal Server Error");
            }
            Ok(None) => {}
        }
    }

    // Simulate response
    tx.add_response_header("Content-Type", "text/plain");

    // Phase 3: Response Headers
    if let Some(interruption) = tx.process_response_headers(200, "HTTP/1.1") {
        write_audit_log(&logfile, &tx, &interruption, marker_header.as_deref())?;
        return send_blocking_response(stream, &interruption);
    }

    let response_body = b"OK";

    // Phase 4: Response Body
    if let Some(interruption) = tx.process_response_body(response_body) {
        write_audit_log(&logfile, &tx, &interruption, marker_header.as_deref())?;
        return send_blocking_response(stream, &interruption);
    }

    // Phase 5: Logging
    tx.process_logging();

    // Write audit log for successful requests (FTW needs this for correlation)
    if let Some(marker_value) = marker_header.as_deref() {
        write_request_log(&logfile, &tx, marker_value)?;
    }

    // Send successful response
    send_response(stream, 200, "OK")
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
    interruption: &coraza::transaction::Interruption,
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

/// Write ModSecurity-compatible audit log for rule triggers
fn write_audit_log(
    logfile: &Arc<Mutex<std::fs::File>>,
    tx: &coraza::transaction::Transaction,
    interruption: &coraza::transaction::Interruption,
    marker: Option<&str>,
) -> std::io::Result<()> {
    let mut file = logfile.lock().unwrap();

    // Format: [timestamp] [rule_id] [msg "message"]
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Write FTW marker header if present (for test correlation)
    if let Some(marker_value) = marker {
        writeln!(file, "[{}] [X-CRS-Test \"{}\"]", timestamp, marker_value)?;
    }

    writeln!(
        file,
        "[{}] [id \"{}\"] [msg \"Rule triggered\"] [data \"{}\"] [severity \"CRITICAL\"]",
        timestamp, interruption.rule_id, interruption.data
    )?;

    // Also write request details for debugging
    writeln!(file, "[{}] [tx_id \"{}\"]", timestamp, tx.id(),)?;

    file.flush()
}

/// Write audit log for successful requests (no rule triggers)
/// FTW needs this for test correlation even when no rules match
fn write_request_log(
    logfile: &Arc<Mutex<std::fs::File>>,
    tx: &coraza::transaction::Transaction,
    marker: &str,
) -> std::io::Result<()> {
    let mut file = logfile.lock().unwrap();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Write marker so FTW can correlate this request
    writeln!(file, "[{}] [X-CRS-Test \"{}\"]", timestamp, marker)?;
    writeln!(file, "[{}] [tx_id \"{}\"]", timestamp, tx.id())?;

    file.flush()
}
