// SPDX-License-Identifier: Apache-2.0

//! FTW Test Server - Async Version
//!
//! Async HTTP server using hyper/tokio for running go-ftw tests against coraza-rs.
//!
//! This server:
//! - Loads CRS rules via SecLang parser
//! - Processes HTTP requests through the WAF (async)
//! - Writes ModSecurity-compatible audit logs
//! - Supports concurrent requests via tokio
//!
//! Usage:
//!   cargo run --example ftw_server_async --features async-server -- \
//!     --port 8080 \
//!     --logfile /tmp/coraza-audit.log \
//!     --rules crs-setup.conf

use std::convert::Infallible;
use std::fs::OpenOptions;
use std::io::Write as IoWrite;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use coraza::config::WafConfig;
use coraza::seclang::Parser;
use coraza::types::RuleEngineStatus;
use coraza::waf::Waf;

#[tokio::main]
async fn main() {
    println!("🛡️  Coraza FTW Test Server (Async)\n");

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

    // Bind to address
    let addr: SocketAddr = format!("127.0.0.1:{}", port)
        .parse()
        .expect("Invalid address");

    let listener = TcpListener::bind(addr).await.expect("Failed to bind");

    println!("🚀 Server listening on http://{}", addr);
    println!("💡 Ready to accept FTW test requests\n");
    println!("✅ Using async HTTP server (hyper/tokio)\n");

    // Accept connections
    loop {
        let (stream, _) = listener.accept().await.expect("Failed to accept");
        let io = TokioIo::new(stream);

        let waf = Arc::clone(&waf);
        let logfile = Arc::clone(&logfile);

        // Spawn a task to handle the connection
        tokio::task::spawn(async move {
            let service =
                service_fn(move |req| handle_request(req, Arc::clone(&waf), Arc::clone(&logfile)));

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}

/// Handle a single HTTP request through the WAF
async fn handle_request(
    req: Request<Incoming>,
    waf: Arc<Waf>,
    logfile: Arc<Mutex<std::fs::File>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // Extract request details
    let method = req.method().as_str();

    // CONNECT requests use authority (host:port) instead of path
    let full_uri = if method == "CONNECT" {
        // For CONNECT, use the authority if present, otherwise path
        req.uri()
            .authority()
            .map(|a| a.to_string())
            .unwrap_or_else(|| req.uri().path().to_string())
    } else {
        // For other methods, use path + query
        let uri = req.uri().path();
        let query = req.uri().query().unwrap_or("");
        if query.is_empty() {
            uri.to_string()
        } else {
            format!("{}?{}", uri, query)
        }
    };
    let protocol = format!("{:?}", req.version());

    println!("📨 {} {} {}", method, full_uri, protocol);

    // Extract marker header
    let marker_header = req
        .headers()
        .get("X-CRS-Test")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Create transaction
    let mut tx = waf.new_transaction();

    // Process request URI
    tx.process_uri(&full_uri, method, &protocol);

    // Add headers
    for (name, value) in req.headers() {
        if let Ok(value_str) = value.to_str() {
            tx.add_request_header(name.as_str(), value_str);
        }
    }

    // Phase 1: Request Headers
    if let Some(interruption) = tx.process_request_headers() {
        write_audit_log(&logfile, &tx, &interruption, marker_header.as_deref());
        return Ok(create_blocking_response(&interruption));
    }

    // Read request body
    let body_bytes = if req.method() == Method::POST || req.method() == Method::PUT {
        match req.collect().await {
            Ok(collected) => collected.to_bytes().to_vec(),
            Err(e) => {
                eprintln!("Error reading body: {}", e);
                return Ok(create_error_response(500, "Internal Server Error"));
            }
        }
    } else {
        Vec::new()
    };

    // Phase 2: Request Body
    if !body_bytes.is_empty() {
        match tx.process_request_body(&body_bytes) {
            Ok(Some(interruption)) => {
                write_audit_log(&logfile, &tx, &interruption, marker_header.as_deref());
                return Ok(create_blocking_response(&interruption));
            }
            Err(e) => {
                eprintln!("Error processing request body: {}", e);
                return Ok(create_error_response(500, "Internal Server Error"));
            }
            Ok(None) => {}
        }
    }

    // Simulate response headers
    tx.add_response_header("Content-Type", "text/plain");

    // Phase 3: Response Headers
    if let Some(interruption) = tx.process_response_headers(200, "HTTP/1.1") {
        write_audit_log(&logfile, &tx, &interruption, marker_header.as_deref());
        return Ok(create_blocking_response(&interruption));
    }

    let response_body = b"OK";

    // Phase 4: Response Body
    if let Some(interruption) = tx.process_response_body(response_body) {
        write_audit_log(&logfile, &tx, &interruption, marker_header.as_deref());
        return Ok(create_blocking_response(&interruption));
    }

    // Phase 5: Logging
    tx.process_logging();

    // Write audit log for successful requests (FTW needs this for correlation)
    if let Some(marker_value) = marker_header.as_deref() {
        write_request_log(&logfile, &tx, marker_value);
    }

    // Send successful response
    Ok(create_success_response("OK"))
}

/// Create a successful HTTP response
fn create_success_response(body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

/// Create an error HTTP response
fn create_error_response(status: u16, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

/// Create a blocking response when WAF interrupts
fn create_blocking_response(
    interruption: &coraza::transaction::Interruption,
) -> Response<Full<Bytes>> {
    println!(
        "🚫 Blocked by rule {}: {}",
        interruption.rule_id, interruption.action
    );
    Response::builder()
        .status(StatusCode::from_u16(interruption.status).unwrap_or(StatusCode::FORBIDDEN))
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from("Blocked by WAF")))
        .unwrap()
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
    _interruption: &coraza::transaction::Interruption,
    marker: Option<&str>,
) {
    let mut file = logfile.lock().unwrap();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Write FTW marker header if present (for test correlation)
    if let Some(marker_value) = marker {
        let _ = writeln!(file, "[{}] [X-CRS-Test \"{}\"]", timestamp, marker_value);
    }

    // Write ALL matched rules (not just the final blocking one)
    // This is critical for CRS test compatibility
    for matched in tx.matched_rules() {
        let _ = writeln!(
            file,
            "[{}] [id \"{}\"] [msg \"{}\"] [data \"{}\"] [severity \"{}\"]",
            timestamp, matched.rule_id, matched.msg, matched.data, matched.severity
        );
    }

    let _ = writeln!(file, "[{}] [tx_id \"{}\"]", timestamp, tx.id());
    let _ = file.flush();
}

/// Write audit log for successful requests (no rule triggers)
/// FTW needs this for test correlation even when no rules match
fn write_request_log(
    logfile: &Arc<Mutex<std::fs::File>>,
    tx: &coraza::transaction::Transaction,
    marker: &str,
) {
    let mut file = logfile.lock().unwrap();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Write marker so FTW can correlate this request
    let _ = writeln!(file, "[{}] [X-CRS-Test \"{}\"]", timestamp, marker);
    let _ = writeln!(file, "[{}] [tx_id \"{}\"]", timestamp, tx.id());
    let _ = file.flush();
}
