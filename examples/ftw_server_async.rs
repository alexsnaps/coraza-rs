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
use coraza::seclang::{compile_sec_action, compile_sec_marker, compile_sec_rule};
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

    // Create WAF
    let config = WafConfig::new()
        .with_rule_engine(RuleEngineStatus::On)
        .with_request_body_access(true)
        .with_response_body_access(true)
        .with_request_body_limit(1048576) // 1MB
        .with_web_app_id("ftw-test".to_string());

    let mut waf = Waf::new(config).expect("Failed to create WAF");

    // Load rules if specified
    if let Some(rules_path) = rules_file {
        println!("📋 Loading rules from {}...", rules_path);
        match load_rules(&mut waf, &rules_path) {
            Ok(count) => {
                println!("✅ Loaded {} rules", count);
                println!("🔗 Linking chained rules...");
                waf.link_chains();
                println!();
            }
            Err(e) => {
                eprintln!("❌ Failed to load rules: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        println!("⚠️  No rules file specified, WAF running without rules\n");
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

/// Load rules from a SecLang file
fn load_rules(waf: &mut Waf, path: &str) -> Result<usize, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read rules file: {}", e))?;

    let mut rules_loaded = 0;
    let lines = process_lines(&content);

    for (line_num, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Parse directive
        if let Some(directive_result) = parse_directive(trimmed) {
            match directive_result {
                Ok((directive_name, directive_args)) => {
                    match directive_name.to_lowercase().as_str() {
                        "secrule" => match compile_sec_rule(&directive_args) {
                            Ok(rule) => {
                                waf.add_rule(rule).map_err(|e| {
                                    format!("Failed to add rule at line {}: {}", line_num + 1, e)
                                })?;
                                rules_loaded += 1;
                            }
                            Err(e) => {
                                eprintln!(
                                    "⚠️  Warning: Failed to compile SecRule at line {}: {}",
                                    line_num + 1,
                                    e
                                );
                            }
                        },
                        "secaction" => match compile_sec_action(&directive_args) {
                            Ok(rule) => {
                                waf.add_rule(rule).map_err(|e| {
                                    format!("Failed to add action at line {}: {}", line_num + 1, e)
                                })?;
                                rules_loaded += 1;
                            }
                            Err(e) => {
                                eprintln!(
                                    "⚠️  Warning: Failed to compile SecAction at line {}: {}",
                                    line_num + 1,
                                    e
                                );
                            }
                        },
                        "secmarker" => match compile_sec_marker(&directive_args) {
                            Ok(rule) => {
                                waf.add_rule(rule).map_err(|e| {
                                    format!("Failed to add marker at line {}: {}", line_num + 1, e)
                                })?;
                                rules_loaded += 1;
                            }
                            Err(e) => {
                                eprintln!(
                                    "⚠️  Warning: Failed to compile SecMarker at line {}: {}",
                                    line_num + 1,
                                    e
                                );
                            }
                        },
                        "secruleengine" => {
                            // Handle engine configuration
                            match directive_args.to_lowercase().as_str() {
                                "on" => println!("   SecRuleEngine: On"),
                                "off" => println!("   SecRuleEngine: Off"),
                                "detectiononly" => println!("   SecRuleEngine: DetectionOnly"),
                                _ => eprintln!(
                                    "⚠️  Warning: Unknown SecRuleEngine value: {}",
                                    directive_args
                                ),
                            }
                        }
                        "secrequestbodyaccess" => {
                            println!("   SecRequestBodyAccess: {}", directive_args);
                        }
                        "include" => {
                            // Recursively load included file
                            match load_rules(waf, directive_args.trim()) {
                                Ok(count) => {
                                    println!(
                                        "   Included {} rules from {}",
                                        count,
                                        directive_args.trim()
                                    );
                                    rules_loaded += count;
                                }
                                Err(e) => {
                                    eprintln!(
                                        "⚠️  Warning: Failed to include {}: {}",
                                        directive_args.trim(),
                                        e
                                    );
                                }
                            }
                        }
                        _ => {
                            // Silently ignore other directives for now
                        }
                    }
                }
                Err(e) => {
                    eprintln!("⚠️  Warning: Failed to parse line {}: {}", line_num + 1, e);
                }
            }
        }
    }

    Ok(rules_loaded)
}

/// Process file content into logical lines (handling line continuations)
fn process_lines(content: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current_line = String::new();

    for line in content.lines() {
        let trimmed = line.trim_end();

        // Check for line continuation
        if let Some(without_backslash) = trimmed.strip_suffix('\\') {
            // Remove the backslash and append to current line
            current_line.push_str(without_backslash);
            current_line.push(' '); // Add space between continued lines
        } else {
            // Complete the current line
            current_line.push_str(trimmed);
            result.push(current_line.clone());
            current_line.clear();
        }
    }

    // Add any remaining partial line
    if !current_line.is_empty() {
        result.push(current_line);
    }

    result
}

/// Parse a directive line into (directive_name, arguments)
fn parse_directive(line: &str) -> Option<Result<(String, String), String>> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Find the first whitespace to split directive from args
    if let Some(space_pos) = trimmed.find(|c: char| c.is_whitespace()) {
        let directive = trimmed[..space_pos].to_string();
        let args = trimmed[space_pos..].trim().to_string();
        Some(Ok((directive, args)))
    } else {
        // Directive with no arguments (e.g., "SecRuleEngine")
        Some(Ok((trimmed.to_string(), String::new())))
    }
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

    let _ = writeln!(
        file,
        "[{}] [id \"{}\"] [msg \"Rule triggered\"] [data \"{}\"] [severity \"CRITICAL\"]",
        timestamp, interruption.rule_id, interruption.data
    );

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
