// SPDX-License-Identifier: Apache-2.0

//! Simple WAF Example
//!
//! This example demonstrates:
//! - Creating a WAF from SecLang configuration and rules
//! - Creating transactions
//! - Processing HTTP request/response lifecycle
//! - Simulating both benign and malicious requests
//!
//! Run with: cargo run --example simple

use coraza::seclang::Parser;
use coraza::waf::Waf;

/// The WAF's configuration and rules, as SecLang directives.
const DIRECTIVES: &str = r#"
    SecRuleEngine On
    SecRequestBodyAccess On
    SecResponseBodyAccess On
    SecRequestBodyLimit 1048576
    SecWebAppId demo-app

    # Block requests with "malicious" in query parameters
    SecRule ARGS_GET "@contains malicious" "id:100,phase:1,deny,status:403"
    # Block requests with "attack" in POST body
    SecRule ARGS_POST "@contains attack" "id:101,phase:2,deny,status:403"
"#;

fn main() {
    println!("🛡️  Coraza WAF - Simple Example\n");

    // Step 1: Load the configuration and rules
    println!("📝 Step 1: Loading the configuration and security rules...");
    let mut parser = Parser::new();
    parser
        .from_string(DIRECTIVES)
        .expect("Failed to load the directives");
    let waf = parser.into_waf().expect("Failed to build WAF");
    println!("✅ WAF created with configuration\n");

    // Step 2: Show the rules
    println!("📋 Step 2: Security rules");
    println!("✅ Rule 100: Block 'malicious' in query params (Phase 1)");
    println!("✅ Rule 101: Block 'attack' in POST body (Phase 2)");
    println!("📊 Total rules loaded: {}\n", waf.rule_count());

    // Step 3: Demonstrate request processing
    println!("🔄 Step 3: Processing HTTP requests...\n");

    // Test 1: Benign GET request
    println!("{}", "=".repeat(70));
    println!("🟢 Test 1: Benign GET Request");
    println!("{}", "=".repeat(70));
    process_get_request(&waf, "/search?q=rust+programming");
    println!();

    // Test 2: Malicious GET request
    println!("{}", "=".repeat(70));
    println!("🔴 Test 2: Malicious GET Request (contains 'malicious')");
    println!("{}", "=".repeat(70));
    process_get_request(&waf, "/search?input=malicious_payload");
    println!();

    // Test 3: Benign POST request
    println!("{}", "=".repeat(70));
    println!("🟢 Test 3: Benign POST Request");
    println!("{}", "=".repeat(70));
    process_post_request(&waf, "/api/comment", "comment=Hello+World");
    println!();

    // Test 4: Malicious POST request
    println!("{}", "=".repeat(70));
    println!("🔴 Test 4: Malicious POST Request (contains 'attack')");
    println!("{}", "=".repeat(70));
    process_post_request(&waf, "/api/comment", "comment=This+is+an+attack");
    println!();

    // Step 4: Show WAF statistics
    println!("📊 Step 4: WAF Statistics");
    println!("{}", "=".repeat(70));
    println!("Rules loaded: {}", waf.rule_count());

    println!("\n🎉 Example complete! The Coraza WAF infrastructure is ready.");
    println!("\n💡 Summary: This example demonstrated:");
    println!("   ✅ WAF configuration and rule loading");
    println!("   ✅ Transaction lifecycle (5 phases)");
    println!("   ✅ Variable population (ARGS_GET, ARGS_POST, headers, cookies)");
    println!("   ✅ Body processing (URL-encoded forms)");
    println!("\n📚 Next steps:");
    println!("   - Load CRS v4 rules with Parser::from_file");
    println!("   - Integrate with web servers (Caddy, nginx, etc.)");
}

/// Process a GET request through the WAF
fn process_get_request(waf: &Waf, uri: &str) {
    println!("📨 GET {}", uri);

    let mut tx = waf.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1");
    tx.add_request_header("User-Agent", "Mozilla/5.0");
    tx.add_request_header("Host", "example.com");

    // Process Phase 1 and check for interruption
    if let Some(interruption) = tx.process_request_headers() {
        print_blocked(&interruption);
        return;
    }
    println!("⚙️  Phase 1: Request headers processed");
    println!("   └─ Variables populated: ARGS_GET, REQUEST_URI, REQUEST_HEADERS");

    tx.add_response_header("Content-Type", "text/html");
    let _ = tx.process_response_headers(200, "HTTP/1.1");
    println!("⚙️  Phase 3: Response headers processed");

    let _ = tx.process_response_body(b"OK");
    println!("⚙️  Phase 4: Response body processed");

    tx.process_logging().expect("writing the audit log");
    println!("⚙️  Phase 5: Logging complete");
    println!("✅ Transaction completed successfully");
}

/// Process a POST request through the WAF
fn process_post_request(waf: &Waf, uri: &str, body: &str) {
    println!("📨 POST {}", uri);
    println!("   Body: {}", body);

    let mut tx = waf.new_transaction();
    tx.process_uri(uri, "POST", "HTTP/1.1");
    tx.add_request_header("User-Agent", "Mozilla/5.0");
    tx.add_request_header("Host", "example.com");
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");

    // Process Phase 1 and check for interruption
    if let Some(interruption) = tx.process_request_headers() {
        print_blocked(&interruption);
        return;
    }
    println!("⚙️  Phase 1: Request headers processed");

    // Process Phase 2 and check for interruption
    if let Some(interruption) = tx.process_request_body(body.as_bytes()) {
        print_blocked(&interruption);
        return;
    }
    println!("⚙️  Phase 2: Request body processed");
    println!("   └─ Variables populated: ARGS_POST, REQUEST_BODY");

    tx.add_response_header("Content-Type", "application/json");
    let _ = tx.process_response_headers(200, "HTTP/1.1");
    println!("⚙️  Phase 3: Response headers processed");

    let _ = tx.process_response_body(b"{\"status\":\"ok\"}");
    println!("⚙️  Phase 4: Response body processed");

    tx.process_logging().expect("writing the audit log");
    println!("⚙️  Phase 5: Logging complete");
    println!("✅ Transaction completed successfully");
}

/// Print information about a blocked request
fn print_blocked(interruption: &coraza::transaction::Interruption) {
    println!("\n🚫 REQUEST BLOCKED!");
    println!("   Action: {}", interruption.action);
    println!("   Status: {}", interruption.status);
    println!("   Rule ID: {}", interruption.rule_id);
    if !interruption.data.is_empty() {
        println!("   Matched Data: {}", interruption.data);
    }
}
