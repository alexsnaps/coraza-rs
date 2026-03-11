// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Simple WAF Example
//!
//! This example demonstrates:
//! - Creating a WAF with configuration
//! - Adding security rules
//! - Creating transactions
//! - Processing HTTP request/response lifecycle
//! - Simulating both benign and malicious requests
//!
//! Run with: cargo run --example simple

use coraza::actions::{DenyAction, StatusAction};
use coraza::config::WafConfig;
use coraza::operators::contains;
use coraza::rules::{Rule, RuleAction, RuleOperator, VariableSpec};
use coraza::types::{RuleEngineStatus, RulePhase, RuleVariable};
use coraza::waf::Waf;

fn main() {
    println!("🛡️  Coraza WAF - Simple Example\n");

    // Step 1: Create WAF with configuration
    println!("📝 Step 1: Creating WAF with configuration...");
    let config = WafConfig::new()
        .with_rule_engine(RuleEngineStatus::On)
        .with_request_body_access(true)
        .with_response_body_access(true)
        .with_request_body_limit(1048576) // 1MB
        .with_web_app_id("demo-app".to_string());

    let mut waf = Waf::new(config).expect("Failed to create WAF");
    println!("✅ WAF created with configuration\n");

    // Step 2: Add security rules
    println!("📋 Step 2: Adding security rules...");

    // Rule 1: Block requests with "malicious" in query parameters
    let mut rule1 = Rule::new()
        .with_id(100)
        .add_variable(VariableSpec::new(RuleVariable::ArgsGet))
        .with_operator(RuleOperator::new(
            contains("malicious").unwrap().into(),
            "@contains",
            "malicious".to_string(),
        ))
        .add_action(RuleAction::new("deny", Box::new(DenyAction)))
        .add_action(RuleAction::new("status", Box::new(StatusAction)));
    rule1.metadata_mut().phase = RulePhase::RequestHeaders;
    rule1.metadata_mut().status = 403;

    // Rule 2: Block requests with "attack" in POST body
    let mut rule2 = Rule::new()
        .with_id(101)
        .add_variable(VariableSpec::new(RuleVariable::ArgsPost))
        .with_operator(RuleOperator::new(
            contains("attack").unwrap().into(),
            "@contains",
            "attack".to_string(),
        ))
        .add_action(RuleAction::new("deny", Box::new(DenyAction)))
        .add_action(RuleAction::new("status", Box::new(StatusAction)));
    rule2.metadata_mut().phase = RulePhase::RequestBody;
    rule2.metadata_mut().status = 403;

    waf.add_rule(rule1).expect("Failed to add rule 100");
    waf.add_rule(rule2).expect("Failed to add rule 101");

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
    println!("Rule 100 exists: {}", waf.find_rule_by_id(100).is_some());
    println!("Rule 101 exists: {}", waf.find_rule_by_id(101).is_some());

    println!("\n🎉 Example complete! The Coraza WAF infrastructure is ready.");
    println!("\n💡 Summary: This example demonstrated:");
    println!("   ✅ WAF configuration and rule loading");
    println!("   ✅ Transaction lifecycle (5 phases)");
    println!("   ✅ Variable population (ARGS_GET, ARGS_POST, headers, cookies)");
    println!("   ✅ Body processing (URL-encoded forms)");
    println!("\n📚 Next steps:");
    println!("   - Full automatic rule evaluation during phase processing (future enhancement)");
    println!("   - Load CRS v4 rules from SecLang files");
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

    tx.process_logging();
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
    if let Ok(Some(interruption)) = tx.process_request_body(body.as_bytes()) {
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

    tx.process_logging();
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
