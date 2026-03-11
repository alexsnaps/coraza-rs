// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for Phase 9: Transaction Enhancements
//!
//! These tests validate that all Phase 9 components work together:
//! - Body processors (URL-encoded, multipart, JSON, XML)
//! - Variable population (connection, headers, body)
//! - Phase processing with rule evaluation
//! - CTL action execution
//! - Flow control (skip, skipAfter)
//! - Deferred actions (exec, expirevar, setenv, initcol)

use coraza::actions::{ActionType, Rule as ActionRule};
use coraza::body_processors::{BodyProcessorOptions, get_body_processor};
use coraza::collection::Keyed;
use coraza::rules::{Rule, RuleGroup};
use coraza::transaction::{Interruption, Transaction};
use coraza::{RulePhase, RuleVariable};

// ===== Body Processor Integration Tests =====

#[test]
fn test_urlencoded_body_processing() {
    let mut tx = Transaction::new("urlencoded-test");

    // Process URL-encoded body
    let processor = get_body_processor("urlencoded").unwrap();
    let body = b"username=admin&password=secret123&remember=true";

    processor
        .process_request(body, &mut tx, &BodyProcessorOptions::default())
        .unwrap();

    // Verify ARGS_POST populated
    assert_eq!(tx.args_post().get("username"), vec!["admin"]);
    assert_eq!(tx.args_post().get("password"), vec!["secret123"]);
    assert_eq!(tx.args_post().get("remember"), vec!["true"]);

    // Verify REQUEST_BODY stored
    assert_eq!(
        tx.request_body(),
        "username=admin&password=secret123&remember=true"
    );
}

#[test]
fn test_json_body_processing() {
    let mut tx = Transaction::new("json-test");

    // Process JSON body
    let processor = get_body_processor("json").unwrap();
    let body = br#"{"user": {"name": "admin", "role": "super"}, "items": [1, 2, 3]}"#;

    processor
        .process_request(body, &mut tx, &BodyProcessorOptions::default())
        .unwrap();

    // Verify flattened JSON in ARGS_POST
    assert_eq!(tx.args_post().get("json.user.name"), vec!["admin"]);
    assert_eq!(tx.args_post().get("json.user.role"), vec!["super"]);
    assert_eq!(tx.args_post().get("json.items"), vec!["3"]); // array length
    assert_eq!(tx.args_post().get("json.items.0"), vec!["1"]);
}

#[test]
fn test_xml_body_processing() {
    let mut tx = Transaction::new("xml-test");

    // Process XML body
    let processor = get_body_processor("xml").unwrap();
    let body = br#"<user role="admin"><name>John</name></user>"#;

    processor
        .process_request(body, &mut tx, &BodyProcessorOptions::default())
        .unwrap();

    // Verify attributes and content extracted
    let attrs = tx.request_xml().get("//@*");
    assert_eq!(attrs, vec!["admin"]);

    let content = tx.request_xml().get("/*");
    assert_eq!(content, vec!["John"]);
}

// ===== Variable Population Integration Tests =====

#[test]
fn test_full_request_variable_population() {
    let mut tx = Transaction::new("full-request-test");

    // Phase 1: Connection variables
    tx.process_connection("192.168.1.100", 54321, "10.0.0.1", 443);
    tx.set_server_name("example.com");

    assert_eq!(tx.remote_addr(), "192.168.1.100");
    assert_eq!(tx.remote_port(), "54321");
    assert_eq!(tx.server_addr(), "10.0.0.1");
    assert_eq!(tx.server_port(), "443");
    assert_eq!(tx.server_name(), "example.com");

    // Phase 2: Request headers and URI
    tx.process_uri("/api/users?id=123", "POST", "HTTP/1.1");
    tx.add_request_header("Host", "example.com");
    tx.add_request_header("User-Agent", "Mozilla/5.0");
    tx.add_request_header("Cookie", "session=abc123; user=admin");

    assert_eq!(tx.request_method(), "POST");
    assert_eq!(tx.request_uri(), "/api/users");
    assert_eq!(tx.request_protocol(), "HTTP/1.1");
    assert_eq!(tx.query_string(), "id=123");
    assert_eq!(tx.args_get().get("id"), vec!["123"]);

    // Verify headers
    assert_eq!(tx.request_headers().get("host"), vec!["example.com"]);
    assert_eq!(tx.request_headers().get("user-agent"), vec!["Mozilla/5.0"]);

    // Verify cookies parsed
    assert_eq!(tx.request_cookies().get("session"), vec!["abc123"]);
    assert_eq!(tx.request_cookies().get("user"), vec!["admin"]);
}

#[test]
fn test_response_variable_population() {
    let mut tx = Transaction::new("response-test");

    // Populate response headers
    tx.add_response_header("Content-Type", "application/json; charset=utf-8");
    tx.add_response_header("X-Custom", "test-value");

    // Process response headers phase
    let interruption = tx.process_response_headers(200, "HTTP/1.1");
    assert!(interruption.is_none());

    // Verify response variables
    assert_eq!(tx.response_status(), "200");
    assert_eq!(tx.response_protocol(), "HTTP/1.1");
    assert_eq!(tx.response_content_type(), "application/json");
    assert_eq!(
        tx.response_headers().get("content-type"),
        vec!["application/json; charset=utf-8"]
    );
}

// ===== Phase Processing Integration Tests =====

#[test]
fn test_phase_processing_with_interruption() {
    let mut tx = Transaction::new("phase-interrupt-test");

    // Process request body
    let body = b"username=admin&password=test";
    let result = tx.process_request_body(body);
    assert!(result.is_ok());

    // Simulate an interruption
    tx.set_interruption(Some(Interruption {
        rule_id: 123,
        action: "deny".to_string(),
        status: 403,
        data: String::new(),
    }));

    // Try to process response headers - should return the interruption
    let interruption = tx.process_response_headers(200, "HTTP/1.1");
    assert!(interruption.is_some());
    let int = interruption.unwrap();
    assert_eq!(int.action, "deny");
    assert_eq!(int.status, 403);
}

#[test]
fn test_phase_prevents_duplicate_processing() {
    let mut tx = Transaction::new("phase-duplicate-test");

    // Process connection
    tx.process_connection("127.0.0.1", 8080, "10.0.0.1", 80);

    // Try to process connection again
    tx.process_connection("192.168.1.1", 9090, "10.0.0.2", 443);

    // First values should be preserved (duplicate processing prevented)
    assert_eq!(tx.remote_addr(), "127.0.0.1");
    assert_eq!(tx.remote_port(), "8080");
}

// ===== CTL Action Integration Tests =====

#[test]
fn test_ctl_modifies_transaction_settings() {
    use coraza::types::RuleEngineStatus;

    let mut tx = Transaction::new("ctl-test");

    // Default values
    assert_eq!(tx.rule_engine(), RuleEngineStatus::On);
    assert!(tx.request_body_access());
    assert_eq!(tx.request_body_limit(), 131072); // 128KB

    // Modify via CTL-like setters (simulating CTL action execution)
    tx.set_rule_engine(RuleEngineStatus::DetectionOnly);
    tx.set_request_body_access(false);
    tx.set_request_body_limit(262144); // 256KB

    // Verify changes
    assert_eq!(tx.rule_engine(), RuleEngineStatus::DetectionOnly);
    assert!(!tx.request_body_access());
    assert_eq!(tx.request_body_limit(), 262144);
}

#[test]
fn test_ctl_phase_restrictions() {
    let mut tx = Transaction::new("ctl-phase-test");

    // Request body access can be changed before request body phase
    tx.set_request_body_access(false);
    assert!(!tx.request_body_access());

    // Process request body phase
    let _ = tx.process_request_body(b"test=data");

    // Now we're in/past request body phase - verify phase tracking
    assert_eq!(tx.last_phase(), Some(RulePhase::RequestBody));
}

// ===== Flow Control Integration Tests =====

#[test]
fn test_skip_and_skipafter_with_rulegroup() {
    let mut group = RuleGroup::new();

    // Add 5 rules for RequestHeaders phase
    for id in 1..=5 {
        let mut rule = Rule::new().with_id(id);
        rule.metadata_mut().phase = RulePhase::RequestHeaders;
        group.add(rule).unwrap();
    }

    let mut tx = Transaction::new("flow-control-test");

    // Set skip = 2
    tx.set_skip(2);

    // Evaluate - should skip 2 rules
    group.eval(RulePhase::RequestHeaders, &mut tx, true);

    // Skip counter should be decremented to 0
    assert_eq!(tx.skip(), 0);
}

#[test]
fn test_skipafter_finds_marker() {
    let mut group = RuleGroup::new();

    // Add rules with a marker
    let mut rule1 = Rule::new().with_id(1);
    rule1.metadata_mut().phase = RulePhase::RequestHeaders;
    group.add(rule1).unwrap();

    // Add SecMarker
    let mut marker = Rule::new().with_id(0);
    marker.metadata_mut().phase = RulePhase::RequestHeaders;
    marker.metadata_mut().sec_mark = Some("END_BLOCK".to_string());
    group.add(marker).unwrap();

    let mut rule2 = Rule::new().with_id(2);
    rule2.metadata_mut().phase = RulePhase::RequestHeaders;
    group.add(rule2).unwrap();

    let mut tx = Transaction::new("skipafter-test");
    tx.set_skip_after("END_BLOCK");

    // Evaluate - should find marker and clear skip_after
    group.eval(RulePhase::RequestHeaders, &mut tx, true);

    assert!(tx.skip_after().is_empty());
}

// ===== Deferred Actions Integration Tests =====

#[test]
fn test_setenv_action_execution() {
    use coraza::actions::get;

    let mut action = get("setenv").unwrap();
    let mut rule = ActionRule::new();

    // Initialize with key=value
    action.init(&mut rule, "TEST_VAR=test_value").unwrap();
    assert_eq!(action.action_type(), ActionType::Nondisruptive);

    // Execute (sets environment variable)
    use coraza::operators::TransactionState;
    struct MockTx;
    impl TransactionState for MockTx {
        fn get_variable(&self, _var: RuleVariable, _key: Option<&str>) -> Option<String> {
            None
        }
    }

    let mut tx = MockTx;
    action.evaluate(&rule, &mut tx);

    // Verify environment variable was set
    assert_eq!(std::env::var("TEST_VAR").unwrap(), "test_value");

    // Cleanup
    unsafe {
        std::env::remove_var("TEST_VAR");
    }
}

#[test]
fn test_exec_action_is_safe_stub() {
    use coraza::actions::get;

    // Exec should be registered but not execute anything
    let mut action = get("exec").unwrap();
    let mut rule = ActionRule::new();

    // Should parse script path
    action.init(&mut rule, "/usr/bin/test.sh").unwrap();

    // Execute should be safe (no-op)
    use coraza::operators::TransactionState;
    struct MockTx;
    impl TransactionState for MockTx {
        fn get_variable(&self, _var: RuleVariable, _key: Option<&str>) -> Option<String> {
            None
        }
    }

    let mut tx = MockTx;
    action.evaluate(&rule, &mut tx); // Should not crash or execute anything
}

// ===== Combined Scenario Tests =====

#[test]
fn test_complete_transaction_flow() {
    let mut tx = Transaction::new("complete-flow-test");

    // 1. Connection phase
    tx.process_connection("192.168.1.1", 12345, "10.0.0.1", 443);
    assert_eq!(tx.remote_addr(), "192.168.1.1");

    // 2. Request headers phase
    tx.process_uri("/api/login?redirect=/dashboard", "POST", "HTTP/1.1");
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
    tx.add_request_header("User-Agent", "curl/7.68.0");

    assert_eq!(tx.request_method(), "POST");
    assert_eq!(tx.request_uri(), "/api/login");
    assert_eq!(tx.args_get().get("redirect"), vec!["/dashboard"]);

    // 3. Request body phase with URL-encoded data
    let body = b"username=admin&password=P%40ssw0rd";
    let result = tx.process_request_body(body);
    assert!(result.is_ok());

    // Verify body was processed
    assert_eq!(tx.args_post().get("username"), vec!["admin"]);
    assert_eq!(tx.args_post().get("password"), vec!["P@ssw0rd"]); // Decoded

    // 4. Response headers phase
    let interruption = tx.process_response_headers(200, "HTTP/1.1");
    assert!(interruption.is_none()); // No interruption

    assert_eq!(tx.response_status(), "200");

    // 5. Response body phase with JSON
    let response_body = br#"{"status": "success", "token": "abc123"}"#;
    let interruption = tx.process_response_body(response_body);
    assert!(interruption.is_none());

    // Verify response body stored
    assert!(tx.response_body().contains("success"));

    // 6. Logging phase
    tx.process_logging();

    // Verify final phase tracking
    assert_eq!(tx.last_phase(), Some(RulePhase::Logging));
}

#[test]
fn test_multipart_file_upload_flow() {
    let mut tx = Transaction::new("upload-test");

    // Simulate multipart file upload
    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    let multipart_body = "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n\
         Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n\
         Content-Type: text/plain\r\n\
         \r\n\
         Hello, World!\r\n\
         ------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n\
         Content-Disposition: form-data; name=\"description\"\r\n\
         \r\n\
         Test file upload\r\n\
         ------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n";

    // Add Content-Type header with boundary
    tx.add_request_header(
        "Content-Type",
        &format!("multipart/form-data; boundary={}", boundary),
    );

    // Process multipart body
    let result = tx.process_request_body(multipart_body.as_bytes());
    assert!(result.is_ok());

    // Verify file was captured
    assert_eq!(tx.files().get("file"), vec!["test.txt"]);
    assert_eq!(tx.files_names().get("file"), vec!["file"]);

    // Verify form field
    assert_eq!(tx.args_post().get("description"), vec!["Test file upload"]);

    // Verify combined size tracked
    assert!(!tx.files_combined_size().is_empty());
}

#[test]
fn test_json_api_request_with_nested_data() {
    let mut tx = Transaction::new("json-api-test");

    // JSON API request
    tx.process_uri("/api/v1/users", "POST", "HTTP/2");
    tx.add_request_header("Content-Type", "application/json");
    tx.add_request_header("Authorization", "Bearer token123");

    let json_body = br#"{
        "user": {
            "email": "test@example.com",
            "profile": {
                "name": "Test User",
                "age": 30
            }
        },
        "tags": ["developer", "admin"]
    }"#;

    let result = tx.process_request_body(json_body);
    assert!(result.is_ok());

    // Verify nested JSON flattened correctly
    assert_eq!(
        tx.args_post().get("json.user.email"),
        vec!["test@example.com"]
    );
    assert_eq!(
        tx.args_post().get("json.user.profile.name"),
        vec!["Test User"]
    );
    assert_eq!(tx.args_post().get("json.user.profile.age"), vec!["30"]);

    // Verify array handling
    assert_eq!(tx.args_post().get("json.tags"), vec!["2"]); // array length
    assert_eq!(tx.args_post().get("json.tags.0"), vec!["developer"]);
    assert_eq!(tx.args_post().get("json.tags.1"), vec!["admin"]);
}

#[test]
fn test_ctl_and_phase_processing_integration() {
    use coraza::types::RuleEngineStatus;

    let mut tx = Transaction::new("ctl-phase-integration");

    // Initially rule engine is On
    assert_eq!(tx.rule_engine(), RuleEngineStatus::On);

    // Simulate CTL action changing rule engine to DetectionOnly
    tx.set_rule_engine(RuleEngineStatus::DetectionOnly);

    // Process phases
    tx.process_connection("127.0.0.1", 8080, "10.0.0.1", 80);

    // CTL setting should persist
    assert_eq!(tx.rule_engine(), RuleEngineStatus::DetectionOnly);

    // Process request body
    let result = tx.process_request_body(b"test=data");
    assert!(result.is_ok());

    // Settings still intact after phase processing
    assert_eq!(tx.rule_engine(), RuleEngineStatus::DetectionOnly);
}
