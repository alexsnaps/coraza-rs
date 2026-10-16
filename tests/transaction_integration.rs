// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for Phase 9: Transaction Enhancements
//!
//! These tests validate that all Phase 9 components work together:
//! - Body processors (URL-encoded, multipart, JSON, XML)
//! - Variable population (connection, headers, body)
//! - Phase processing with rule evaluation
//! - CTL action execution
//! - Deferred actions (exec, expirevar, setenv, initcol)

use coraza::RulePhase;
use coraza::RuleVariable;
use coraza::seclang::Parser;
use coraza::transaction::{Transaction, VariableCollection};
use coraza::waf::Waf;

fn waf(rules: &str) -> Waf {
    let mut parser = Parser::new();
    parser.from_string(rules).expect("rules should parse");
    parser.into_waf().expect("config should be valid")
}

/// The values of `key` in `variable`, as rules read them; empty if none.
fn values(tx: &Transaction, variable: RuleVariable, key: &str) -> Vec<String> {
    match tx.collection(variable) {
        Some(VariableCollection::Map(map)) => map.get(key),
        _ => Vec::new(),
    }
}

/// The value of a single-value variable such as REQUEST_URI.
fn single(tx: &Transaction, variable: RuleVariable) -> String {
    tx.get_variable(variable, None)
        .expect("a variable this engine populates")
}

/// Rules that have request bodies read, JSON and XML ones too, as `coraza.conf-recommended`
/// does.
const BODY_RULES: &str = r#"
    SecRequestBodyAccess On
    SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
    SecRule REQUEST_HEADERS:Content-Type "^application/xml" "id:200002,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
"#;

/// A request of `content_type` with `body`, through its request body phase.
fn request_with_body(content_type: &str, body: &[u8]) -> Transaction {
    let mut tx = waf(BODY_RULES).new_transaction();
    tx.add_request_header("Content-Type", content_type);
    tx.process_request_headers();
    assert!(tx.process_request_body(body).is_none());
    tx
}

// ===== Body Processor Integration Tests =====

#[test]
fn test_urlencoded_body_processing() {
    let tx = request_with_body(
        "application/x-www-form-urlencoded",
        b"username=admin&password=secret123&remember=true",
    );

    // Verify ARGS_POST populated
    assert_eq!(values(&tx, RuleVariable::ArgsPost, "username"), ["admin"]);
    assert_eq!(
        values(&tx, RuleVariable::ArgsPost, "password"),
        ["secret123"]
    );
    assert_eq!(values(&tx, RuleVariable::ArgsPost, "remember"), ["true"]);

    // Verify REQUEST_BODY stored
    assert_eq!(
        single(&tx, RuleVariable::RequestBody),
        "username=admin&password=secret123&remember=true"
    );
}

#[test]
fn test_json_body_processing() {
    let tx = request_with_body(
        "application/json",
        br#"{"user": {"name": "admin", "role": "super"}, "items": [1, 2, 3]}"#,
    );

    // Verify flattened JSON in ARGS_POST
    let arg = |key| values(&tx, RuleVariable::ArgsPost, key);
    assert_eq!(arg("json.user.name"), ["admin"]);
    assert_eq!(arg("json.user.role"), ["super"]);
    assert_eq!(arg("json.items"), ["3"]); // array length
    assert_eq!(arg("json.items.0"), ["1"]);
}

#[test]
fn test_xml_body_processing() {
    let tx = request_with_body(
        "application/xml",
        br#"<user role="admin"><name>John</name></user>"#,
    );

    // Verify attributes and content extracted
    assert_eq!(values(&tx, RuleVariable::RequestXML, "//@*"), ["admin"]);
    assert_eq!(values(&tx, RuleVariable::RequestXML, "/*"), ["John"]);
}

// ===== Variable Population Integration Tests =====

#[test]
fn test_full_request_variable_population() {
    let mut tx = Waf::default().new_transaction();

    // Phase 1: Connection variables
    tx.process_connection("192.168.1.100", 54321, "10.0.0.1", 443);
    tx.set_server_name("example.com");

    assert_eq!(single(&tx, RuleVariable::RemoteAddr), "192.168.1.100");
    assert_eq!(single(&tx, RuleVariable::RemotePort), "54321");
    assert_eq!(single(&tx, RuleVariable::ServerAddr), "10.0.0.1");
    assert_eq!(single(&tx, RuleVariable::ServerPort), "443");
    assert_eq!(single(&tx, RuleVariable::ServerName), "example.com");

    // Phase 2: Request headers and URI
    tx.process_uri("/api/users?id=123", "POST", "HTTP/1.1");
    tx.add_request_header("Host", "example.com");
    tx.add_request_header("User-Agent", "Mozilla/5.0");
    tx.add_request_header("Cookie", "session=abc123; user=admin");

    assert_eq!(single(&tx, RuleVariable::RequestMethod), "POST");
    assert_eq!(single(&tx, RuleVariable::RequestURI), "/api/users?id=123");
    assert_eq!(single(&tx, RuleVariable::RequestProtocol), "HTTP/1.1");
    assert_eq!(single(&tx, RuleVariable::QueryString), "id=123");
    assert_eq!(values(&tx, RuleVariable::ArgsGet, "id"), ["123"]);

    // Verify headers
    let header = |name| values(&tx, RuleVariable::RequestHeaders, name);
    assert_eq!(header("host"), ["example.com"]);
    assert_eq!(header("user-agent"), ["Mozilla/5.0"]);

    // Verify cookies parsed
    assert_eq!(
        values(&tx, RuleVariable::RequestCookies, "session"),
        ["abc123"]
    );
    assert_eq!(values(&tx, RuleVariable::RequestCookies, "user"), ["admin"]);
}

#[test]
fn test_response_variable_population() {
    let mut tx = Waf::default().new_transaction();

    // Populate response headers
    tx.add_response_header("Content-Type", "application/json; charset=utf-8");
    tx.add_response_header("X-Custom", "test-value");

    // Process response headers phase
    let interruption = tx.process_response_headers(200, "HTTP/1.1");
    assert!(interruption.is_none());

    // Verify response variables
    assert_eq!(single(&tx, RuleVariable::ResponseStatus), "200");
    assert_eq!(single(&tx, RuleVariable::ResponseProtocol), "HTTP/1.1");
    assert_eq!(
        single(&tx, RuleVariable::ResponseContentType),
        "application/json"
    );
    assert_eq!(
        values(&tx, RuleVariable::ResponseHeaders, "content-type"),
        ["application/json; charset=utf-8"]
    );
}

// ===== Phase Processing Integration Tests =====

#[test]
fn test_phase_prevents_duplicate_processing() {
    let mut tx = Waf::default().new_transaction();

    // Process connection
    tx.process_connection("127.0.0.1", 8080, "10.0.0.1", 80);

    // Try to process connection again
    tx.process_connection("192.168.1.1", 9090, "10.0.0.2", 443);

    // First values should be preserved (duplicate processing prevented)
    assert_eq!(single(&tx, RuleVariable::RemoteAddr), "127.0.0.1");
    assert_eq!(single(&tx, RuleVariable::RemotePort), "8080");
}

// ===== CTL Action Integration Tests =====

/// A urlencoded request for `uri` with `body`, through its request body phase.
fn post(waf: &Waf, uri: &str, body: &[u8]) -> Transaction {
    let mut tx = waf.new_transaction();
    tx.process_uri(uri, "POST", "HTTP/1.1");
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
    tx.process_request_headers();
    tx.process_request_body(body);
    tx
}

#[test]
fn ctl_changes_request_body_settings_for_one_transaction() {
    let waf = waf(r#"
        SecRequestBodyAccess Off
        SecRule REQUEST_FILENAME "@streq /upload" "id:1,phase:1,pass,nolog,ctl:requestBodyAccess=On,ctl:requestBodyLimit=8"
    "#);

    // Other requests keep the WAF's settings: the body isn't read
    let tx = post(&waf, "/other", b"a=1");
    assert!(!tx.request_body_access());
    assert_eq!(tx.get_variable(RuleVariable::ArgsPost, Some("a")), None);

    // For /upload, the body is read, up to the limit `ctl` set
    let tx = post(&waf, "/upload", b"a=1");
    assert!(tx.request_body_access());
    assert_eq!(values(&tx, RuleVariable::ArgsPost, "a"), ["1"]);
    let tx = post(&waf, "/upload", b"a=12345678");
    assert_eq!(tx.interruption().map(|i| i.status), Some(413));

    assert!(!waf.config().request_body_access);
}

#[test]
fn ctl_changes_request_body_settings_only_before_the_request_body_phase() {
    let waf = waf(r#"
        SecRequestBodyAccess On
        SecRule ARGS_GET:skip "@streq 1" "id:1,phase:1,pass,nolog,ctl:requestBodyAccess=Off"
        SecAction "id:2,phase:2,pass,nolog,ctl:requestBodyAccess=Off"
    "#);

    // In phase 1, the change keeps the body from being read
    let tx = post(&waf, "/?skip=1", b"a=1");
    assert_eq!(tx.get_variable(RuleVariable::ArgsPost, Some("a")), None);

    // In phase 2, the body was read already, and the change doesn't apply
    let tx = post(&waf, "/", b"a=1");
    assert_eq!(values(&tx, RuleVariable::ArgsPost, "a"), ["1"]);
    assert!(tx.request_body_access());
    assert_eq!(tx.last_phase(), Some(RulePhase::RequestBody));
}

// ===== Deferred Actions Integration Tests =====

#[test]
fn test_setenv_action_execution() {
    // Sets ENV, not the process environment
    let waf = waf(r#"SecAction "id:1,phase:1,pass,nolog,setenv:TEST_VAR=test_value""#);
    let mut tx = waf.new_transaction();
    tx.process_request_headers();

    assert_eq!(
        tx.get_variable(RuleVariable::Env, Some("TEST_VAR"))
            .as_deref(),
        Some("test_value")
    );
    assert!(std::env::var_os("TEST_VAR").is_none());
}

#[cfg(unix)]
#[test]
fn test_exec_action_is_never_run() {
    use std::os::unix::fs::PermissionsExt;

    // exec is accepted, but has no runtime part: scripts are never executed
    let dir = tempfile::tempdir().unwrap();
    let ran = dir.path().join("ran");
    let script = dir.path().join("script.sh");
    std::fs::write(&script, format!("#!/bin/sh\ntouch {}\n", ran.display())).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let waf = waf(&format!(
        r#"SecAction "id:1,phase:1,pass,nolog,exec:{}""#,
        script.display()
    ));

    let mut tx = waf.new_transaction();
    assert!(tx.process_request_headers().is_none());
    assert!(!ran.exists());
}

// ===== Combined Scenario Tests =====

#[test]
fn test_complete_transaction_flow() {
    let waf = Waf::new(coraza::config::WafConfig {
        request_body_access: true,
        response_body_access: true,
        response_body_mime_types: vec!["application/json".to_string()],
        ..Default::default()
    })
    .unwrap();
    let mut tx = waf.new_transaction_with_id("complete-flow-test".to_string());

    // 1. Connection phase
    tx.process_connection("192.168.1.1", 12345, "10.0.0.1", 443);
    assert_eq!(single(&tx, RuleVariable::RemoteAddr), "192.168.1.1");

    // 2. Request headers phase
    tx.process_uri("/api/login?redirect=/dashboard", "POST", "HTTP/1.1");
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
    tx.add_request_header("User-Agent", "curl/7.68.0");

    assert_eq!(single(&tx, RuleVariable::RequestMethod), "POST");
    assert_eq!(
        single(&tx, RuleVariable::RequestURI),
        "/api/login?redirect=/dashboard"
    );
    assert_eq!(
        values(&tx, RuleVariable::ArgsGet, "redirect"),
        ["/dashboard"]
    );

    // 3. Request body phase with URL-encoded data
    let body = b"username=admin&password=P%40ssw0rd";
    tx.process_request_headers();
    let result = tx.process_request_body(body);
    assert!(result.is_none());

    // Verify body was processed
    assert_eq!(values(&tx, RuleVariable::ArgsPost, "username"), ["admin"]);
    assert_eq!(
        values(&tx, RuleVariable::ArgsPost, "password"),
        ["P@ssw0rd"]
    ); // Decoded

    // 4. Response headers phase
    tx.add_response_header("Content-Type", "application/json");
    let interruption = tx.process_response_headers(200, "HTTP/1.1");
    assert!(interruption.is_none()); // No interruption

    assert_eq!(single(&tx, RuleVariable::ResponseStatus), "200");

    // 5. Response body phase with JSON
    let response_body = br#"{"status": "success", "token": "abc123"}"#;
    let interruption = tx.process_response_body(response_body);
    assert!(interruption.is_none());

    // Verify response body stored
    assert!(single(&tx, RuleVariable::ResponseBody).contains("success"));

    // 6. Logging phase
    tx.process_logging().unwrap();

    // Verify final phase tracking
    assert_eq!(tx.last_phase(), Some(RulePhase::Logging));
}

#[test]
fn test_multipart_file_upload_flow() {
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

    // Process multipart body, with the boundary in the Content-Type header
    let tx = request_with_body(
        &format!("multipart/form-data; boundary={}", boundary),
        multipart_body.as_bytes(),
    );

    // Verify file was captured
    // Listed without keys, as in Go Coraza
    assert_eq!(values(&tx, RuleVariable::Files, ""), ["test.txt"]);
    assert_eq!(values(&tx, RuleVariable::FilesNames, ""), ["file"]);

    // Verify form field
    assert_eq!(
        values(&tx, RuleVariable::ArgsPost, "description"),
        ["Test file upload"]
    );

    // Verify combined size tracked
    assert!(!single(&tx, RuleVariable::FilesCombinedSize).is_empty());
}

#[test]
fn test_json_api_request_with_nested_data() {
    // As in Go, JSON bodies are parsed once a rule selects the JSON processor
    let mut tx = waf(BODY_RULES).new_transaction();

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

    tx.process_request_headers();
    let result = tx.process_request_body(json_body);
    assert!(result.is_none());

    // Verify nested JSON flattened correctly
    let arg = |key| values(&tx, RuleVariable::ArgsPost, key);
    assert_eq!(arg("json.user.email"), ["test@example.com"]);
    assert_eq!(arg("json.user.profile.name"), ["Test User"]);
    assert_eq!(arg("json.user.profile.age"), ["30"]);

    // Verify array handling
    assert_eq!(arg("json.tags"), ["2"]); // array length
    assert_eq!(arg("json.tags.0"), ["developer"]);
    assert_eq!(arg("json.tags.1"), ["admin"]);
}
