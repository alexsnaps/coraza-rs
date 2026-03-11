// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! HTTP Integration Tests
//!
//! These tests validate the E2E testing framework by processing HTTP requests
//! through the WAF and verifying proper request/response handling, variable
//! population, and phase processing.
//!
//! NOTE: This test suite focuses on validating the E2E test infrastructure
//! (TestServer, TestRequest, TestResponse) rather than comprehensive WAF
//! rule testing. Full rule-based attack detection tests will be added once
//! SecLang directive support (SecRule/SecAction) is implemented in Phase 12.

mod e2e;

use coraza::config::WafConfig;
use coraza::waf::Waf;
use e2e::{TestRequest, TestServer};

// ============================================================================
// Basic Request Processing Tests
// ============================================================================

#[test]
fn test_get_request_with_query_parameters() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response = server.process(TestRequest::get("/search?q=rust&category=web&page=1").build());

    response.assert_status(200);
    response.assert_not_blocked();
}

#[test]
fn test_post_request_with_form_data() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response = server.process(
        TestRequest::post("/login")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body("username=testuser&password=secret123")
            .build(),
    );

    response.assert_status(200);
    response.assert_not_blocked();
}

#[test]
fn test_post_request_with_json_body() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response = server.process(
        TestRequest::post("/api/users")
            .header("Content-Type", "application/json")
            .body(r#"{"name":"John","email":"john@example.com"}"#)
            .build(),
    );

    response.assert_status(200);
    response.assert_not_blocked();
}

#[test]
fn test_post_request_with_xml_body() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response = server.process(
        TestRequest::post("/api/data")
            .header("Content-Type", "application/xml")
            .body("<user><name>John</name><email>john@example.com</email></user>")
            .build(),
    );

    response.assert_status(200);
    response.assert_not_blocked();
}

#[test]
fn test_request_with_multiple_headers() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response = server.process(
        TestRequest::get("/api/data")
            .header("User-Agent", "Mozilla/5.0")
            .header("Accept", "application/json")
            .header("Accept-Language", "en-US")
            .header("X-Custom-Header", "test-value")
            .build(),
    );

    response.assert_status(200);
    response.assert_not_blocked();
}

#[test]
fn test_request_with_cookies() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response = server.process(
        TestRequest::get("/")
            .header("Cookie", "session=abc123; user=john; theme=dark")
            .build(),
    );

    response.assert_status(200);
    response.assert_not_blocked();
}

// ============================================================================
// URL Encoding Tests
// ============================================================================

#[test]
fn test_url_encoded_query_parameters() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response =
        server.process(TestRequest::get("/search?q=hello%20world&filter=test%3Dvalue").build());

    response.assert_status(200);
    response.assert_not_blocked();
}

#[test]
fn test_special_characters_in_url() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response = server.process(TestRequest::get("/search?q=a+b+c&filter=x%2By%3Dz").build());

    response.assert_status(200);
    response.assert_not_blocked();
}

#[test]
fn test_unicode_in_url() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response = server.process(TestRequest::get("/search?q=日本語&lang=ja").build());

    response.assert_status(200);
    response.assert_not_blocked();
}

// ============================================================================
// Body Processing Tests
// ============================================================================

#[test]
fn test_multipart_form_data() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    let body = format!(
        "--{}\r\nContent-Disposition: form-data; name=\"field1\"\r\n\r\nvalue1\r\n--{}\r\nContent-Disposition: form-data; name=\"field2\"\r\n\r\nvalue2\r\n--{}--\r\n",
        boundary, boundary, boundary
    );

    let response = server.process(
        TestRequest::post("/upload")
            .header(
                "Content-Type",
                format!("multipart/form-data; boundary={}", boundary),
            )
            .body(body)
            .build(),
    );

    response.assert_status(200);
    response.assert_not_blocked();
}

#[test]
fn test_large_request_body() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    // 10KB body
    let large_body = "data=".to_string() + &"x".repeat(10000);

    let response = server.process(
        TestRequest::post("/upload")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(large_body)
            .build(),
    );

    response.assert_status(200);
    response.assert_not_blocked();
}

#[test]
fn test_json_nested_structure() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response = server.process(
        TestRequest::post("/api/complex")
            .header("Content-Type", "application/json")
            .body(r#"{"user":{"name":"John","email":"john@example.com"},"settings":{"theme":"dark","notifications":true}}"#)
            .build(),
    );

    response.assert_status(200);
    response.assert_not_blocked();
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_empty_request_body() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response = server.process(
        TestRequest::post("/submit")
            .header("Content-Type", "application/json")
            .build(),
    );

    response.assert_status(200);
    response.assert_not_blocked();
}

#[test]
fn test_request_without_headers() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response = server.process(TestRequest::get("/").build());

    response.assert_status(200);
    response.assert_not_blocked();
}

#[test]
fn test_empty_query_string() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response = server.process(TestRequest::get("/page?").build());

    response.assert_status(200);
    response.assert_not_blocked();
}

#[test]
fn test_very_long_header_value() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let long_value = "x".repeat(1000);

    let response = server.process(
        TestRequest::get("/")
            .header("X-Long-Header", &long_value)
            .build(),
    );

    response.assert_status(200);
    response.assert_not_blocked();
}

#[test]
fn test_binary_content() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    // Binary data (PNG header)
    let binary_data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    let response = server.process(
        TestRequest::post("/upload")
            .header("Content-Type", "image/png")
            .body_bytes(binary_data)
            .build(),
    );

    response.assert_status(200);
    response.assert_not_blocked();
}

#[test]
fn test_multiple_requests_same_server() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    // Process multiple requests through the same server
    for i in 0..5 {
        let response = server.process(TestRequest::get(format!("/page?id={}", i)).build());
        response.assert_status(200);
        response.assert_not_blocked();
    }
}

// ============================================================================
// Response Processing
// ============================================================================

#[test]
fn test_response_headers() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response = server.process(TestRequest::get("/").build());

    // TestServer sets Content-Type to text/html by default
    assert_eq!(
        response.header("Content-Type"),
        Some(&"text/html".to_string())
    );
}

#[test]
fn test_response_status_ok() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response = server.process(TestRequest::get("/").build());

    assert!(response.is_ok());
    assert_eq!(response.status(), 200);
}

// ============================================================================
// HTTP Method Tests
// ============================================================================

#[test]
fn test_http_methods() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    // GET
    let response = server.process(TestRequest::get("/resource").build());
    response.assert_status(200);

    // POST
    let response = server.process(
        TestRequest::post("/resource")
            .header("Content-Type", "application/json")
            .body(r#"{"data":"test"}"#)
            .build(),
    );
    response.assert_status(200);

    // PUT
    let response = server.process(
        TestRequest::put("/resource/123")
            .header("Content-Type", "application/json")
            .body(r#"{"data":"updated"}"#)
            .build(),
    );
    response.assert_status(200);

    // DELETE
    let response = server.process(TestRequest::delete("/resource/123").build());
    response.assert_status(200);
}
