// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! End-to-End Testing Framework
//!
//! This module provides a complete HTTP test framework for validating
//! WAF behavior in realistic scenarios. It includes:
//!
//! - `TestServer`: Simple HTTP server for processing requests through WAF
//! - `TestRequest`/`TestResponse`: Builder patterns for request/response construction
//! - Assertion helpers for validating WAF behavior
//!
//! # Examples
//!
//! ```no_run
//! use coraza::waf::Waf;
//! use coraza_tests::e2e::{TestServer, TestRequest};
//!
//! let waf = Waf::new().build();
//! let server = TestServer::new(waf);
//!
//! let response = server.process(
//!     TestRequest::get("/")
//!         .header("User-Agent", "TestBot")
//!         .build()
//! );
//!
//! assert!(response.is_ok());
//! assert_eq!(response.status(), 200);
//! ```

use coraza::transaction::Transaction;
use coraza::types::RulePhase;
use coraza::waf::Waf;
use std::collections::HashMap;

/// HTTP method for requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
}

impl Method {
    fn as_str(&self) -> &str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Head => "HEAD",
            Method::Options => "OPTIONS",
            Method::Patch => "PATCH",
        }
    }
}

/// Builder for constructing HTTP requests for testing.
///
/// # Examples
///
/// ```
/// use coraza_tests::e2e::{TestRequest, Method};
///
/// let request = TestRequest::new(Method::Post, "/login")
///     .header("Content-Type", "application/x-www-form-urlencoded")
///     .body("username=admin&password=secret")
///     .build();
/// ```
#[derive(Debug)]
pub struct TestRequest {
    method: Method,
    uri: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    query_string: String,
}

impl TestRequest {
    #[allow(dead_code)]
    /// Creates a new request builder with the given method and URI.
    pub fn new(method: Method, uri: impl Into<String>) -> Self {
        let uri_str = uri.into();
        let (path, query) = uri_str.split_once('?').unwrap_or((&uri_str, ""));

        Self {
            method,
            uri: path.to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
            query_string: query.to_string(),
        }
    }

    /// Creates a GET request builder.
    pub fn get(uri: impl Into<String>) -> Self {
        Self::new(Method::Get, uri)
    }

    /// Creates a POST request builder.
    pub fn post(uri: impl Into<String>) -> Self {
        Self::new(Method::Post, uri)
    }

    /// Creates a PUT request builder.
    #[allow(dead_code)]
    pub fn put(uri: impl Into<String>) -> Self {
        Self::new(Method::Put, uri)
    }

    /// Creates a DELETE request builder.
    #[allow(dead_code)]
    pub fn delete(uri: impl Into<String>) -> Self {
        Self::new(Method::Delete, uri)
    }

    /// Adds a header to the request.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Sets the request body from a string.
    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = body.into().into_bytes();
        self
    }

    /// Sets the request body from raw bytes.
    #[allow(dead_code)]
    pub fn body_bytes(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Sets the query string.
    #[allow(dead_code)]
    pub fn query(mut self, query: impl Into<String>) -> Self {
        self.query_string = query.into();
        self
    }

    /// Builds the final request.
    pub fn build(self) -> Self {
        self
    }

    /// Returns the HTTP method.
    pub fn method(&self) -> Method {
        self.method
    }

    /// Returns the request URI (without query string).
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Returns the query string.
    pub fn query_string(&self) -> &str {
        &self.query_string
    }

    /// Returns all headers.
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// Returns a specific request header value.
    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.headers.get(name)
    }

    /// Returns the request body as bytes.
    pub fn get_body(&self) -> &[u8] {
        &self.body
    }
}

/// HTTP response returned by the test server.
#[derive(Debug)]
#[allow(dead_code)]
pub struct TestResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    interrupted: bool,
    rule_matches: Vec<RuleMatch>,
}

/// Information about a rule that matched during request processing.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RuleMatch {
    pub rule_id: i32,
    pub message: String,
    pub severity: String,
    pub phase: RulePhase,
}

impl TestResponse {
    #[allow(dead_code)]
    /// Returns the HTTP status code.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Returns true if the response is successful (2xx status).
    pub fn is_ok(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// Returns true if the transaction was interrupted by the WAF.
    pub fn is_blocked(&self) -> bool {
        self.interrupted
    }

    /// Returns all response headers.
    #[allow(dead_code)]
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// Returns a specific response header value.
    #[allow(dead_code)]
    pub fn header(&self, name: &str) -> Option<&String> {
        self.headers.get(name)
    }

    /// Returns a specific request header value.
    #[allow(dead_code)]
    pub fn request_header(&self, name: &str) -> Option<&String> {
        self.headers.get(name)
    }

    /// Returns the response body.
    #[allow(dead_code)]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the response body as a UTF-8 string.
    #[allow(dead_code)]
    pub fn body_string(&self) -> Result<String, std::str::Utf8Error> {
        std::str::from_utf8(&self.body).map(|s| s.to_string())
    }

    /// Returns all rules that matched during processing.
    #[allow(dead_code)]
    pub fn rule_matches(&self) -> &[RuleMatch] {
        &self.rule_matches
    }

    /// Returns the number of rules that matched.
    #[allow(dead_code)]
    pub fn match_count(&self) -> usize {
        self.rule_matches.len()
    }

    /// Asserts that the response has the given status code.
    #[track_caller]
    pub fn assert_status(&self, expected: u16) {
        assert_eq!(
            self.status, expected,
            "Expected status {}, got {}",
            expected, self.status
        );
    }

    /// Asserts that the response was blocked.
    #[track_caller]
    #[allow(dead_code)]
    pub fn assert_blocked(&self) {
        assert!(
            self.interrupted,
            "Expected transaction to be blocked, but it was not"
        );
    }

    /// Asserts that the response was not blocked.
    #[track_caller]
    pub fn assert_not_blocked(&self) {
        assert!(
            !self.interrupted,
            "Expected transaction to not be blocked, but it was"
        );
    }

    /// Asserts that at least one rule matched.
    #[track_caller]
    #[allow(dead_code)]
    pub fn assert_matched(&self) {
        assert!(
            !self.rule_matches.is_empty(),
            "Expected at least one rule to match, but none did"
        );
    }

    /// Asserts that no rules matched.
    #[track_caller]
    pub fn assert_no_matches(&self) {
        assert!(
            self.rule_matches.is_empty(),
            "Expected no rule matches, but {} rule(s) matched",
            self.rule_matches.len()
        );
    }

    /// Asserts that a specific rule ID matched.
    #[track_caller]
    #[allow(dead_code)]
    pub fn assert_rule_matched(&self, rule_id: i32) {
        let matched = self.rule_matches.iter().any(|m| m.rule_id == rule_id);
        assert!(
            matched,
            "Expected rule {} to match, but it did not. Matched rules: {:?}",
            rule_id,
            self.rule_matches
                .iter()
                .map(|m| m.rule_id)
                .collect::<Vec<_>>()
        );
    }

    /// Asserts that exactly N rules matched.
    #[track_caller]
    #[allow(dead_code)]
    pub fn assert_match_count(&self, count: usize) {
        assert_eq!(
            self.rule_matches.len(),
            count,
            "Expected {} rule matches, got {}",
            count,
            self.rule_matches.len()
        );
    }
}

/// Test server that processes requests through a WAF instance.
///
/// This simulates a simple HTTP server that runs requests through
/// all WAF phases and returns the result.
///
/// # Examples
///
/// ```
/// use coraza::waf::Waf;
/// use coraza_tests::e2e::{TestServer, TestRequest};
///
/// let waf = Waf::new().build();
/// let server = TestServer::new(waf);
///
/// let response = server.process(TestRequest::get("/").build());
/// assert!(response.is_ok());
/// ```
pub struct TestServer {
    waf: Waf,
}

impl TestServer {
    /// Creates a new test server with the given WAF instance.
    pub fn new(waf: Waf) -> Self {
        Self { waf }
    }

    /// Processes a request through the WAF and returns the response.
    ///
    /// This simulates the full HTTP lifecycle:
    /// 1. Phase 1: Request headers
    /// 2. Phase 2: Request body
    /// 3. Phase 3: Response headers
    /// 4. Phase 4: Response body
    /// 5. Phase 5: Logging
    pub fn process(&self, request: TestRequest) -> TestResponse {
        let mut tx = self.waf.new_transaction();

        // Track rule matches (not yet implemented)
        let rule_matches = Vec::new();

        // Phase 1: Request Headers
        tx.process_uri(request.uri(), request.method().as_str(), "HTTP/1.1");

        // Add request headers
        for (key, value) in request.headers() {
            tx.add_request_header(key, value);
        }

        // Check for interruption after Phase 1
        if tx.interruption().is_some() {
            return self.build_blocked_response(&tx, rule_matches);
        }

        // Phase 2: Request Body
        if !request.get_body().is_empty() {
            let _ = tx.process_request_body(request.get_body());

            if tx.interruption().is_some() {
                return self.build_blocked_response(&tx, rule_matches);
            }
        }

        // Phase 3: Response Headers (simulated)
        let mut response_headers = HashMap::new();
        response_headers.insert("Content-Type".to_string(), "text/html".to_string());
        response_headers.insert("Content-Length".to_string(), "0".to_string());

        for (key, value) in &response_headers {
            tx.add_response_header(key, value);
        }

        let _ = tx.process_response_headers(200, "HTTP/1.1");

        if tx.interruption().is_some() {
            return self.build_blocked_response(&tx, rule_matches);
        }

        // Phase 4: Response Body (empty for now)
        let _ = tx.process_response_body(&[]);

        if tx.interruption().is_some() {
            return self.build_blocked_response(&tx, rule_matches);
        }

        // Phase 5: Logging
        tx.process_logging();

        // Build successful response
        TestResponse {
            status: 200,
            headers: response_headers,
            body: Vec::new(),
            interrupted: false,
            rule_matches,
        }
    }

    fn build_blocked_response(
        &self,
        tx: &Transaction,
        rule_matches: Vec<RuleMatch>,
    ) -> TestResponse {
        let interruption = tx.interruption().expect("Expected interruption");

        let status_code = if interruption.status > 0 {
            interruption.status
        } else {
            match interruption.action.as_str() {
                "deny" => 403,
                "drop" => 444,
                "redirect" => 302,
                _ => 403,
            }
        };

        TestResponse {
            status: status_code,
            headers: HashMap::new(),
            body: Vec::new(),
            interrupted: true,
            rule_matches,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_builder_get() {
        let req = TestRequest::get("/test").build();
        assert_eq!(req.method(), Method::Get);
        assert_eq!(req.uri(), "/test");
        assert!(req.get_body().is_empty());
    }

    #[test]
    fn test_request_builder_post_with_body() {
        let req = TestRequest::post("/login")
            .header("Content-Type", "application/json")
            .body(r#"{"user":"admin"}"#)
            .build();

        assert_eq!(req.method(), Method::Post);
        assert_eq!(req.uri(), "/login");
        assert_eq!(
            req.get_header("Content-Type"),
            Some(&"application/json".to_string())
        );
        assert_eq!(req.get_body(), br#"{"user":"admin"}"#);
    }

    #[test]
    fn test_request_with_query_string() {
        let req = TestRequest::get("/search?q=test&page=1").build();
        assert_eq!(req.uri(), "/search");
        assert_eq!(req.query_string(), "q=test&page=1");
    }

    #[test]
    fn test_response_assertions() {
        let response = TestResponse {
            status: 200,
            headers: HashMap::new(),
            body: Vec::new(),
            interrupted: false,
            rule_matches: Vec::new(),
        };

        response.assert_status(200);
        response.assert_not_blocked();
        response.assert_no_matches();
        assert!(response.is_ok());
    }

    #[test]
    fn test_server_basic_request() {
        use coraza::config::WafConfig;

        let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
        let server = TestServer::new(waf);

        let response = server.process(TestRequest::get("/").build());

        assert!(response.is_ok());
        assert_eq!(response.status(), 200);
        assert!(!response.is_blocked());
    }
}
