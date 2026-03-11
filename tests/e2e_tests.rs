// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! End-to-End integration tests for the WAF.

mod e2e;

use coraza::config::WafConfig;
use coraza::waf::Waf;
use e2e::{TestRequest, TestServer};

#[test]
fn test_e2e_framework_get_request() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response = server.process(TestRequest::get("/test").build());

    response.assert_status(200);
    response.assert_not_blocked();
    response.assert_no_matches();
}

#[test]
fn test_e2e_framework_post_request() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response = server.process(
        TestRequest::post("/login")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body("username=test&password=secret")
            .build(),
    );

    response.assert_status(200);
    response.assert_not_blocked();
}

#[test]
fn test_e2e_framework_with_headers() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response = server.process(
        TestRequest::get("/api/data")
            .header("User-Agent", "TestBot/1.0")
            .header("Accept", "application/json")
            .build(),
    );

    response.assert_status(200);
    assert_eq!(
        response.header("Content-Type"),
        Some(&"text/html".to_string())
    );
}

#[test]
fn test_e2e_framework_query_string() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response = server.process(TestRequest::get("/search?q=test&filter=active").build());

    response.assert_status(200);
    response.assert_not_blocked();
}

#[test]
fn test_e2e_framework_empty_body() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response = server.process(
        TestRequest::post("/submit")
            .header("Content-Type", "application/json")
            .build(),
    );

    response.assert_status(200);
}
