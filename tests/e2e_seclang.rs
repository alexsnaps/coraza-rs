// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! End-to-End SecLang Integration Tests
//!
//! These tests validate the complete pipeline:
//! 1. Parse configuration from SecLang strings
//! 2. Create WAF with parsed config
//! 3. Process HTTP requests through TestServer
//! 4. Verify configuration is applied
//!
//! This demonstrates the full integration of parser → WAF → transaction.

mod e2e;

use e2e::{TestRequest, TestServer};

/// Helper function to convert seclang::WafConfig to config::WafConfig
fn to_waf_config(seclang_config: &coraza::seclang::WafConfig) -> coraza::config::WafConfig {
    use coraza::config::WafConfig;

    WafConfig::new()
        .with_rule_engine(seclang_config.rule_engine)
        .with_request_body_access(seclang_config.request_body_access)
        .with_request_body_limit(seclang_config.request_body_limit)
        .with_request_body_in_memory_limit(seclang_config.request_body_in_memory_limit)
        .with_response_body_access(seclang_config.response_body_access)
        .with_response_body_limit(seclang_config.response_body_limit)
        .with_debug_log_level(seclang_config.debug_log_level as i32)
        .with_web_app_id(seclang_config.web_app_id.clone())
        .with_argument_limit(seclang_config.argument_limit)
}

// ============================================================================
// Configuration Parsing Tests
// ============================================================================

#[test]
fn test_parse_and_apply_rule_engine_on() {
    use coraza::seclang::Parser;
    use coraza::types::RuleEngineStatus;
    use coraza::waf::Waf;

    let mut parser = Parser::new();

    let config_str = r#"
        SecRuleEngine On
    "#;

    parser
        .from_string(config_str)
        .expect("Failed to parse config");

    let parsed = parser.config();

    let waf = Waf::new(to_waf_config(parsed)).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let tx = server.waf().new_transaction();
    assert_eq!(tx.rule_engine(), RuleEngineStatus::On);
}

#[test]
fn test_parse_and_apply_rule_engine_detection_only() {
    use coraza::seclang::Parser;
    use coraza::types::RuleEngineStatus;
    use coraza::waf::Waf;

    let mut parser = Parser::new();

    let config_str = r#"
        SecRuleEngine DetectionOnly
    "#;

    parser
        .from_string(config_str)
        .expect("Failed to parse config");

    let parsed_config = to_waf_config(parser.config());
    let waf = Waf::new(parsed_config).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let tx = server.waf().new_transaction();
    assert_eq!(tx.rule_engine(), RuleEngineStatus::DetectionOnly);
}

#[test]
fn test_parse_and_apply_request_body_config() {
    use coraza::seclang::Parser;
    use coraza::waf::Waf;

    let mut parser = Parser::new();

    let config_str = r#"
        SecRuleEngine On
        SecRequestBodyAccess On
        SecRequestBodyLimit 2097152
    "#;

    parser
        .from_string(config_str)
        .expect("Failed to parse config");

    let parsed_config = to_waf_config(parser.config());
    let waf = Waf::new(parsed_config).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    // Process a request with body
    let response = server.process(
        TestRequest::post("/upload")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body("data=test")
            .build(),
    );

    response.assert_status(200);
    response.assert_not_blocked();
}

#[test]
fn test_parse_comprehensive_config() {
    use coraza::seclang::Parser;
    use coraza::types::RuleEngineStatus;
    use coraza::waf::Waf;

    let mut parser = Parser::new();

    let config_str = r#"
        # Engine Configuration
        SecRuleEngine On
        SecRequestBodyAccess On
        SecRequestBodyLimit 13107200
        SecRequestBodyNoFilesLimit 131072
        SecResponseBodyAccess On
        SecResponseBodyLimit 524288
        SecDebugLogLevel 3

        # Application Identity
        SecWebAppId production-app
        SecServerSignature "Coraza WAF/1.0"

        # Limits
        SecArgumentsLimit 1000
    "#;

    parser
        .from_string(config_str)
        .expect("Failed to parse config");

    let parsed_config = parser.config();

    // Verify parsed configuration
    assert_eq!(parsed_config.rule_engine, RuleEngineStatus::On);
    assert!(parsed_config.request_body_access);
    assert_eq!(parsed_config.request_body_limit, 13107200);
    assert_eq!(parsed_config.request_body_no_files_limit, 131072);
    assert!(parsed_config.response_body_access);
    assert_eq!(parsed_config.response_body_limit, 524288);
    assert_eq!(parsed_config.debug_log_level, 3);
    assert_eq!(parsed_config.web_app_id, "production-app");
    assert_eq!(parsed_config.server_signature, "Coraza WAF/1.0");
    assert_eq!(parsed_config.argument_limit, 1000);

    // Create WAF and verify config is applied
    let waf = Waf::new(to_waf_config(parsed_config)).expect("Failed to create WAF");
    let tx = waf.new_transaction();

    assert_eq!(tx.rule_engine(), RuleEngineStatus::On);
}

// ============================================================================
// E2E Processing Tests
// ============================================================================

#[test]
fn test_e2e_basic_request_with_parsed_config() {
    use coraza::seclang::Parser;
    use coraza::waf::Waf;

    let mut parser = Parser::new();

    parser
        .from_string("SecRuleEngine On")
        .expect("Failed to parse");

    let waf = Waf::new(to_waf_config(parser.config())).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    let response = server.process(TestRequest::get("/search?q=rust&category=web").build());

    response.assert_status(200);
    response.assert_not_blocked();
}

#[test]
fn test_e2e_post_json_with_parsed_config() {
    use coraza::seclang::Parser;
    use coraza::waf::Waf;

    let mut parser = Parser::new();

    let config = r#"
        SecRuleEngine On
        SecRequestBodyAccess On
    "#;

    parser.from_string(config).expect("Failed to parse");

    let waf = Waf::new(to_waf_config(parser.config())).expect("Failed to create WAF");
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
fn test_e2e_multipart_with_parsed_config() {
    use coraza::seclang::Parser;
    use coraza::waf::Waf;

    let mut parser = Parser::new();

    let config = r#"
        SecRuleEngine On
        SecRequestBodyAccess On
        SecRequestBodyLimit 10485760
    "#;

    parser.from_string(config).expect("Failed to parse");

    let waf = Waf::new(to_waf_config(parser.config())).expect("Failed to create WAF");
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

// ============================================================================
// Multiple Request Tests
// ============================================================================

#[test]
fn test_e2e_multiple_requests_same_config() {
    use coraza::seclang::Parser;
    use coraza::waf::Waf;

    let mut parser = Parser::new();

    parser
        .from_string("SecRuleEngine On")
        .expect("Failed to parse");

    let waf = Waf::new(to_waf_config(parser.config())).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    // Process 10 different requests
    for i in 0..10 {
        let response = server.process(TestRequest::get(format!("/page?id={}", i)).build());
        response.assert_status(200);
        response.assert_not_blocked();
    }
}

#[test]
fn test_e2e_mixed_request_methods() {
    use coraza::seclang::Parser;
    use coraza::waf::Waf;

    let mut parser = Parser::new();

    let config = r#"
        SecRuleEngine On
        SecRequestBodyAccess On
    "#;

    parser.from_string(config).expect("Failed to parse");

    let waf = Waf::new(to_waf_config(parser.config())).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    // GET request
    let response = server.process(TestRequest::get("/api/resource/123").build());
    response.assert_status(200);

    // POST request
    let response = server.process(
        TestRequest::post("/api/resource")
            .header("Content-Type", "application/json")
            .body(r#"{"data":"value"}"#)
            .build(),
    );
    response.assert_status(200);

    // PUT request
    let response = server.process(
        TestRequest::put("/api/resource/123")
            .header("Content-Type", "application/json")
            .body(r#"{"data":"updated"}"#)
            .build(),
    );
    response.assert_status(200);

    // DELETE request
    let response = server.process(TestRequest::delete("/api/resource/123").build());
    response.assert_status(200);
}

// ============================================================================
// Parser Feature Tests
// ============================================================================

#[test]
fn test_parser_incremental_config() {
    use coraza::seclang::Parser;
    use coraza::types::RuleEngineStatus;
    use coraza::waf::Waf;

    let mut parser = Parser::new();

    // Parse config in multiple chunks
    parser
        .from_string("SecRuleEngine On")
        .expect("Failed to parse");

    parser
        .from_string("SecRequestBodyAccess On")
        .expect("Failed to parse");

    parser
        .from_string("SecRequestBodyLimit 524288")
        .expect("Failed to parse");

    let config = parser.config();

    assert_eq!(config.rule_engine, RuleEngineStatus::On);
    assert!(config.request_body_access);
    assert_eq!(config.request_body_limit, 524288);

    // Use config in WAF
    let waf = Waf::new(to_waf_config(config)).expect("Failed to create WAF");
    let tx = waf.new_transaction();

    assert_eq!(tx.rule_engine(), RuleEngineStatus::On);
}

#[test]
fn test_parser_with_comments() {
    use coraza::seclang::Parser;

    let mut parser = Parser::new();

    let config = r#"
        # This is a comment
        SecRuleEngine On

        # More comments
        SecRequestBodyAccess On

        # Even more comments
        SecRequestBodyLimit 1048576
    "#;

    let result = parser.from_string(config);
    assert!(result.is_ok(), "Parser should handle comments");

    let parsed_config = parser.config();
    assert_eq!(parsed_config.request_body_limit, 1048576);
}

#[test]
fn test_parser_line_continuation() {
    use coraza::seclang::Parser;

    let mut parser = Parser::new();

    let config = r#"
        SecRuleEngine \
            On

        SecRequestBodyLimit \
            2097152
    "#;

    let result = parser.from_string(config);
    assert!(result.is_ok(), "Parser should handle line continuation");

    let parsed_config = parser.config();
    assert_eq!(parsed_config.request_body_limit, 2097152);
}

#[test]
fn test_parser_case_insensitive() {
    use coraza::seclang::Parser;

    let mut parser = Parser::new();

    // Mix of case styles
    let config = r#"
        seCruLeenGiNe On
        SECREQUESTBODYaccess on
        SecRequestBodyLimit 1048576
    "#;

    let result = parser.from_string(config);
    assert!(
        result.is_ok(),
        "Parser should be case-insensitive for directives"
    );
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_parser_invalid_directive() {
    use coraza::seclang::Parser;

    let mut parser = Parser::new();

    let invalid_config = r#"
        SecRuleEngine On
        InvalidDirective SomeValue
    "#;

    let result = parser.from_string(invalid_config);
    assert!(result.is_err(), "Parser should reject invalid directives");
}

#[test]
fn test_parser_invalid_value() {
    use coraza::seclang::Parser;

    let mut parser = Parser::new();

    let invalid_config = r#"
        SecRuleEngine InvalidValue
    "#;

    let result = parser.from_string(invalid_config);
    assert!(
        result.is_err(),
        "Parser should reject invalid directive values"
    );
}

#[test]
fn test_parser_missing_argument() {
    use coraza::seclang::Parser;

    let mut parser = Parser::new();

    let invalid_config = r#"
        SecRequestBodyLimit
    "#;

    let result = parser.from_string(invalid_config);
    assert!(
        result.is_err(),
        "Parser should reject directives missing arguments"
    );
}

#[test]
fn test_parser_negative_limit() {
    use coraza::seclang::Parser;
    use coraza::waf::Waf;

    let mut parser = Parser::new();

    let config = r#"
        SecRequestBodyLimit -1
    "#;

    parser.from_string(config).expect("Parser accepts value");

    // WAF should reject invalid config
    let result = Waf::new(to_waf_config(parser.config()));
    assert!(result.is_err(), "WAF should reject negative limits");
}

// ============================================================================
// Real-World Scenario Tests
// ============================================================================

#[test]
fn test_realistic_production_config() {
    use coraza::seclang::Parser;
    use coraza::types::RuleEngineStatus;
    use coraza::waf::Waf;

    let mut parser = Parser::new();

    let config = r#"
        # ==========================================
        # Coraza WAF Production Configuration
        # ==========================================

        # Engine Configuration
        SecRuleEngine On
        SecRequestBodyAccess On
        SecRequestBodyLimit 13107200
        SecRequestBodyNoFilesLimit 131072
        SecRequestBodyInMemoryLimit 131072
        SecResponseBodyAccess On
        SecResponseBodyLimit 524288
        SecDebugLogLevel 2

        # Application Identity
        SecWebAppId production-api
        SecServerSignature "Coraza WAF/1.0"
        SecComponentSignature "core-ruleset/4.0.0"

        # Limits and Tuning
        SecArgumentsLimit 1000

        # TODO: Rules will be added once SecRule directive is implemented
        # SecRule ARGS "@rx ..." "..."
    "#;

    parser
        .from_string(config)
        .expect("Failed to parse production config");

    let parsed_config = parser.config();

    // Verify all settings
    assert_eq!(parsed_config.rule_engine, RuleEngineStatus::On);
    assert!(parsed_config.request_body_access);
    assert_eq!(parsed_config.request_body_limit, 13107200);
    assert_eq!(parsed_config.request_body_no_files_limit, 131072);
    assert_eq!(parsed_config.request_body_in_memory_limit, 131072);
    assert!(parsed_config.response_body_access);
    assert_eq!(parsed_config.response_body_limit, 524288);
    assert_eq!(parsed_config.debug_log_level, 2);
    assert_eq!(parsed_config.web_app_id, "production-api");
    assert_eq!(parsed_config.server_signature, "Coraza WAF/1.0");
    // Note: component_signature field doesn't exist in current WafConfig
    // assert_eq!(parsed_config.component_signature, "core-ruleset/4.0.0");
    assert_eq!(parsed_config.argument_limit, 1000);

    // Create WAF and test
    let waf = Waf::new(to_waf_config(parsed_config)).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    // Simulate production traffic
    let response = server.process(
        TestRequest::post("/api/v1/users")
            .header("Content-Type", "application/json")
            .header("User-Agent", "ProductionClient/1.0")
            .body(r#"{"username":"john","email":"john@example.com"}"#)
            .build(),
    );

    response.assert_status(200);
    response.assert_not_blocked();
}

#[test]
fn test_development_vs_production_configs() {
    use coraza::seclang::Parser;
    use coraza::types::RuleEngineStatus;
    use coraza::waf::Waf;

    // Development config - more permissive
    let mut dev_parser = Parser::new();
    dev_parser
        .from_string(
            r#"
        SecRuleEngine DetectionOnly
        SecDebugLogLevel 9
        SecRequestBodyLimit 52428800
    "#,
        )
        .expect("Failed to parse dev config");

    let dev_waf = Waf::new(to_waf_config(dev_parser.config())).expect("Failed to create dev WAF");
    let dev_tx = dev_waf.new_transaction();

    assert_eq!(dev_tx.rule_engine(), RuleEngineStatus::DetectionOnly);

    // Production config - more restrictive
    let mut prod_parser = Parser::new();
    prod_parser
        .from_string(
            r#"
        SecRuleEngine On
        SecDebugLogLevel 1
        SecRequestBodyLimit 1048576
    "#,
        )
        .expect("Failed to parse prod config");

    let prod_waf =
        Waf::new(to_waf_config(prod_parser.config())).expect("Failed to create prod WAF");
    let prod_tx = prod_waf.new_transaction();

    assert_eq!(prod_tx.rule_engine(), RuleEngineStatus::On);
}

// ============================================================================
// Performance and Stress Tests
// ============================================================================

#[test]
fn test_large_config_parsing() {
    use coraza::seclang::Parser;

    let mut parser = Parser::new();

    // Generate a large config with many directives
    let mut large_config = String::from("SecRuleEngine On\n");
    for i in 0..100 {
        large_config.push_str(&format!("# Comment {}\n", i));
        large_config.push_str("SecRequestBodyAccess On\n");
        large_config.push_str("SecResponseBodyAccess On\n");
    }

    let result = parser.from_string(&large_config);
    assert!(result.is_ok(), "Parser should handle large configs");
}

#[test]
fn test_stress_many_requests_through_waf() {
    use coraza::seclang::Parser;
    use coraza::waf::Waf;

    let mut parser = Parser::new();
    parser
        .from_string("SecRuleEngine On")
        .expect("Failed to parse");

    let waf = Waf::new(to_waf_config(parser.config())).expect("Failed to create WAF");
    let server = TestServer::new(waf);

    // Process 100 requests
    for i in 0..100 {
        let response = server.process(TestRequest::get(format!("/test?id={}", i)).build());
        response.assert_status(200);
    }
}
