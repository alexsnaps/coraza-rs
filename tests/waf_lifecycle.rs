// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! WAF Lifecycle Integration Tests
//!
//! These tests validate the complete WAF lifecycle from configuration
//! to transaction processing, including rule management, phase processing,
//! and configuration inheritance.

use coraza::config::WafConfig;
use coraza::seclang::Parser;
use coraza::transaction::Interruption;
use coraza::types::{RuleEngineStatus, RulePhase, RuleVariable};
use coraza::waf::Waf;

/// A WAF with the rules `directives` compile to.
fn waf(directives: &str) -> Waf {
    let mut parser = Parser::new();
    parser.from_string(directives).expect("rules should parse");
    parser.into_waf().expect("config should be valid")
}

/// `SecRule` `id`, denying a request with an argument `test{id}` in phase 1.
fn rule(id: i32) -> String {
    format!("SecRule ARGS \"@streq test{id}\" \"id:{id},phase:1,deny,status:403\"\n")
}

/// The interruption of a GET request for `/?{query}`, in phase 1, if any.
fn get(waf: &Waf, query: &str) -> Option<Interruption> {
    let mut tx = waf.new_transaction();
    tx.process_uri(&format!("/?{query}"), "GET", "HTTP/1.1");
    tx.process_request_headers()
}

// ============================================================================
// WAF Configuration Tests
// ============================================================================

#[test]
fn test_waf_creation_with_default_config() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let tx = waf.new_transaction();

    // Default configuration should allow requests
    assert_eq!(tx.rule_engine(), RuleEngineStatus::On);
}

#[test]
fn test_waf_creation_with_custom_config() {
    let config = WafConfig {
        rule_engine: RuleEngineStatus::DetectionOnly,
        request_body_limit: 1048576,
        response_body_limit: 524288,
        ..WafConfig::default()
    };

    let waf = Waf::new(config).expect("Failed to create WAF");
    let tx = waf.new_transaction();

    assert_eq!(tx.rule_engine(), RuleEngineStatus::DetectionOnly);
}

#[test]
fn test_waf_config_inheritance_to_transactions() {
    let config = WafConfig {
        rule_engine: RuleEngineStatus::Off,
        request_body_limit: 2097152,
        ..WafConfig::default()
    };

    let waf = Waf::new(config).expect("Failed to create WAF");

    // Multiple transactions should inherit the same config
    let tx1 = waf.new_transaction();
    let tx2 = waf.new_transaction();

    assert_eq!(tx1.rule_engine(), RuleEngineStatus::Off);
    assert_eq!(tx2.rule_engine(), RuleEngineStatus::Off);
}

#[test]
fn test_waf_invalid_config_rejected() {
    let config = WafConfig {
        request_body_limit: -1,
        ..WafConfig::default()
    };

    let result = Waf::new(config);
    assert!(result.is_err(), "Invalid config should be rejected");
}

// ============================================================================
// Rule Management Tests
// ============================================================================

#[test]
fn test_waf_loads_a_single_rule() {
    let waf = waf(&rule(1));
    assert_eq!(waf.rule_count(), 1);
}

#[test]
fn test_waf_loads_multiple_rules() {
    let waf = waf(&(1..=10).map(rule).collect::<String>());
    assert_eq!(waf.rule_count(), 10);
}

#[test]
fn test_waf_duplicate_rule_id_rejected() {
    let mut parser = Parser::new();
    let result = parser.from_string(&format!("{}{}", rule(100), rule(100)));
    assert!(result.is_err(), "Duplicate rule ID should be rejected");
}

#[test]
fn test_waf_reports_the_rule_that_interrupts() {
    let waf = waf(&format!("{}{}", rule(41), rule(42)));

    assert_eq!(get(&waf, "a=test42").map(|i| i.rule_id), Some(42));
    assert_eq!(get(&waf, "a=test999"), None);
}

// ============================================================================
// Transaction Lifecycle Tests
// ============================================================================

#[test]
fn test_waf_create_single_transaction() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let tx = waf.new_transaction();

    // Transaction should have an auto-generated ID
    assert!(!tx.id().is_empty());
}

#[test]
fn test_waf_create_transaction_with_custom_id() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let tx = waf.new_transaction_with_id("custom-tx-123".to_string());

    assert_eq!(tx.id(), "custom-tx-123");
}

#[test]
fn test_waf_multiple_transactions() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");

    // Create 100 transactions - each should be independent
    for i in 0..100 {
        let tx = waf.new_transaction_with_id(format!("tx-{}", i));
        assert_eq!(tx.id(), format!("tx-{}", i));
    }
}

#[test]
fn test_transaction_independence() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");

    let mut tx1 = waf.new_transaction_with_id("tx1".to_string());
    let tx2 = waf.new_transaction_with_id("tx2".to_string());

    // Modify tx1
    tx1.add_get_argument("key", "value1");

    // tx2 should not be affected
    assert_eq!(tx2.get_variable(RuleVariable::ArgsGet, Some("key")), None);
}

// ============================================================================
// Phase Processing Tests
// ============================================================================

#[test]
fn test_transaction_phase_progression() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let mut tx = waf.new_transaction();

    // Initially no phase processed
    assert_eq!(tx.last_phase(), None);

    // Process URI (Phase 1)
    tx.process_uri("/test", "GET", "HTTP/1.1");
    // Note: process_uri doesn't update last_phase, only the phase methods do

    // Process request headers (Phase 1), then the request body (Phase 2)
    tx.process_request_headers();
    let _ = tx.process_request_body(b"test=value");
    assert_eq!(tx.last_phase(), Some(RulePhase::RequestBody));

    // Process response headers (Phase 3)
    let _ = tx.process_response_headers(200, "HTTP/1.1");
    assert_eq!(tx.last_phase(), Some(RulePhase::ResponseHeaders));

    // Process response body (Phase 4)
    let _ = tx.process_response_body(b"response data");
    assert_eq!(tx.last_phase(), Some(RulePhase::ResponseBody));

    // Process logging (Phase 5)
    tx.process_logging().unwrap();
    assert_eq!(tx.last_phase(), Some(RulePhase::Logging));
}

#[test]
fn test_phase_idempotency() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let mut tx = waf.new_transaction();

    // Process request body twice
    tx.process_request_headers();
    let _ = tx.process_request_body(b"test=value");
    let phase1 = tx.last_phase();

    let _ = tx.process_request_body(b"different=data");
    let phase2 = tx.last_phase();

    // Second call should be ignored (phase doesn't regress)
    assert_eq!(phase1, phase2);
}

#[test]
fn test_transaction_variables_populated() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let mut tx = waf.new_transaction();

    // Process URI with query string
    tx.process_uri("/search?q=test&page=1", "GET", "HTTP/1.1");

    // ARGS_GET should be populated
    let arg = |key| tx.get_variable(RuleVariable::ArgsGet, Some(key));
    assert_eq!(arg("q").as_deref(), Some("test"));
    assert_eq!(arg("page").as_deref(), Some("1"));

    // Add headers
    tx.add_request_header("User-Agent", "TestBot/1.0");
    tx.add_request_header("Cookie", "session=abc123");

    // REQUEST_HEADERS should be populated
    let user_agent = tx.get_variable(RuleVariable::RequestHeaders, Some("user-agent"));
    assert_eq!(user_agent.as_deref(), Some("TestBot/1.0"));

    // REQUEST_COOKIES should be populated
    let session = tx.get_variable(RuleVariable::RequestCookies, Some("session"));
    assert_eq!(session.as_deref(), Some("abc123"));
}

// ============================================================================
// Configuration Modification Tests
// ============================================================================

#[test]
fn test_waf_config_immutable_after_creation() {
    let config = WafConfig {
        rule_engine: RuleEngineStatus::DetectionOnly,
        ..WafConfig::default()
    };

    let waf = Waf::new(config).expect("Failed to create WAF");

    // WAF config is immutable - changing the original doesn't affect WAF
    let tx = waf.new_transaction();
    assert_eq!(tx.rule_engine(), RuleEngineStatus::DetectionOnly);
}

#[test]
fn test_multiple_wafs_independent() {
    let config1 = WafConfig {
        rule_engine: RuleEngineStatus::On,
        ..WafConfig::default()
    };
    let config2 = WafConfig {
        rule_engine: RuleEngineStatus::Off,
        ..WafConfig::default()
    };

    let waf1 = Waf::new(config1).expect("Failed to create WAF1");
    let waf2 = Waf::new(config2).expect("Failed to create WAF2");

    let tx1 = waf1.new_transaction();
    let tx2 = waf2.new_transaction();

    assert_eq!(tx1.rule_engine(), RuleEngineStatus::On);
    assert_eq!(tx2.rule_engine(), RuleEngineStatus::Off);
}

// ============================================================================
// Rule Evaluation Tests
// ============================================================================

#[test]
fn test_waf_rule_evaluation_basic() {
    let waf = waf(r#"SecRule ARGS:input "@streq attack" "id:1,phase:1,deny,status:403""#);

    assert_eq!(get(&waf, "input=attack").map(|i| i.status), Some(403));
    assert_eq!(get(&waf, "input=benign"), None);
}

#[test]
fn test_waf_rules_shared_across_transactions() {
    let waf = waf(&rule(1));

    // Both transactions see the same rule
    let tx1 = get(&waf, "a=test1");
    let tx2 = get(&waf, "a=test1");
    assert_eq!(tx1.map(|i| i.rule_id), Some(1));
    assert_eq!(tx2.map(|i| i.rule_id), Some(1));
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_waf_handles_invalid_body_gracefully() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let mut tx = waf.new_transaction();

    // Invalid JSON should not crash
    tx.add_request_header("Content-Type", "application/json");
    tx.process_request_headers();
    let result = tx.process_request_body(b"{invalid json}");

    // Not an interruption: rules see the error in REQBODY_ERROR
    assert!(result.is_none());
}

#[test]
fn test_waf_handles_malformed_headers_gracefully() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let mut tx = waf.new_transaction();

    // Add various header formats
    tx.add_request_header("Normal-Header", "value");
    tx.add_request_header("", "empty-name");
    tx.add_request_header("Empty-Value", "");

    // Should not crash
    let _ = tx.get_variable(RuleVariable::RequestHeaders, Some("normal-header"));
}

// ============================================================================
// Memory and Resource Tests
// ============================================================================

#[test]
fn test_waf_transaction_cleanup() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");

    // Create and drop many transactions
    for i in 0..1000 {
        let mut tx = waf.new_transaction_with_id(format!("tx-{}", i));
        tx.add_get_argument("test", "value");
        // Transaction dropped here
    }

    // WAF should still be usable
    let tx = waf.new_transaction();
    assert!(!tx.id().is_empty());
}

#[test]
fn test_waf_large_rule_set() {
    let waf = waf(&(1..=1000).map(rule).collect::<String>());
    assert_eq!(waf.rule_count(), 1000);

    // Each rule still applies
    assert_eq!(get(&waf, "a=test500").map(|i| i.rule_id), Some(500));
    assert_eq!(get(&waf, "a=test1000").map(|i| i.rule_id), Some(1000));
}
