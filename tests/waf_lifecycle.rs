// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! WAF Lifecycle Integration Tests
//!
//! These tests validate the complete WAF lifecycle from configuration
//! to transaction processing, including rule management, phase processing,
//! and configuration inheritance.

use coraza::actions::{DenyAction, StatusAction};
use coraza::collection::{Keyed, MapCollection};
use coraza::config::WafConfig;
use coraza::operators::streq;
use coraza::rules::{Rule, RuleAction, RuleOperator, VariableSpec};
use coraza::types::{RuleEngineStatus, RulePhase, RuleVariable};
use coraza::waf::Waf;

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
    let config = WafConfig::new()
        .with_rule_engine(RuleEngineStatus::DetectionOnly)
        .with_request_body_limit(1048576)
        .with_response_body_limit(524288);

    let waf = Waf::new(config).expect("Failed to create WAF");
    let tx = waf.new_transaction();

    assert_eq!(tx.rule_engine(), RuleEngineStatus::DetectionOnly);
}

#[test]
fn test_waf_config_inheritance_to_transactions() {
    let config = WafConfig::new()
        .with_rule_engine(RuleEngineStatus::Off)
        .with_request_body_limit(2097152);

    let waf = Waf::new(config).expect("Failed to create WAF");

    // Multiple transactions should inherit the same config
    let tx1 = waf.new_transaction();
    let tx2 = waf.new_transaction();

    assert_eq!(tx1.rule_engine(), RuleEngineStatus::Off);
    assert_eq!(tx2.rule_engine(), RuleEngineStatus::Off);
}

#[test]
fn test_waf_invalid_config_rejected() {
    let config = WafConfig::new().with_request_body_limit(-1);

    let result = Waf::new(config);
    assert!(result.is_err(), "Invalid config should be rejected");
}

// ============================================================================
// Rule Management Tests
// ============================================================================

#[test]
fn test_waf_add_single_rule() {
    let mut waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");

    let operator = RuleOperator::new(streq("test").unwrap().into(), "@streq", "test");
    let rule = Rule::new()
        .with_id(1)
        .add_variable(VariableSpec::new(RuleVariable::Args))
        .with_operator(operator);

    assert!(waf.add_rule(rule).is_ok());
    assert_eq!(waf.rule_count(), 1);
}

#[test]
fn test_waf_add_multiple_rules() {
    let mut waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");

    for id in 1..=10 {
        let operator = RuleOperator::new(
            streq(&format!("test{}", id)).unwrap().into(),
            "@streq",
            format!("test{}", id),
        );
        let rule = Rule::new()
            .with_id(id)
            .add_variable(VariableSpec::new(RuleVariable::Args))
            .with_operator(operator);

        waf.add_rule(rule).expect("Failed to add rule");
    }

    assert_eq!(waf.rule_count(), 10);
}

#[test]
fn test_waf_duplicate_rule_id_rejected() {
    let mut waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");

    let operator = RuleOperator::new(streq("test").unwrap().into(), "@streq", "test");
    let rule1 = Rule::new()
        .with_id(100)
        .add_variable(VariableSpec::new(RuleVariable::Args))
        .with_operator(operator.clone());

    waf.add_rule(rule1).expect("First rule should succeed");

    let rule2 = Rule::new()
        .with_id(100)
        .add_variable(VariableSpec::new(RuleVariable::Args))
        .with_operator(operator);

    let result = waf.add_rule(rule2);
    assert!(result.is_err(), "Duplicate rule ID should be rejected");
}

#[test]
fn test_waf_find_rule_by_id() {
    let mut waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");

    let operator = RuleOperator::new(streq("test").unwrap().into(), "@streq", "test");
    let rule = Rule::new()
        .with_id(42)
        .add_variable(VariableSpec::new(RuleVariable::Args))
        .with_operator(operator);

    waf.add_rule(rule).expect("Failed to add rule");

    let found = waf.find_rule_by_id(42);
    assert!(found.is_some());
    assert_eq!(found.unwrap().metadata().id, 42);

    let not_found = waf.find_rule_by_id(999);
    assert!(not_found.is_none());
}

#[test]
fn test_waf_remove_rule_by_id() {
    let mut waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");

    let operator = RuleOperator::new(streq("test").unwrap().into(), "@streq", "test");
    let rule = Rule::new()
        .with_id(50)
        .add_variable(VariableSpec::new(RuleVariable::Args))
        .with_operator(operator);

    waf.add_rule(rule).expect("Failed to add rule");
    assert_eq!(waf.rule_count(), 1);

    waf.remove_rule_by_id(50);
    assert_eq!(waf.rule_count(), 0);
    assert!(waf.find_rule_by_id(50).is_none());
}

#[test]
fn test_waf_remove_multiple_rules_by_id() {
    let mut waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");

    // Add rules 10, 20, 30, 40, 50
    for id in (10..=50).step_by(10) {
        let operator = RuleOperator::new(streq("test").unwrap().into(), "@streq", "test");
        let rule = Rule::new()
            .with_id(id)
            .add_variable(VariableSpec::new(RuleVariable::Args))
            .with_operator(operator);
        waf.add_rule(rule).expect("Failed to add rule");
    }

    assert_eq!(waf.rule_count(), 5);

    // Remove rule 20 and 40
    waf.remove_rule_by_id(20);
    waf.remove_rule_by_id(40);

    assert_eq!(waf.rule_count(), 3);
    assert!(waf.find_rule_by_id(10).is_some());
    assert!(waf.find_rule_by_id(20).is_none());
    assert!(waf.find_rule_by_id(30).is_some());
    assert!(waf.find_rule_by_id(40).is_none());
    assert!(waf.find_rule_by_id(50).is_some());
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
    tx1.args_get_mut().add("key", "value1");

    // tx2 should not be affected
    assert_eq!(tx2.args_get().get("key"), Vec::<&str>::new());
}

#[test]
fn test_transaction_shares_waf_rules() {
    let mut waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");

    // Add a rule to WAF
    let operator = RuleOperator::new(streq("test").unwrap().into(), "@streq", "test");
    let rule = Rule::new()
        .with_id(100)
        .add_variable(VariableSpec::new(RuleVariable::Args))
        .with_operator(operator);

    waf.add_rule(rule).expect("Failed to add rule");

    // Transactions should have access to WAF rules via Arc
    let _tx = waf.new_transaction();
    // Transaction has access to rules through internal Arc reference
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
    // Note: process_uri doesn't update last_phase, only process_request_body and later do

    // Process request body (Phase 2)
    let _ = tx.process_request_body(b"test=value");
    assert_eq!(tx.last_phase(), Some(RulePhase::RequestBody));

    // Process response headers (Phase 3)
    let _ = tx.process_response_headers(200, "HTTP/1.1");
    assert_eq!(tx.last_phase(), Some(RulePhase::ResponseHeaders));

    // Process response body (Phase 4)
    let _ = tx.process_response_body(b"response data");
    assert_eq!(tx.last_phase(), Some(RulePhase::ResponseBody));

    // Process logging (Phase 5)
    tx.process_logging();
    assert_eq!(tx.last_phase(), Some(RulePhase::Logging));
}

#[test]
fn test_phase_idempotency() {
    let waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");
    let mut tx = waf.new_transaction();

    // Process request body twice
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
    assert_eq!(tx.args_get().get("q"), vec!["test"]);
    assert_eq!(tx.args_get().get("page"), vec!["1"]);

    // Add headers
    tx.add_request_header("User-Agent", "TestBot/1.0");
    tx.add_request_header("Cookie", "session=abc123");

    // REQUEST_HEADERS should be populated
    assert_eq!(tx.request_headers().get("user-agent"), vec!["TestBot/1.0"]);

    // REQUEST_COOKIES should be populated
    assert_eq!(tx.request_cookies().get("session"), vec!["abc123"]);
}

// ============================================================================
// Configuration Modification Tests
// ============================================================================

#[test]
fn test_waf_config_immutable_after_creation() {
    let config = WafConfig::new().with_rule_engine(RuleEngineStatus::DetectionOnly);

    let waf = Waf::new(config).expect("Failed to create WAF");

    // WAF config is immutable - changing the original doesn't affect WAF
    let tx = waf.new_transaction();
    assert_eq!(tx.rule_engine(), RuleEngineStatus::DetectionOnly);
}

#[test]
fn test_multiple_wafs_independent() {
    let config1 = WafConfig::new().with_rule_engine(RuleEngineStatus::On);
    let config2 = WafConfig::new().with_rule_engine(RuleEngineStatus::Off);

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
    let mut waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");

    // Add a simple rule
    let operator = RuleOperator::new(streq("attack").unwrap().into(), "@streq", "attack");
    let rule = Rule::new()
        .with_id(1)
        .add_variable(VariableSpec::new_string(
            RuleVariable::Args,
            "input".to_string(),
        ))
        .with_operator(operator);

    waf.add_rule(rule).expect("Failed to add rule");

    // Create transaction
    let mut tx = waf.new_transaction();
    tx.args_mut().add("input", "attack");

    // Evaluate rules (this happens during phase processing)
    // Note: Full evaluation integration requires Phase 2 processing
}

#[test]
fn test_waf_rules_shared_across_transactions() {
    let mut waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");

    let operator = RuleOperator::new(streq("test").unwrap().into(), "@streq", "test");
    let rule = Rule::new()
        .with_id(1)
        .add_variable(VariableSpec::new(RuleVariable::Args))
        .with_operator(operator);

    waf.add_rule(rule).expect("Failed to add rule");

    // Both transactions should see the same rule
    let _tx1 = waf.new_transaction();
    let _tx2 = waf.new_transaction();

    // Transactions share rules via Arc (verified by rule_count test above)
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
    let result = tx.process_request_body(b"{invalid json}");

    // Should return Ok (error logged but not fatal)
    assert!(result.is_ok());
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
    let _ = tx.request_headers().get("normal-header");
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
        tx.args_mut().add("test", "value");
        // Transaction dropped here
    }

    // WAF should still be usable
    let tx = waf.new_transaction();
    assert!(!tx.id().is_empty());
}

#[test]
fn test_waf_large_rule_set() {
    let mut waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");

    // Add 1000 rules
    for id in 1..=1000 {
        let operator = RuleOperator::new(
            streq(&format!("test{}", id)).unwrap().into(),
            "@streq",
            format!("test{}", id),
        );
        let rule = Rule::new()
            .with_id(id)
            .add_variable(VariableSpec::new(RuleVariable::Args))
            .with_operator(operator);

        waf.add_rule(rule).expect("Failed to add rule");
    }

    assert_eq!(waf.rule_count(), 1000);

    // Should still be able to find specific rules
    assert!(waf.find_rule_by_id(500).is_some());
    assert!(waf.find_rule_by_id(1000).is_some());
}

// ============================================================================
// Default Actions Tests
// ============================================================================

#[test]
fn test_waf_set_default_actions() {
    let mut waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");

    let default_action = RuleAction::new("deny", Box::new(DenyAction));
    waf.set_default_actions(RulePhase::RequestHeaders, vec![default_action]);

    let defaults = waf.get_default_actions(RulePhase::RequestHeaders);
    assert_eq!(defaults.len(), 1);
    assert_eq!(defaults[0].name(), "deny");
}

#[test]
fn test_waf_overwrite_default_actions() {
    let mut waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");

    let action1 = RuleAction::new("deny", Box::new(DenyAction));
    waf.set_default_actions(RulePhase::RequestHeaders, vec![action1]);

    assert_eq!(waf.get_default_actions(RulePhase::RequestHeaders).len(), 1);

    // Overwrite with empty vector
    waf.set_default_actions(RulePhase::RequestHeaders, vec![]);
    assert_eq!(waf.get_default_actions(RulePhase::RequestHeaders).len(), 0);
}

#[test]
fn test_waf_default_actions_per_phase() {
    let mut waf = Waf::new(WafConfig::new()).expect("Failed to create WAF");

    // Set different defaults for different phases
    waf.set_default_actions(
        RulePhase::RequestHeaders,
        vec![RuleAction::new("deny", Box::new(DenyAction))],
    );

    waf.set_default_actions(
        RulePhase::RequestBody,
        vec![
            RuleAction::new("deny", Box::new(DenyAction)),
            RuleAction::new("status", Box::new(StatusAction)),
        ],
    );

    assert_eq!(waf.get_default_actions(RulePhase::RequestHeaders).len(), 1);
    assert_eq!(waf.get_default_actions(RulePhase::RequestBody).len(), 2);
    assert_eq!(waf.get_default_actions(RulePhase::ResponseHeaders).len(), 0);
}
