// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the rule engine.
//!
//! These tests exercise the complete rule evaluation pipeline as external users
//! would interact with it, testing the public API end-to-end.

use coraza::RulePhase;
use coraza::RuleVariable;
use coraza::collection::MapCollection;
use coraza::operators::{eq, streq};
use coraza::rules::{Rule, RuleGroup, RuleOperator, VariableSpec};
use coraza::transaction::Transaction;
use coraza::transformations::lowercase;

// ============================================================================
// Basic Rule Evaluation Tests
// ============================================================================

// Ported from: coraza/internal/corazawaf/rule_test.go::TestMatchEvaluate
#[test]
fn test_rule_match_evaluate() {
    // Create a rule that matches when ARGS_GET:test equals "0"
    let rule = Rule::new()
        .with_id(1)
        .add_variable(VariableSpec::new_string(
            RuleVariable::ArgsGet,
            "test".to_string(),
        ))
        .with_operator(RuleOperator::new(eq("0").unwrap().into(), "@eq", "0"));

    let mut tx = Transaction::new("test-tx");
    tx.args_get_mut().add("test", "0");

    let matches = rule.evaluate(&mut tx, true);

    // Should have one match
    assert_eq!(matches.len(), 1, "Expected 1 match");
    assert_eq!(matches[0].key, "test");
    assert_eq!(matches[0].value, "0");
}

// Ported from: coraza/internal/corazawaf/rule_test.go::TestNoMatchEvaluate
#[test]
fn test_rule_no_match_evaluate() {
    // Create a rule that matches when ARGS_GET:test equals "1"
    let rule = Rule::new()
        .with_id(1)
        .add_variable(VariableSpec::new_string(
            RuleVariable::ArgsGet,
            "test".to_string(),
        ))
        .with_operator(RuleOperator::new(eq("1").unwrap().into(), "@eq", "1"));

    let mut tx = Transaction::new("test-tx");
    tx.args_get_mut().add("test", "999"); // Different value

    let matches = rule.evaluate(&mut tx, true);

    // Should have no matches
    assert_eq!(matches.len(), 0, "Expected 0 matches");
}

// ============================================================================
// Variable Exception Tests
// ============================================================================

// Ported from: coraza/internal/corazawaf/rule_test.go::TestNoMatchEvaluateBecauseOfException
#[test]
fn test_rule_no_match_due_to_exception() {
    // Create a rule for ARGS_GET with exception for "test" key
    let mut var_spec = VariableSpec::new(RuleVariable::ArgsGet);
    var_spec.add_exception_string("test".to_string());

    let rule = Rule::new()
        .with_id(1)
        .add_variable(var_spec)
        .with_operator(RuleOperator::new(eq("0").unwrap().into(), "@eq", "0"));

    let mut tx = Transaction::new("test-tx");
    tx.args_get_mut().add("test", "0"); // Would match but is excepted

    let matches = rule.evaluate(&mut tx, true);

    // Should have no matches because "test" key is excepted
    assert_eq!(matches.len(), 0, "Expected 0 matches due to exception");
}

#[test]
fn test_rule_match_with_exception_for_other_key() {
    // Create a rule for ARGS_GET with exception for "id" key
    let mut var_spec = VariableSpec::new(RuleVariable::ArgsGet);
    var_spec.add_exception_string("id".to_string());

    let rule = Rule::new()
        .with_id(1)
        .add_variable(var_spec)
        .with_operator(RuleOperator::new(eq("0").unwrap().into(), "@eq", "0"));

    let mut tx = Transaction::new("test-tx");
    tx.args_get_mut().add("test", "0"); // Not excepted
    tx.args_get_mut().add("id", "0"); // Excepted

    let matches = rule.evaluate(&mut tx, true);

    // Should match only "test", not "id"
    assert_eq!(matches.len(), 1, "Expected 1 match");
    assert_eq!(matches[0].key, "test");
}

// ============================================================================
// Transformation Tests
// ============================================================================

#[test]
fn test_rule_with_transformation() {
    let mut rule = Rule::new()
        .with_id(1)
        .add_variable(VariableSpec::new_string(
            RuleVariable::ArgsGet,
            "name".to_string(),
        ))
        .with_operator(RuleOperator::new(
            streq("admin").unwrap().into(),
            "@streq",
            "admin",
        ));

    // Add lowercase transformation
    rule.transformations_mut()
        .add("lowercase", lowercase)
        .unwrap();

    let mut tx = Transaction::new("test-tx");
    tx.args_get_mut().add("name", "ADMIN"); // Will be lowercased

    let matches = rule.evaluate(&mut tx, true);

    // Should match after transformation
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].value, "admin");
}

#[test]
fn test_rule_with_multiple_transformations() {
    use coraza::transformations::uppercase;

    let mut rule = Rule::new()
        .with_id(1)
        .add_variable(VariableSpec::new_string(
            RuleVariable::ArgsGet,
            "data".to_string(),
        ))
        .with_operator(RuleOperator::new(
            streq("HELLO").unwrap().into(),
            "@streq",
            "HELLO",
        ));

    // Add transformation chain: lowercase then uppercase
    rule.transformations_mut()
        .add("lowercase", lowercase)
        .unwrap();
    rule.transformations_mut()
        .add("uppercase", uppercase)
        .unwrap();

    let mut tx = Transaction::new("test-tx");
    tx.args_get_mut().add("data", "HeLLo");

    let matches = rule.evaluate(&mut tx, true);

    // Should match after both transformations
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].value, "HELLO");
}

// ============================================================================
// Chained Rules Tests
// ============================================================================

#[test]
fn test_chained_rules_both_match() {
    // Create chained rule
    let mut chained_rule = Rule::new()
        .with_id(2)
        .add_variable(VariableSpec::new_string(
            RuleVariable::ArgsGet,
            "password".to_string(),
        ))
        .with_operator(RuleOperator::new(
            streq("secret").unwrap().into(),
            "@streq",
            "secret",
        ));
    chained_rule.metadata_mut().parent_id = 1;

    // Create parent rule with chain
    let rule = Rule::new()
        .with_id(1)
        .add_variable(VariableSpec::new_string(
            RuleVariable::ArgsGet,
            "username".to_string(),
        ))
        .with_operator(RuleOperator::new(
            streq("admin").unwrap().into(),
            "@streq",
            "admin",
        ))
        .with_chain(chained_rule);

    let mut tx = Transaction::new("test-tx");
    tx.args_get_mut().add("username", "admin");
    tx.args_get_mut().add("password", "secret");

    let matches = rule.evaluate(&mut tx, true);

    // Both rules match - should return 2 match data
    assert_eq!(matches.len(), 2);
}

#[test]
fn test_chained_rules_first_fails() {
    // Create chained rule
    let mut chained_rule = Rule::new()
        .with_id(2)
        .add_variable(VariableSpec::new_string(
            RuleVariable::ArgsGet,
            "password".to_string(),
        ))
        .with_operator(RuleOperator::new(
            streq("secret").unwrap().into(),
            "@streq",
            "secret",
        ));
    chained_rule.metadata_mut().parent_id = 1;

    // Create parent rule with chain
    let rule = Rule::new()
        .with_id(1)
        .add_variable(VariableSpec::new_string(
            RuleVariable::ArgsGet,
            "username".to_string(),
        ))
        .with_operator(RuleOperator::new(
            streq("admin").unwrap().into(),
            "@streq",
            "admin",
        ))
        .with_chain(chained_rule);

    let mut tx = Transaction::new("test-tx");
    tx.args_get_mut().add("username", "user"); // Doesn't match
    tx.args_get_mut().add("password", "secret");

    let matches = rule.evaluate(&mut tx, true);

    // First rule fails - chain fails
    assert_eq!(matches.len(), 0);
}

#[test]
fn test_chained_rules_second_fails() {
    // Create chained rule
    let mut chained_rule = Rule::new()
        .with_id(2)
        .add_variable(VariableSpec::new_string(
            RuleVariable::ArgsGet,
            "password".to_string(),
        ))
        .with_operator(RuleOperator::new(
            streq("secret").unwrap().into(),
            "@streq",
            "secret",
        ));
    chained_rule.metadata_mut().parent_id = 1;

    // Create parent rule with chain
    let rule = Rule::new()
        .with_id(1)
        .add_variable(VariableSpec::new_string(
            RuleVariable::ArgsGet,
            "username".to_string(),
        ))
        .with_operator(RuleOperator::new(
            streq("admin").unwrap().into(),
            "@streq",
            "admin",
        ))
        .with_chain(chained_rule);

    let mut tx = Transaction::new("test-tx");
    tx.args_get_mut().add("username", "admin");
    tx.args_get_mut().add("password", "wrong"); // Doesn't match

    let matches = rule.evaluate(&mut tx, true);

    // Second rule fails - chain fails
    assert_eq!(matches.len(), 0);
}

// ============================================================================
// Rule Group Tests
// ============================================================================

#[test]
fn test_rule_group_evaluation() {
    let mut group = RuleGroup::new();

    // Add two rules
    let rule1 = Rule::new()
        .with_id(1)
        .add_variable(VariableSpec::new_string(
            RuleVariable::ArgsGet,
            "id".to_string(),
        ))
        .with_operator(RuleOperator::new(eq("0").unwrap().into(), "@eq", "0"));

    let rule2 = Rule::new()
        .with_id(2)
        .add_variable(VariableSpec::new_string(
            RuleVariable::ArgsGet,
            "name".to_string(),
        ))
        .with_operator(RuleOperator::new(
            streq("test").unwrap().into(),
            "@streq",
            "test",
        ));

    group.add(rule1).unwrap();
    group.add(rule2).unwrap();

    let mut tx = Transaction::new("test-tx");
    tx.args_get_mut().add("id", "0");
    tx.args_get_mut().add("name", "test");

    // Evaluate all rules
    let _disrupted = group.eval(RulePhase::RequestHeaders, &mut tx, true);

    // Both rules should have matched (we can't easily verify this without
    // tracking state in Transaction, but we can verify no panic occurred)
}

// ============================================================================
// Multi-Variable Tests
// ============================================================================

#[test]
fn test_rule_with_multiple_variables() {
    let rule = Rule::new()
        .with_id(1)
        .add_variable(VariableSpec::new(RuleVariable::ArgsGet))
        .with_operator(RuleOperator::new(
            streq("attack").unwrap().into(),
            "@streq",
            "attack",
        ));

    let mut tx = Transaction::new("test-tx");
    tx.args_get_mut().add("param1", "safe");
    tx.args_get_mut().add("param2", "attack");
    tx.args_get_mut().add("param3", "safe");

    let matches = rule.evaluate(&mut tx, true);

    // Should match param2
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].key, "param2");
    assert_eq!(matches[0].value, "attack");
}

#[test]
fn test_rule_with_regex_variable_key() {
    use regex::Regex;

    let rx = Regex::new("id.*").unwrap();
    let var_spec = VariableSpec::new_regex(RuleVariable::ArgsGet, rx);

    let rule = Rule::new()
        .with_id(1)
        .add_variable(var_spec)
        .with_operator(RuleOperator::new(eq("123").unwrap().into(), "@eq", "123"));

    let mut tx = Transaction::new("test-tx");
    tx.args_get_mut().add("id", "123");
    tx.args_get_mut().add("id_number", "123");
    tx.args_get_mut().add("name", "123"); // Doesn't match regex

    let matches = rule.evaluate(&mut tx, true);

    // Should match both "id" and "id_number"
    assert_eq!(matches.len(), 2);
}

// ============================================================================
// Operator-less Rules (SecAction)
// ============================================================================

#[test]
fn test_operator_less_rule_always_matches() {
    // Rule with no operator (like SecAction)
    let rule = Rule::new().with_id(1);

    let mut tx = Transaction::new("test-tx");

    let matches = rule.evaluate(&mut tx, true);

    // Operator-less rules always match
    assert_eq!(matches.len(), 1);
}

// ============================================================================
// Complex Scenarios
// ============================================================================

#[test]
fn test_complex_rule_with_transformations_and_chain() {
    // Chained rule with transformation
    let mut chained_rule = Rule::new()
        .with_id(2)
        .add_variable(VariableSpec::new_string(
            RuleVariable::RequestHeaders,
            "User-Agent".to_string(),
        ))
        .with_operator(RuleOperator::new(
            streq("bot").unwrap().into(),
            "@streq",
            "bot",
        ));
    chained_rule.metadata_mut().parent_id = 1;
    chained_rule
        .transformations_mut()
        .add("lowercase", lowercase)
        .unwrap();

    // Parent rule with transformation and chain
    let mut rule = Rule::new()
        .with_id(1)
        .add_variable(VariableSpec::new_string(
            RuleVariable::ArgsGet,
            "action".to_string(),
        ))
        .with_operator(RuleOperator::new(
            streq("delete").unwrap().into(),
            "@streq",
            "delete",
        ))
        .with_chain(chained_rule);

    rule.transformations_mut()
        .add("lowercase", lowercase)
        .unwrap();

    let mut tx = Transaction::new("test-tx");
    tx.args_get_mut().add("action", "DELETE"); // Will be lowercased
    tx.request_headers_mut().add("User-Agent", "BOT"); // Will be lowercased to match "bot"

    let matches = rule.evaluate(&mut tx, true);

    // Both rules should match after transformations
    assert_eq!(matches.len(), 2);
}

#[test]
fn test_rule_group_with_mixed_rules() {
    let mut group = RuleGroup::new();

    // Operator-less rule
    let rule1 = Rule::new().with_id(1);

    // Rule with operator
    let rule2 = Rule::new()
        .with_id(2)
        .add_variable(VariableSpec::new_string(
            RuleVariable::ArgsGet,
            "test".to_string(),
        ))
        .with_operator(RuleOperator::new(eq("1").unwrap().into(), "@eq", "1"));

    // Rule with transformation
    let mut rule3 = Rule::new()
        .with_id(3)
        .add_variable(VariableSpec::new_string(
            RuleVariable::ArgsGet,
            "name".to_string(),
        ))
        .with_operator(RuleOperator::new(
            streq("admin").unwrap().into(),
            "@streq",
            "admin",
        ));
    rule3
        .transformations_mut()
        .add("lowercase", lowercase)
        .unwrap();

    group.add(rule1).unwrap();
    group.add(rule2).unwrap();
    group.add(rule3).unwrap();

    let mut tx = Transaction::new("test-tx");
    tx.args_get_mut().add("test", "1");
    tx.args_get_mut().add("name", "ADMIN");

    let _disrupted = group.eval(RulePhase::RequestHeaders, &mut tx, true);

    // All three rules should evaluate successfully
    assert_eq!(group.count(), 3);
}

#[test]
fn test_negated_operator() {
    // Rule with negated operator (matches when value is NOT "admin")
    let rule = Rule::new()
        .with_id(1)
        .add_variable(VariableSpec::new_string(
            RuleVariable::ArgsGet,
            "user".to_string(),
        ))
        .with_operator(RuleOperator::new(
            streq("admin").unwrap().into(),
            "!@streq", // Negated
            "admin",
        ));

    let mut tx = Transaction::new("test-tx");
    tx.args_get_mut().add("user", "guest");

    let matches = rule.evaluate(&mut tx, true);

    // Should match because value is NOT "admin"
    assert_eq!(matches.len(), 1);
}

#[test]
fn test_negated_operator_no_match() {
    // Rule with negated operator
    let rule = Rule::new()
        .with_id(1)
        .add_variable(VariableSpec::new_string(
            RuleVariable::ArgsGet,
            "user".to_string(),
        ))
        .with_operator(RuleOperator::new(
            streq("admin").unwrap().into(),
            "!@streq", // Negated
            "admin",
        ));

    let mut tx = Transaction::new("test-tx");
    tx.args_get_mut().add("user", "admin");

    let matches = rule.evaluate(&mut tx, true);

    // Should NOT match because negation reverses the result
    assert_eq!(matches.len(), 0);
}
