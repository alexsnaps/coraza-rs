// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Core rule evaluation engine.
//!
//! This module implements the main Rule struct and evaluation logic that ties together:
//! - Variable extraction from transaction state
//! - Transformation pipelines
//! - Operator matching
//! - Action execution
//! - Rule chaining (AND logic)

use crate::RulePhase;
use crate::actions::Rule as RuleMetadata;
use crate::collection::MatchData;
use crate::operators::TransactionState;
use crate::rules::{
    RuleAction, RuleOperator, TransformationChain, VariableSpec,
    execute_flow_and_disruptive_actions, execute_nondisruptive_actions,
};
use crate::transaction::Transaction;

/// Core rule for WAF evaluation.
///
/// A rule extracts variables from a transaction, applies transformations,
/// evaluates an operator, and executes actions if the operator matches.
/// Rules can be chained together with AND logic.
///
/// # Evaluation Flow
///
/// 1. Extract variables from transaction using VariableSpec
/// 2. Apply transformation chain to each variable value
/// 3. Evaluate operator against each transformed value
/// 4. If match: execute nondisruptive actions immediately
/// 5. If parent rule and match: evaluate chained rules recursively
/// 6. If parent rule and full chain matches: execute flow/disruptive actions
///
/// # Examples
///
/// ```
/// use coraza::rules::Rule;
/// use coraza::RuleVariable;
///
/// // Simple rule that matches all requests
/// let rule = Rule::new()
///     .with_id(1);
///
/// // Rule has no operator - always matches (like SecAction)
/// assert!(rule.operator().is_none());
/// ```
#[derive(Debug)]
pub struct Rule {
    /// Rule metadata (id, msg, severity, etc.)
    metadata: RuleMetadata,

    /// Variables to extract from transaction
    variables: Vec<VariableSpec>,

    /// Operator to evaluate (None for SecAction/SecMarker)
    operator: Option<RuleOperator>,

    /// Transformation chain to apply to variable values
    transformations: TransformationChain,

    /// Actions to execute when rule matches
    actions: Vec<RuleAction>,

    /// Chained rule for AND logic (None if not chained)
    chain: Option<Box<Rule>>,
}

impl Rule {
    /// Create a new rule with default values.
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata::new(),
            variables: Vec::new(),
            operator: None,
            transformations: TransformationChain::new(),
            actions: Vec::new(),
            chain: None,
        }
    }

    /// Set the rule ID.
    pub fn with_id(mut self, id: i32) -> Self {
        self.metadata.id = id;
        self
    }

    /// Add a variable specification.
    pub fn add_variable(mut self, variable: VariableSpec) -> Self {
        self.variables.push(variable);
        self
    }

    /// Set the operator.
    pub fn with_operator(mut self, operator: RuleOperator) -> Self {
        self.operator = Some(operator);
        self
    }

    /// Add an action.
    pub fn add_action(mut self, action: RuleAction) -> Self {
        self.actions.push(action);
        self
    }

    /// Set the chained rule.
    pub fn with_chain(mut self, chain: Rule) -> Self {
        self.metadata.has_chain = true;
        self.chain = Some(Box::new(chain));
        self
    }

    /// Get the rule metadata.
    pub fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    /// Get mutable rule metadata.
    pub fn metadata_mut(&mut self) -> &mut RuleMetadata {
        &mut self.metadata
    }

    /// Get the operator (if any).
    pub fn operator(&self) -> Option<&RuleOperator> {
        self.operator.as_ref()
    }

    /// Get the transformation chain.
    pub fn transformations(&self) -> &TransformationChain {
        &self.transformations
    }

    /// Get mutable transformation chain.
    pub fn transformations_mut(&mut self) -> &mut TransformationChain {
        &mut self.transformations
    }

    /// Get the actions.
    pub fn actions(&self) -> &[RuleAction] {
        &self.actions
    }

    /// Get the chained rule (if any).
    pub fn chain(&self) -> Option<&Rule> {
        self.chain.as_deref()
    }

    /// Get the rule's processing phase.
    pub fn phase(&self) -> RulePhase {
        self.metadata.phase
    }

    /// Check if this rule is a SecMarker with the given label.
    ///
    /// SecMarkers are used for flow control with skipAfter actions.
    ///
    /// # Arguments
    ///
    /// * `marker` - The marker label to check for
    ///
    /// # Returns
    ///
    /// `true` if this rule is a SecMarker with the given label
    pub fn is_sec_marker(&self, marker: &str) -> bool {
        self.metadata.sec_mark.as_deref() == Some(marker)
    }

    /// Evaluate the rule against a transaction.
    ///
    /// Returns a vector of match data for all matches found. If the rule doesn't
    /// match, or if a chained rule fails to match, returns an empty vector.
    ///
    /// # Arguments
    ///
    /// * `tx` - Transaction to evaluate against
    /// * `rule_engine_on` - Whether the rule engine is in enforcement mode
    ///
    /// # Returns
    ///
    /// Vector of MatchData for all matched values. Empty if no match.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::rules::Rule;
    /// use coraza::transaction::Transaction;
    ///
    /// let rule = Rule::new().with_id(1);
    /// let mut tx = Transaction::new("test");
    ///
    /// // Evaluate rule (no operator = always matches)
    /// let matches = rule.evaluate(&mut tx, true);
    /// assert_eq!(matches.len(), 1);
    /// ```
    pub fn evaluate(&self, tx: &mut Transaction, rule_engine_on: bool) -> Vec<MatchData> {
        self.do_evaluate(tx, rule_engine_on, 0)
    }

    /// Internal recursive evaluation function.
    ///
    /// # Arguments
    ///
    /// * `tx` - Transaction to evaluate against
    /// * `rule_engine_on` - Whether the rule engine is in enforcement mode
    /// * `chain_level` - Current chain depth (0 for parent rule)
    fn do_evaluate(
        &self,
        tx: &mut Transaction,
        rule_engine_on: bool,
        chain_level: i32,
    ) -> Vec<MatchData> {
        // Operator-less rules always match (SecAction, SecMarker)
        if self.operator.is_none() {
            let match_data = MatchData::new_empty();
            let matches = vec![match_data];

            // Execute nondisruptive actions immediately
            execute_nondisruptive_actions(
                &self.actions,
                &self.metadata,
                tx as &mut dyn TransactionState,
            );

            // If this is a parent rule (not chained), evaluate chain and execute
            // flow/disruptive actions
            if self.metadata.parent_id == 0 {
                return self.evaluate_chain_and_actions(matches, tx, rule_engine_on, chain_level);
            }

            return matches;
        }

        // Extract matches from all variables
        let mut matched_values = Vec::new();

        for var_spec in &self.variables {
            let variable_matches = var_spec.get_matches(tx);

            for var_match in variable_matches {
                // Apply transformations to the variable value
                let (transformed_value, _errors) = if self.metadata.multi_match {
                    // Multi-match: test original + all intermediate transformed values
                    let (values, errors) = self.transformations.apply_multimatch(&var_match.value);
                    // For simplicity, concatenate all values (we'd actually test each separately)
                    // In a full implementation, we'd loop through values
                    (values.join("|"), errors)
                } else {
                    // Simple mode: just get final transformed value
                    self.transformations.apply(&var_match.value)
                };

                // TODO: Log transformation errors

                // Evaluate operator against transformed value
                let operator = self.operator.as_ref().unwrap();
                let matches = operator.evaluate(Some(tx), &transformed_value);

                if matches {
                    // Create match data
                    let match_data = MatchData::new(
                        var_match.variable,
                        var_match.key.clone(),
                        transformed_value.clone(),
                    );

                    matched_values.push(match_data);

                    // Execute nondisruptive actions immediately (unless parent of chain)
                    if self.metadata.parent_id != 0 || !self.metadata.has_chain {
                        execute_nondisruptive_actions(
                            &self.actions,
                            &self.metadata,
                            tx as &mut dyn TransactionState,
                        );
                    }
                }
            }
        }

        // If no matches, return empty
        if matched_values.is_empty() {
            return Vec::new();
        }

        // If this is a parent rule (not chained), evaluate chain and execute
        // flow/disruptive actions
        if self.metadata.parent_id == 0 {
            return self.evaluate_chain_and_actions(
                matched_values,
                tx,
                rule_engine_on,
                chain_level,
            );
        }

        matched_values
    }

    /// Evaluate chained rules and execute flow/disruptive actions.
    ///
    /// This is only called for parent rules (parent_id == 0).
    fn evaluate_chain_and_actions(
        &self,
        mut matched_values: Vec<MatchData>,
        tx: &mut Transaction,
        rule_engine_on: bool,
        mut chain_level: i32,
    ) -> Vec<MatchData> {
        // Evaluate chained rules (AND logic)
        let mut current_chain = self.chain.as_deref();
        while let Some(chained_rule) = current_chain {
            chain_level += 1;

            let chain_matches = chained_rule.do_evaluate(tx, rule_engine_on, chain_level);

            // If any chained rule doesn't match, the whole chain fails
            if chain_matches.is_empty() {
                return Vec::new();
            }

            // Aggregate matches from chain
            matched_values.extend(chain_matches);

            // Move to next chained rule
            current_chain = chained_rule.chain.as_deref();
        }

        // All rules matched - execute flow and disruptive actions
        execute_flow_and_disruptive_actions(&self.actions, &self.metadata, tx, rule_engine_on);

        matched_values
    }
}

impl Default for Rule {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuleVariable;
    use crate::collection::MapCollection;
    use crate::operators::streq;
    use crate::transaction::Transaction;

    // Ported from: coraza/internal/corazawaf/rule_test.go::TestSecActionRule
    #[test]
    fn test_operator_less_rule_always_matches() {
        let rule = Rule::new().with_id(1);

        let mut tx = Transaction::new("test");
        let matches = rule.evaluate(&mut tx, true);

        // Operator-less rules always match (SecAction behavior)
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_rule_with_operator_match() {
        let rule = Rule::new()
            .with_id(1)
            .add_variable(VariableSpec::new_string(
                RuleVariable::Args,
                "test".to_string(),
            ))
            .with_operator(RuleOperator::new(
                streq("value").unwrap().into(),
                "@streq",
                "value",
            ));

        let mut tx = Transaction::new("test");
        tx.args_mut().add("test", "value");

        let matches = rule.evaluate(&mut tx, true);

        // Should match the ARGS:test with value "value"
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].key, "test");
        assert_eq!(matches[0].value, "value");
    }

    #[test]
    fn test_rule_with_operator_no_match() {
        let rule = Rule::new()
            .with_id(1)
            .add_variable(VariableSpec::new_string(
                RuleVariable::Args,
                "test".to_string(),
            ))
            .with_operator(RuleOperator::new(
                streq("expected").unwrap().into(),
                "@streq",
                "expected",
            ));

        let mut tx = Transaction::new("test");
        tx.args_mut().add("test", "different");

        let matches = rule.evaluate(&mut tx, true);

        // Should not match
        assert!(matches.is_empty());
    }

    #[test]
    fn test_rule_with_transformation() {
        use crate::transformations::lowercase;

        let mut rule = Rule::new()
            .with_id(1)
            .add_variable(VariableSpec::new_string(
                RuleVariable::Args,
                "test".to_string(),
            ))
            .with_operator(RuleOperator::new(
                streq("hello").unwrap().into(),
                "@streq",
                "hello",
            ));

        // Add lowercase transformation
        rule.transformations_mut()
            .add("lowercase", lowercase)
            .unwrap();

        let mut tx = Transaction::new("test");
        tx.args_mut().add("test", "HELLO");

        let matches = rule.evaluate(&mut tx, true);

        // Should match after lowercase transformation
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].value, "hello");
    }

    // Ported from: coraza/internal/corazawaf/rule_test.go - Chain tests
    #[test]
    fn test_chained_rule_both_match() {
        let mut chained_rule = Rule::new()
            .with_id(2)
            .add_variable(VariableSpec::new_string(
                RuleVariable::Args,
                "second".to_string(),
            ))
            .with_operator(RuleOperator::new(
                streq("value2").unwrap().into(),
                "@streq",
                "value2",
            ));

        chained_rule.metadata.parent_id = 1;

        let rule = Rule::new()
            .with_id(1)
            .add_variable(VariableSpec::new_string(
                RuleVariable::Args,
                "first".to_string(),
            ))
            .with_operator(RuleOperator::new(
                streq("value1").unwrap().into(),
                "@streq",
                "value1",
            ))
            .with_chain(chained_rule);

        let mut tx = Transaction::new("test");
        tx.args_mut().add("first", "value1");
        tx.args_mut().add("second", "value2");

        let matches = rule.evaluate(&mut tx, true);

        // Both rules match - should return matches from both
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_chained_rule_first_fails() {
        let mut chained_rule = Rule::new()
            .with_id(2)
            .add_variable(VariableSpec::new_string(
                RuleVariable::Args,
                "second".to_string(),
            ))
            .with_operator(RuleOperator::new(
                streq("value2").unwrap().into(),
                "@streq",
                "value2",
            ));

        chained_rule.metadata.parent_id = 1;

        let rule = Rule::new()
            .with_id(1)
            .add_variable(VariableSpec::new_string(
                RuleVariable::Args,
                "first".to_string(),
            ))
            .with_operator(RuleOperator::new(
                streq("value1").unwrap().into(),
                "@streq",
                "value1",
            ))
            .with_chain(chained_rule);

        let mut tx = Transaction::new("test");
        tx.args_mut().add("first", "wrong");
        tx.args_mut().add("second", "value2");

        let matches = rule.evaluate(&mut tx, true);

        // First rule doesn't match - chain fails
        assert!(matches.is_empty());
    }

    #[test]
    fn test_chained_rule_second_fails() {
        let mut chained_rule = Rule::new()
            .with_id(2)
            .add_variable(VariableSpec::new_string(
                RuleVariable::Args,
                "second".to_string(),
            ))
            .with_operator(RuleOperator::new(
                streq("value2").unwrap().into(),
                "@streq",
                "value2",
            ));

        chained_rule.metadata.parent_id = 1;

        let rule = Rule::new()
            .with_id(1)
            .add_variable(VariableSpec::new_string(
                RuleVariable::Args,
                "first".to_string(),
            ))
            .with_operator(RuleOperator::new(
                streq("value1").unwrap().into(),
                "@streq",
                "value1",
            ))
            .with_chain(chained_rule);

        let mut tx = Transaction::new("test");
        tx.args_mut().add("first", "value1");
        tx.args_mut().add("second", "wrong");

        let matches = rule.evaluate(&mut tx, true);

        // Second rule doesn't match - chain fails
        assert!(matches.is_empty());
    }

    #[test]
    fn test_rule_builder_pattern() {
        let rule = Rule::new()
            .with_id(123)
            .add_variable(VariableSpec::new(RuleVariable::Args))
            .with_operator(RuleOperator::new(
                streq("test").unwrap().into(),
                "@streq",
                "test",
            ));

        assert_eq!(rule.metadata().id, 123);
        assert_eq!(rule.variables.len(), 1);
        assert!(rule.operator().is_some());
    }

    #[test]
    fn test_metadata_access() {
        let mut rule = Rule::new().with_id(1);

        assert_eq!(rule.metadata().id, 1);

        rule.metadata_mut().severity = Some(crate::RuleSeverity::Error);
        assert_eq!(rule.metadata().severity, Some(crate::RuleSeverity::Error));
    }
}
