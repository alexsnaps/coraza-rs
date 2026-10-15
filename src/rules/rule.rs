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
use crate::actions::{Action, ActionType, RuleMetadata};
use crate::collection::MatchData;
use crate::rules::{
    RuleOperator, VariableSpec, execute_flow_and_disruptive_actions, execute_nondisruptive_actions,
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

    /// Actions to execute when rule matches
    actions: Vec<Action>,

    /// Rules chained to this one (AND logic), in order; empty unless this rule starts a chain
    pub(crate) chain: Vec<Rule>,
}

impl Rule {
    /// Create a new rule with default values.
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata::new(),
            variables: Vec::new(),
            operator: None,
            actions: Vec::new(),
            chain: Vec::new(),
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

    /// Adds an action. A rule has at most one disruptive action: adding one replaces
    /// the previous (the last one wins, as in SecLang).
    pub fn add_action(mut self, action: Action) -> Self {
        if action.action_type() == ActionType::Disruptive {
            self.actions
                .retain(|existing| existing.action_type() != ActionType::Disruptive);
        }
        self.actions.push(action);
        self
    }

    /// Appends a rule to this rule's chain; it must also match for this rule to match.
    pub fn with_chain(mut self, link: Rule) -> Self {
        self.chain.push(link);
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

    /// Get the actions.
    pub fn actions(&self) -> &[Action] {
        &self.actions
    }

    /// The rule's own variables, in order, for SecLang directives that update them.
    pub(crate) fn variables_mut(&mut self) -> &mut Vec<VariableSpec> {
        &mut self.variables
    }

    /// Set the rule's variables (replaces existing variables).
    ///
    /// This is used by SecLang directives like `SecRuleUpdateTargetById`.
    pub fn set_variables(&mut self, variables: Vec<VariableSpec>) {
        self.variables = variables;
    }

    /// Set the rule's actions (replaces existing actions).
    ///
    /// This is used by SecLang directives like `SecRuleUpdateActionById`.
    pub fn set_actions(&mut self, actions: Vec<Action>) {
        self.actions = actions;
    }

    /// Rules chained to this one, in evaluation order; empty if this rule starts no chain.
    pub fn chain(&self) -> &[Rule] {
        &self.chain
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

    /// Evaluate the rule, and its chain, against a transaction.
    ///
    /// Non-disruptive actions of each rule in the chain run for every value it
    /// matches, even if a later link fails. Only when every link matches are the
    /// match recorded and this rule's flow and disruptive actions run (disruptive
    /// ones only if `rule_engine_on`).
    ///
    /// Returns the match data of this rule and its chain; empty if any link didn't match.
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
        let id = self.metadata.id;
        let mut matched_values = self.match_values(tx, id);
        if matched_values.is_empty() {
            return matched_values;
        }

        for link in &self.chain {
            let link_matches = link.match_values(tx, id);
            if link_matches.is_empty() {
                return Vec::new();
            }
            matched_values.extend(link_matches);
        }

        // Record the match for audit logging; SecMarker and SecAction rules have ID 0
        if self.metadata.id != 0 {
            use crate::transaction::MatchedRule;

            let msg = self
                .metadata
                .msg
                .as_ref()
                .map(|m| m.expand(Some(tx)))
                .unwrap_or_default();

            let severity = self
                .metadata
                .severity
                .as_ref()
                .map(|s| format!("{:?}", s).to_uppercase())
                .unwrap_or_else(|| "NOTICE".to_string());

            let data = self
                .metadata
                .log_data
                .as_ref()
                .map(|ld| ld.expand(Some(tx)))
                .unwrap_or_default();

            tx.record_match(MatchedRule {
                rule_id: self.metadata.id,
                msg,
                severity,
                data,
                tags: self.metadata.tags.clone(),
            });
        }

        if let Some(severity) = self.metadata.severity {
            tx.raise_highest_severity(severity);
        }

        execute_flow_and_disruptive_actions(&self.actions, &self.metadata, tx, rule_engine_on);

        matched_values
    }

    /// Matches this rule's own variables and operator, ignoring its chain, and runs its
    /// non-disruptive actions once per matched value. RULE describes it, as `id` (that
    /// of the chain's first rule).
    ///
    /// A rule without an operator (SecAction, SecMarker) always matches once.
    fn match_values(&self, tx: &mut Transaction, id: i32) -> Vec<MatchData> {
        let expand = |text: &Option<crate::operators::Macro>, tx: &Transaction| {
            text.as_ref().map(|text| text.expand(Some(tx)))
        };
        let msg = expand(&self.metadata.msg, tx);
        let log_data = expand(&self.metadata.log_data, tx);
        let severity = self.metadata.severity.map_or("unknown", |s| s.as_str());
        tx.set_rule_variable(id, msg, &self.metadata.rev, log_data, severity);

        let Some(operator) = &self.operator else {
            // As in Go Coraza, an operator-less rule matches an empty, unknown variable
            let matched = MatchData::new_empty();
            tx.record_matched_variable(&matched);
            execute_nondisruptive_actions(&self.actions, &self.metadata, tx);
            return vec![matched];
        };

        // Operators store regex groups in TX.0-TX.9 only for rules with `capture`
        tx.set_capturing(self.metadata.capture);

        let mut matched_values = Vec::new();
        for var_spec in &self.variables {
            for var_match in var_spec.get_matches(tx) {
                // With multiMatch, the value before and after each transformation that
                // changed it is tested; otherwise only the fully transformed value.
                // TODO: Log transformation errors
                let (values, _errors) = if self.metadata.multi_match {
                    self.metadata
                        .transformations
                        .apply_multimatch(&var_match.value)
                } else {
                    let (value, errors) = self.metadata.transformations.apply(&var_match.value);
                    (vec![value], errors)
                };

                for value in values {
                    if operator.evaluate(Some(tx), &value) {
                        let matched =
                            MatchData::new(var_match.variable, var_match.key.clone(), value);
                        tx.record_matched_variable(&matched);
                        execute_nondisruptive_actions(&self.actions, &self.metadata, tx);
                        matched_values.push(matched);
                    }
                }
            }
        }
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
        rule.metadata_mut()
            .transformations
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
        let chained_rule = Rule::new()
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
        let chained_rule = Rule::new()
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
        let chained_rule = Rule::new()
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
