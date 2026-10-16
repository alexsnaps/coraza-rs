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
use crate::operators::Outputs;
use crate::rules::{RuleOperator, VariableSpec};
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
/// Rules are compiled from SecLang (`crate::seclang`), which is the only way to make one.
#[derive(Debug)]
pub(crate) struct Rule {
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
    pub(crate) fn new() -> Self {
        Self {
            metadata: RuleMetadata::new(),
            variables: Vec::new(),
            operator: None,
            actions: Vec::new(),
            chain: Vec::new(),
        }
    }

    /// Add a variable specification.
    pub(crate) fn add_variable(mut self, variable: VariableSpec) -> Self {
        self.variables.push(variable);
        self
    }

    /// Set the operator.
    pub(crate) fn with_operator(mut self, operator: RuleOperator) -> Self {
        self.operator = Some(operator);
        self
    }

    /// Like [`Rule::add_action`], on a rule in place.
    pub(crate) fn push_action(&mut self, action: Action) {
        if action.action_type() == ActionType::Disruptive {
            self.actions
                .retain(|existing| existing.action_type() != ActionType::Disruptive);
        }
        self.actions.push(action);
    }

    /// Get the rule metadata.
    pub(crate) fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    /// Get mutable rule metadata.
    pub(crate) fn metadata_mut(&mut self) -> &mut RuleMetadata {
        &mut self.metadata
    }

    /// Get the operator (if any).
    #[cfg(test)]
    pub(crate) fn operator(&self) -> Option<&RuleOperator> {
        self.operator.as_ref()
    }

    /// Get the actions.
    pub(crate) fn actions(&self) -> &[Action] {
        &self.actions
    }

    /// The rule's own variables, in order, for SecLang directives that update them.
    pub(crate) fn variables_mut(&mut self) -> &mut Vec<VariableSpec> {
        &mut self.variables
    }

    /// Rules chained to this one, in evaluation order; empty if this rule starts no chain.
    #[cfg(test)]
    pub(crate) fn chain(&self) -> &[Rule] {
        &self.chain
    }

    /// Get the rule's processing phase.
    pub(crate) fn phase(&self) -> RulePhase {
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
    pub(crate) fn is_sec_marker(&self, marker: &str) -> bool {
        self.metadata.sec_mark.as_deref() == Some(marker)
    }

    /// Evaluate the rule, and its chain, against a transaction.
    ///
    /// Non-disruptive actions of each rule in the chain run for every value it
    /// matches, even if a later link fails. Only when every link matches are the
    /// match recorded and this rule's flow and disruptive actions run; the transaction
    /// decides whether a disruptive one takes effect.
    ///
    /// Returns the match data of this rule and its chain; empty if any link didn't match.
    pub(crate) fn evaluate(&self, tx: &mut Transaction) -> Vec<MatchData> {
        let id = self.metadata.id;
        let mut matched_values = self.match_values(tx, id);
        if matched_values.is_empty() {
            return matched_values;
        }
        let own_matches = matched_values.len();

        for link in &self.chain {
            let link_matches = link.match_values(tx, id);
            if link_matches.is_empty() {
                return Vec::new();
            }
            matched_values.extend(link_matches);
        }

        // As in Go Coraza, the first rule of a chain describes its matches once the whole
        // chain matched, so that its msg and logdata see the chain's MATCHED_* variables
        if !self.chain.is_empty() {
            let (message, data) = self.describe_match(tx);
            for matched in &mut matched_values[..own_matches] {
                matched.message.clone_from(&message);
                matched.data.clone_from(&data);
            }
        }

        // Record the match for logging; SecMarker rules have ID 0
        if self.metadata.id != 0 {
            let mut rule = self.metadata.clone();
            for link in &self.chain {
                rule.raw.push_str(" \n");
                rule.raw.push_str(&link.metadata.raw);
            }
            let disruptive_action = self
                .actions
                .iter()
                .find(|action| action.action_type() == ActionType::Disruptive)
                .map(Action::name);
            tx.record_match(rule, matched_values.clone(), disruptive_action);
        }

        if let Some(severity) = self.metadata.severity {
            tx.raise_highest_severity(severity);
        }

        self.run_actions(tx, |action_type| action_type != ActionType::Nondisruptive);

        matched_values
    }

    /// Runs, in order, this rule's actions whose type `runs` accepts.
    fn run_actions(&self, tx: &mut Transaction, runs: impl Fn(ActionType) -> bool) {
        for action in &self.actions {
            if runs(action.action_type()) {
                action.evaluate(&self.metadata, tx);
            }
        }
    }

    /// This rule's `msg` and `logdata`, expanded now; empty when unset.
    fn describe_match(&self, tx: &Transaction) -> (String, String) {
        let expand = |text: &Option<crate::operators::Macro>| {
            text.as_ref()
                .map(|text| text.expand(tx))
                .unwrap_or_default()
        };
        (expand(&self.metadata.msg), expand(&self.metadata.log_data))
    }

    /// Matches this rule's own variables and operator, ignoring its chain, and runs its
    /// non-disruptive actions once per matched value. RULE describes it, as `id` (that
    /// of the chain's first rule).
    ///
    /// A rule without an operator (SecAction, SecMarker) always matches once.
    fn match_values(&self, tx: &mut Transaction, id: i32) -> Vec<MatchData> {
        let expand = |text: &Option<crate::operators::Macro>, tx: &Transaction| {
            text.as_ref().map(|text| text.expand(tx))
        };
        let msg = expand(&self.metadata.msg, tx);
        let log_data = expand(&self.metadata.log_data, tx);
        let severity = self.metadata.severity.map_or("unknown", |s| s.as_str());
        tx.set_rule_variable(id, msg, &self.metadata.rev, log_data, severity);

        let Some(operator) = &self.operator else {
            // As in Go Coraza, an operator-less rule matches an empty, unknown variable
            let mut matched = MatchData::new_empty();
            tx.record_matched_variable(&matched);
            self.run_actions(tx, |action_type| action_type == ActionType::Nondisruptive);
            if self.chain.is_empty() {
                (matched.message, matched.data) = self.describe_match(tx);
            }
            return vec![matched];
        };

        // Operators capture, for TX.0-TX.9, only for rules with `capture`
        let mut outputs = Outputs::new(self.metadata.capture);

        let mut matched_values = Vec::new();
        for var_spec in &self.variables {
            for var_match in var_spec.get_matches_for_rule(tx, id) {
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
                    let operator_matched = operator.evaluate(tx, &value, &mut outputs);
                    // As in Go Coraza, what the operator handed back is stored whether or not
                    // the rule matches (a negated operator may have captured)
                    tx.store_operator_outputs(&mut outputs);
                    if operator_matched {
                        let mut matched =
                            MatchData::new(var_match.variable, var_match.key.clone(), value);
                        tx.record_matched_variable(&matched);
                        self.run_actions(tx, |action_type| {
                            action_type == ActionType::Nondisruptive
                        });
                        // The first rule of a chain describes its matches once the chain matched
                        if self.chain.is_empty() {
                            (matched.message, matched.data) = self.describe_match(tx);
                        }
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
    use crate::rules::RuleGroup;
    use crate::seclang::{compile_sec_action, compile_sec_rule};
    use crate::transaction::Transaction;

    /// The rule a `SecRule` directive with `arguments` compiles to.
    fn sec_rule(arguments: &str) -> Rule {
        compile_sec_rule(arguments).unwrap()
    }

    /// `SecRule` directives with `arguments`, added in order: the first one, with
    /// `chain`, takes the next ones as its chain.
    fn chain(arguments: &[&str]) -> RuleGroup {
        let mut group = RuleGroup::new();
        for arguments in arguments {
            group.add(sec_rule(arguments)).unwrap();
        }
        assert_eq!(group.count(), 1, "one chain");
        group
    }

    const FIRST: &str = r#"ARGS:first "@streq value1" "id:1,chain""#;
    const SECOND: &str = r#"ARGS:second "@streq value2" "t:none""#;

    // Ported from: coraza/internal/corazawaf/rule_test.go::TestSecActionRule
    #[test]
    fn test_operator_less_rule_always_matches() {
        let rule = compile_sec_action(r#""id:1""#).unwrap();

        let mut tx = Transaction::new("test");
        let matches = rule.evaluate(&mut tx);

        // Operator-less rules always match (SecAction behavior)
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_rule_with_operator_match() {
        let rule = sec_rule(r#"ARGS:test "@streq value" "id:1""#);

        let mut tx = Transaction::new("test");
        tx.add_get_argument("test", "value");

        let matches = rule.evaluate(&mut tx);

        // Should match the ARGS:test with value "value"
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].key, "test");
        assert_eq!(matches[0].value, b"value");
    }

    #[test]
    fn test_rule_with_operator_no_match() {
        let rule = sec_rule(r#"ARGS:test "@streq expected" "id:1""#);

        let mut tx = Transaction::new("test");
        tx.add_get_argument("test", "different");

        let matches = rule.evaluate(&mut tx);

        // Should not match
        assert!(matches.is_empty());
    }

    #[test]
    fn test_rule_with_transformation() {
        let rule = sec_rule(r#"ARGS:test "@streq hello" "id:1,t:lowercase""#);

        let mut tx = Transaction::new("test");
        tx.add_get_argument("test", "HELLO");

        let matches = rule.evaluate(&mut tx);

        // Should match after lowercase transformation
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].value, b"hello");
    }

    // Ported from: coraza/internal/corazawaf/rule_test.go - Chain tests
    #[test]
    fn test_chained_rule_both_match() {
        let group = chain(&[FIRST, SECOND]);

        let mut tx = Transaction::new("test");
        tx.add_get_argument("first", "value1");
        tx.add_get_argument("second", "value2");

        let matches = group.get_rules()[0].evaluate(&mut tx);

        // Both rules match - should return matches from both
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_chained_rule_first_fails() {
        let group = chain(&[FIRST, SECOND]);

        let mut tx = Transaction::new("test");
        tx.add_get_argument("first", "wrong");
        tx.add_get_argument("second", "value2");

        let matches = group.get_rules()[0].evaluate(&mut tx);

        // First rule doesn't match - chain fails
        assert!(matches.is_empty());
    }

    #[test]
    fn test_chained_rule_second_fails() {
        let group = chain(&[FIRST, SECOND]);

        let mut tx = Transaction::new("test");
        tx.add_get_argument("first", "value1");
        tx.add_get_argument("second", "wrong");

        let matches = group.get_rules()[0].evaluate(&mut tx);

        // Second rule doesn't match - chain fails
        assert!(matches.is_empty());
    }

    #[test]
    fn test_compiled_rule_has_its_parts() {
        let rule = sec_rule(r#"ARGS "@streq test" "id:123,severity:ERROR""#);

        assert_eq!(rule.metadata().id, 123);
        assert_eq!(rule.metadata().severity, Some(crate::RuleSeverity::Error));
        assert_eq!(rule.variables.len(), 1);
        assert!(rule.operator().is_some());
    }
}
