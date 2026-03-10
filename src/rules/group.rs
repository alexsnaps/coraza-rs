// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Rule group management and phase-based evaluation.
//!
//! This module provides RuleGroup for organizing and evaluating collections of rules.
//! Rules are evaluated in syntactic order within their assigned phase.

use crate::RulePhase;
use crate::rules::Rule;
use crate::transaction::Transaction;

/// Collection of rules for WAF evaluation.
///
/// A RuleGroup manages a collection of rules and provides methods for:
/// - Adding/removing rules
/// - Finding rules by ID
/// - Evaluating all rules in a specific phase
///
/// RuleGroup is not concurrent-safe and should not be modified after compilation.
///
/// # Examples
///
/// ```
/// use coraza::rules::{RuleGroup, Rule};
///
/// let mut group = RuleGroup::new();
///
/// let rule = Rule::new().with_id(1);
/// group.add(rule).unwrap();
///
/// assert_eq!(group.count(), 1);
/// ```
#[derive(Debug, Default)]
pub struct RuleGroup {
    /// Rules in syntactic order
    rules: Vec<Rule>,
}

impl RuleGroup {
    /// Create a new empty rule group.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule to the group.
    ///
    /// Returns an error if a rule with the same ID already exists.
    ///
    /// # Arguments
    ///
    /// * `rule` - Rule to add to the group
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the rule was added successfully
    /// * `Err(String)` if a duplicate ID was found
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::rules::{RuleGroup, Rule};
    ///
    /// let mut group = RuleGroup::new();
    /// let rule = Rule::new().with_id(1);
    ///
    /// assert!(group.add(rule).is_ok());
    /// ```
    pub fn add(&mut self, rule: Rule) -> Result<(), String> {
        // Check for duplicate IDs
        let rule_id = rule.metadata().id;
        if rule_id != 0 && self.find_by_id(rule_id).is_some() {
            return Err(format!("duplicated rule id {}", rule_id));
        }

        self.rules.push(rule);
        Ok(())
    }

    /// Find a rule by its ID.
    ///
    /// Returns a reference to the rule if found, None otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::rules::{RuleGroup, Rule};
    ///
    /// let mut group = RuleGroup::new();
    /// group.add(Rule::new().with_id(123)).unwrap();
    ///
    /// assert!(group.find_by_id(123).is_some());
    /// assert!(group.find_by_id(999).is_none());
    /// ```
    pub fn find_by_id(&self, id: i32) -> Option<&Rule> {
        self.rules.iter().find(|r| r.metadata().id == id)
    }

    /// Find a mutable rule by its ID.
    pub fn find_by_id_mut(&mut self, id: i32) -> Option<&mut Rule> {
        self.rules.iter_mut().find(|r| r.metadata().id == id)
    }

    /// Delete a rule by its ID.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::rules::{RuleGroup, Rule};
    ///
    /// let mut group = RuleGroup::new();
    /// group.add(Rule::new().with_id(1)).unwrap();
    /// group.add(Rule::new().with_id(2)).unwrap();
    ///
    /// group.delete_by_id(1);
    /// assert_eq!(group.count(), 1);
    /// assert!(group.find_by_id(1).is_none());
    /// ```
    pub fn delete_by_id(&mut self, id: i32) {
        self.rules.retain(|r| r.metadata().id != id);
    }

    /// Delete rules by ID range (inclusive).
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::rules::{RuleGroup, Rule};
    ///
    /// let mut group = RuleGroup::new();
    /// group.add(Rule::new().with_id(1)).unwrap();
    /// group.add(Rule::new().with_id(2)).unwrap();
    /// group.add(Rule::new().with_id(3)).unwrap();
    /// group.add(Rule::new().with_id(5)).unwrap();
    ///
    /// group.delete_by_range(2, 3);
    /// assert_eq!(group.count(), 2); // Only 1 and 5 remain
    /// ```
    pub fn delete_by_range(&mut self, start: i32, end: i32) {
        self.rules
            .retain(|r| r.metadata().id < start || r.metadata().id > end);
    }

    /// Delete rules by message.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::rules::{RuleGroup, Rule};
    /// use coraza::operators::Macro;
    ///
    /// let mut group = RuleGroup::new();
    /// let mut rule = Rule::new().with_id(1);
    /// rule.metadata_mut().msg = Some(Macro::new("test message").unwrap());
    /// group.add(rule).unwrap();
    ///
    /// group.delete_by_msg("test message");
    /// assert_eq!(group.count(), 0);
    /// ```
    pub fn delete_by_msg(&mut self, msg: &str) {
        self.rules
            .retain(|r| r.metadata().msg.as_ref().is_none_or(|m| m.as_str() != msg));
    }

    /// Delete rules by tag.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::rules::{RuleGroup, Rule};
    ///
    /// let mut group = RuleGroup::new();
    /// let mut rule = Rule::new().with_id(1);
    /// rule.metadata_mut().tags.push("attack".to_string());
    /// group.add(rule).unwrap();
    ///
    /// group.delete_by_tag("attack");
    /// assert_eq!(group.count(), 0);
    /// ```
    pub fn delete_by_tag(&mut self, tag: &str) {
        self.rules
            .retain(|r| !r.metadata().tags.contains(&tag.to_string()));
    }

    /// Get all rules in the group.
    pub fn get_rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Get count of rules in the group.
    pub fn count(&self) -> usize {
        self.rules.len()
    }

    /// Evaluate all rules for a specific phase.
    ///
    /// Rules are evaluated in syntactic order. Evaluation stops early if:
    /// - An interruption occurs (and phase is not Logging)
    /// - Skip/SkipAfter flow control is active
    ///
    /// # Arguments
    ///
    /// * `_phase` - The phase to evaluate rules for (currently unused)
    /// * `tx` - Transaction to evaluate against
    /// * `rule_engine_on` - Whether the rule engine is in enforcement mode
    ///
    /// # Returns
    ///
    /// True if the transaction was disrupted (interruption occurred).
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::rules::{RuleGroup, Rule};
    /// use coraza::transaction::Transaction;
    /// use coraza::RulePhase;
    ///
    /// let mut group = RuleGroup::new();
    /// group.add(Rule::new().with_id(1)).unwrap();
    ///
    /// let mut tx = Transaction::new("test");
    /// let disrupted = group.eval(RulePhase::RequestHeaders, &mut tx, true);
    /// ```
    pub fn eval(&self, _phase: RulePhase, tx: &mut Transaction, rule_engine_on: bool) -> bool {
        // TODO: Track skip counter and skipAfter marker in Transaction
        // TODO: Filter rules by phase
        // For now, evaluate all rules in the group (simplified implementation)

        for rule in &self.rules {
            // TODO: Check if rule should run in this phase
            // For now, evaluate all rules (simplified implementation)

            // Evaluate the rule
            let _matches = rule.evaluate(tx, rule_engine_on);

            // TODO: Check for interruptions and break if needed
            // TODO: Handle skip/skipAfter flow control
        }

        // TODO: Return true if transaction was disrupted
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::Macro;

    // Helper to create a test rule
    fn new_test_rule(id: i32) -> Rule {
        let mut rule = Rule::new().with_id(id);
        rule.metadata_mut().msg = Some(Macro::new("test").unwrap());
        rule.metadata_mut().tags.push("test".to_string());
        rule
    }

    // Ported from: coraza/internal/corazawaf/rulegroup_test.go::TestRuleGroupDeleteByTag
    #[test]
    fn test_rulegroup_delete_by_tag() {
        let mut group = RuleGroup::new();
        let rule = new_test_rule(1);

        group.add(rule).expect("Failed to add rule");
        assert_eq!(group.count(), 1);

        group.delete_by_tag("test");
        assert_eq!(group.count(), 0);
    }

    // Ported from: coraza/internal/corazawaf/rulegroup_test.go::TestRuleGroupDeleteByMsg
    #[test]
    fn test_rulegroup_delete_by_msg() {
        let mut group = RuleGroup::new();
        let rule = new_test_rule(1);

        group.add(rule).expect("Failed to add rule");
        assert_eq!(group.count(), 1);

        group.delete_by_msg("test");
        assert_eq!(group.count(), 0);
    }

    // Ported from: coraza/internal/corazawaf/rulegroup_test.go::TestRuleGroupDeleteByID
    #[test]
    fn test_rulegroup_delete_by_id() {
        let mut group = RuleGroup::new();

        // Add 5 rules
        for id in 1..=5 {
            group.add(new_test_rule(id)).unwrap();
        }
        assert_eq!(group.count(), 5);

        // Delete rule 1
        group.delete_by_id(1);
        assert_eq!(group.count(), 4);

        // Delete range 2-4
        group.delete_by_range(2, 4);
        assert_eq!(group.count(), 1);
        assert_eq!(group.get_rules()[0].metadata().id, 5);
    }

    #[test]
    fn test_rulegroup_add_duplicate_id() {
        let mut group = RuleGroup::new();

        group.add(new_test_rule(1)).unwrap();

        // Try to add another rule with ID 1
        let result = group.add(new_test_rule(1));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "duplicated rule id 1");
    }

    #[test]
    fn test_rulegroup_find_by_id() {
        let mut group = RuleGroup::new();

        group.add(new_test_rule(1)).unwrap();
        group.add(new_test_rule(2)).unwrap();

        assert!(group.find_by_id(1).is_some());
        assert!(group.find_by_id(2).is_some());
        assert!(group.find_by_id(3).is_none());
    }

    #[test]
    fn test_rulegroup_eval_basic() {
        let mut group = RuleGroup::new();

        // Add a simple rule
        let rule = Rule::new().with_id(1);
        group.add(rule).unwrap();

        let mut tx = Transaction::new("test");
        let disrupted = group.eval(RulePhase::RequestHeaders, &mut tx, true);

        // For now, with simplified implementation, should not be disrupted
        assert!(!disrupted);
    }

    #[test]
    fn test_rulegroup_delete_preserves_order() {
        let mut group = RuleGroup::new();

        for id in 1..=5 {
            group.add(new_test_rule(id)).unwrap();
        }

        group.delete_by_id(3);

        let ids: Vec<i32> = group.get_rules().iter().map(|r| r.metadata().id).collect();
        assert_eq!(ids, vec![1, 2, 4, 5]);
    }

    #[test]
    fn test_rulegroup_delete_by_tag_partial() {
        let mut group = RuleGroup::new();

        let mut rule1 = new_test_rule(1);
        rule1.metadata_mut().tags.push("attack".to_string());
        group.add(rule1).unwrap();

        let rule2 = new_test_rule(2); // Only has "test" tag
        group.add(rule2).unwrap();

        group.delete_by_tag("attack");
        assert_eq!(group.count(), 1);
        assert_eq!(group.get_rules()[0].metadata().id, 2);
    }

    #[test]
    fn test_rulegroup_new_and_default() {
        let group1 = RuleGroup::new();
        let group2 = RuleGroup::default();

        assert_eq!(group1.count(), 0);
        assert_eq!(group2.count(), 0);
    }
}
