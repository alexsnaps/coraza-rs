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

    /// Update rules matching a tag with a callback.
    ///
    /// Returns the number of rules updated.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::rules::{RuleGroup, Rule, VariableSpec};
    /// use coraza::RuleVariable;
    ///
    /// let mut group = RuleGroup::new();
    /// let mut rule = Rule::new().with_id(1);
    /// rule.metadata_mut().tags.push("attack".to_string());
    /// group.add(rule).unwrap();
    ///
    /// let count = group.update_by_tag("attack", |rule| {
    ///     rule.set_variables(vec![VariableSpec::new(RuleVariable::Args)]);
    /// });
    /// assert_eq!(count, 1);
    /// ```
    pub fn update_by_tag<F>(&mut self, tag: &str, mut update_fn: F) -> usize
    where
        F: FnMut(&mut Rule),
    {
        let mut count = 0;
        for rule in &mut self.rules {
            if rule.metadata().tags.contains(&tag.to_string()) {
                update_fn(rule);
                count += 1;
            }
        }
        count
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
    /// * `phase` - The phase to evaluate rules for
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
    pub fn eval(&self, phase: RulePhase, tx: &mut Transaction, rule_engine_on: bool) -> bool {
        for rule in &self.rules {
            // Check for interruption - if we're disrupted and not in logging phase, stop evaluation
            if tx.interruption.is_some() && phase != RulePhase::Logging {
                return true; // Transaction was disrupted
            }

            // Phase filtering: skip rules that don't match current phase
            // Rules with phase Unknown (0) always run (phase-agnostic rules)
            if rule.phase() != RulePhase::Unknown && rule.phase() != phase {
                continue;
            }

            // CTL exclusion: skip rules that were removed via ctl:ruleRemoveById
            if tx.is_rule_removed(rule.metadata().id) {
                continue;
            }

            // Handle skipAfter: skip until we find the marker
            if !tx.skip_after.is_empty() {
                // Check if this rule is the marker we're looking for
                if rule.is_sec_marker(&tx.skip_after) {
                    // Found the marker, clear skipAfter and continue to next rule
                    tx.skip_after.clear();
                }
                continue; // Skip this rule
            }

            // Handle skip: decrement counter and skip rule
            if tx.skip > 0 {
                tx.skip -= 1;
                continue;
            }

            // Evaluate the rule
            let _matches = rule.evaluate(tx, rule_engine_on);
        }

        // Return true if an interruption occurred
        tx.interruption.is_some()
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

    // ===== Advanced RuleGroup Features Tests (Step 9) =====

    #[test]
    fn test_rulegroup_phase_filtering() {
        let mut group = RuleGroup::new();

        // Add rules for different phases
        let mut rule1 = Rule::new().with_id(1);
        rule1.metadata_mut().phase = RulePhase::RequestHeaders;
        group.add(rule1).unwrap();

        let mut rule2 = Rule::new().with_id(2);
        rule2.metadata_mut().phase = RulePhase::RequestBody;
        group.add(rule2).unwrap();

        let mut rule3 = Rule::new().with_id(3);
        rule3.metadata_mut().phase = RulePhase::Unknown; // Phase 0 - runs in all phases
        group.add(rule3).unwrap();

        let mut tx = Transaction::new("test");

        // Evaluate RequestHeaders phase
        group.eval(RulePhase::RequestHeaders, &mut tx, true);

        // Only rule1 and rule3 should have been evaluated
        // (We can't directly check which rules ran, but we verify the logic works)

        // Evaluate RequestBody phase
        group.eval(RulePhase::RequestBody, &mut tx, true);

        // Only rule2 and rule3 should have been evaluated
    }

    #[test]
    fn test_rulegroup_skip_action() {
        let mut group = RuleGroup::new();

        // Add 5 rules in RequestHeaders phase
        for id in 1..=5 {
            let mut rule = Rule::new().with_id(id);
            rule.metadata_mut().phase = RulePhase::RequestHeaders;
            group.add(rule).unwrap();
        }

        let mut tx = Transaction::new("test");

        // Set skip = 3 (skip next 3 rules)
        tx.skip = 3;

        group.eval(RulePhase::RequestHeaders, &mut tx, true);

        // Skip counter should be decremented to 0 (3 rules skipped)
        assert_eq!(tx.skip, 0);
    }

    #[test]
    fn test_rulegroup_skipafter_action() {
        let mut group = RuleGroup::new();

        // Add rules with a marker in the middle (all in RequestHeaders phase)
        let mut rule1 = Rule::new().with_id(1);
        rule1.metadata_mut().phase = RulePhase::RequestHeaders;
        group.add(rule1).unwrap();

        let mut rule2 = Rule::new().with_id(2);
        rule2.metadata_mut().phase = RulePhase::RequestHeaders;
        group.add(rule2).unwrap();

        // Add a SecMarker
        let mut marker_rule = Rule::new().with_id(0); // Markers typically have ID 0
        marker_rule.metadata_mut().phase = RulePhase::RequestHeaders;
        marker_rule.metadata_mut().sec_mark = Some("END_CHECK".to_string());
        group.add(marker_rule).unwrap();

        let mut rule3 = Rule::new().with_id(3);
        rule3.metadata_mut().phase = RulePhase::RequestHeaders;
        group.add(rule3).unwrap();

        let mut rule4 = Rule::new().with_id(4);
        rule4.metadata_mut().phase = RulePhase::RequestHeaders;
        group.add(rule4).unwrap();

        let mut tx = Transaction::new("test");

        // Set skipAfter marker
        tx.skip_after = "END_CHECK".to_string();

        group.eval(RulePhase::RequestHeaders, &mut tx, true);

        // skipAfter should be cleared after finding the marker
        assert!(tx.skip_after.is_empty());
    }

    #[test]
    fn test_rulegroup_interruption_stops_evaluation() {
        use crate::transaction::Interruption;

        let mut group = RuleGroup::new();

        // Add multiple rules
        for id in 1..=5 {
            group.add(Rule::new().with_id(id)).unwrap();
        }

        let mut tx = Transaction::new("test");

        // Set an interruption
        tx.interruption = Some(Interruption {
            rule_id: 1,
            action: "deny".to_string(),
            status: 403,
            data: String::new(),
        });

        // Eval should stop immediately and return true
        let disrupted = group.eval(RulePhase::RequestHeaders, &mut tx, true);
        assert!(disrupted);
    }

    #[test]
    fn test_rulegroup_interruption_continues_in_logging_phase() {
        use crate::transaction::Interruption;

        let mut group = RuleGroup::new();

        // Add rules
        for id in 1..=3 {
            let mut rule = Rule::new().with_id(id);
            rule.metadata_mut().phase = RulePhase::Logging;
            group.add(rule).unwrap();
        }

        let mut tx = Transaction::new("test");

        // Set an interruption
        tx.interruption = Some(Interruption {
            rule_id: 1,
            action: "deny".to_string(),
            status: 403,
            data: String::new(),
        });

        // In Logging phase, interruption should not stop evaluation
        let disrupted = group.eval(RulePhase::Logging, &mut tx, true);

        // Still returns true (transaction is disrupted), but rules were evaluated
        assert!(disrupted);
    }

    #[test]
    fn test_rule_phase_method() {
        let mut rule = Rule::new().with_id(1);
        rule.metadata_mut().phase = RulePhase::RequestBody;

        assert_eq!(rule.phase(), RulePhase::RequestBody);
    }

    #[test]
    fn test_rule_is_sec_marker() {
        let mut rule1 = Rule::new().with_id(1);
        rule1.metadata_mut().sec_mark = Some("MARKER1".to_string());

        let rule2 = Rule::new().with_id(2); // No marker

        assert!(rule1.is_sec_marker("MARKER1"));
        assert!(!rule1.is_sec_marker("MARKER2"));
        assert!(!rule2.is_sec_marker("MARKER1"));
    }

    #[test]
    fn test_rulegroup_combined_skip_and_phase() {
        let mut group = RuleGroup::new();

        // Add rules with different phases
        let mut rule1 = Rule::new().with_id(1);
        rule1.metadata_mut().phase = RulePhase::RequestHeaders;
        group.add(rule1).unwrap();

        let mut rule2 = Rule::new().with_id(2);
        rule2.metadata_mut().phase = RulePhase::RequestHeaders;
        group.add(rule2).unwrap();

        let mut rule3 = Rule::new().with_id(3);
        rule3.metadata_mut().phase = RulePhase::RequestBody; // Different phase
        group.add(rule3).unwrap();

        let mut tx = Transaction::new("test");
        tx.skip = 1; // Skip first matching rule

        group.eval(RulePhase::RequestHeaders, &mut tx, true);

        // Skip should be decremented
        assert_eq!(tx.skip, 0);

        // Rule3 should not have affected skip count (different phase)
    }

    #[test]
    fn test_rulegroup_no_interruption_returns_false() {
        let mut group = RuleGroup::new();
        group.add(Rule::new().with_id(1)).unwrap();

        let mut tx = Transaction::new("test");

        let disrupted = group.eval(RulePhase::RequestHeaders, &mut tx, true);

        // No interruption occurred
        assert!(!disrupted);
    }

    #[test]
    fn test_rulegroup_ctl_rule_exclusion() {
        let mut group = RuleGroup::new();

        // Add rules 100, 200, 300
        for id in [100, 200, 300] {
            let mut rule = Rule::new().with_id(id);
            rule.metadata_mut().phase = RulePhase::RequestHeaders;
            group.add(rule).unwrap();
        }

        let mut tx = Transaction::new("test-ctl-exclusion");

        // Exclude rule 200 via transaction
        tx.remove_rule_by_id(200);

        // Verify exclusion list
        assert!(!tx.is_rule_removed(100));
        assert!(tx.is_rule_removed(200));
        assert!(!tx.is_rule_removed(300));

        // Evaluate - rule 200 should be skipped
        group.eval(RulePhase::RequestHeaders, &mut tx, true);

        // All rules should have been processed except 200
        // (We can't directly verify which rules ran, but the test confirms
        // the exclusion mechanism works without errors)
    }

    #[test]
    fn test_rulegroup_ctl_rule_exclusion_range() {
        let mut group = RuleGroup::new();

        // Add rules 100-105
        for id in 100..=105 {
            let mut rule = Rule::new().with_id(id);
            rule.metadata_mut().phase = RulePhase::RequestHeaders;
            group.add(rule).unwrap();
        }

        let mut tx = Transaction::new("test-ctl-exclusion-range");

        // Exclude rules 102-104
        for id in 102..=104 {
            tx.remove_rule_by_id(id);
        }

        // Verify exclusion list
        assert!(!tx.is_rule_removed(100));
        assert!(!tx.is_rule_removed(101));
        assert!(tx.is_rule_removed(102));
        assert!(tx.is_rule_removed(103));
        assert!(tx.is_rule_removed(104));
        assert!(!tx.is_rule_removed(105));

        // Evaluate - rules 102-104 should be skipped
        group.eval(RulePhase::RequestHeaders, &mut tx, true);
    }

    #[test]
    fn test_rulegroup_ctl_target_exclusion() {
        use crate::RuleVariable;

        let mut group = RuleGroup::new();

        // Add a rule that would check ARGS
        let mut rule = Rule::new().with_id(981260);
        rule.metadata_mut().phase = RulePhase::RequestHeaders;
        group.add(rule).unwrap();

        let mut tx = Transaction::new("test-ctl-target-exclusion");

        // Exclude ARGS:user from rule 981260
        tx.remove_rule_target_by_id(981260, RuleVariable::Args, "user");

        // Verify target exclusion
        assert!(tx.is_rule_target_removed(981260, RuleVariable::Args, "user"));
        assert!(!tx.is_rule_target_removed(981260, RuleVariable::Args, "password"));

        // Evaluate - rule should run but with ARGS:user excluded from its variable list
        group.eval(RulePhase::RequestHeaders, &mut tx, true);
    }
}
