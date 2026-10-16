// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Rule group management.
//!
//! This module provides RuleGroup, a WAF's rules in syntactic order. A transaction
//! evaluates them phase by phase.

use crate::rules::Rule;

/// Collection of rules for WAF evaluation.
///
/// A RuleGroup manages a collection of rules and provides methods for:
/// - Adding/removing rules
/// - Finding rules by ID
///
/// RuleGroup is not concurrent-safe and should not be modified after compilation.
#[derive(Debug, Default)]
pub(crate) struct RuleGroup {
    /// Rules in syntactic order
    rules: Vec<Rule>,
}

impl RuleGroup {
    /// Create a new empty rule group.
    pub(crate) fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule to the group.
    ///
    /// If the last rule added has the `chain` action, the new rule is appended to
    /// that rule's chain instead of starting a new top-level rule.
    ///
    /// Returns an error if a rule with the same non-zero ID already exists.
    pub(crate) fn add(&mut self, rule: Rule) -> Result<(), String> {
        // Check for duplicate IDs
        let rule_id = rule.metadata().id;
        if rule_id != 0 && self.find_by_id(rule_id).is_some() {
            return Err(format!("duplicated rule id {}", rule_id));
        }

        match self.open_chain() {
            Some(parent) => parent.chain.push(rule),
            None => self.rules.push(rule),
        }
        Ok(())
    }

    /// Drops the last top-level rule if its chain still expects another rule.
    ///
    /// Used when the rule meant to continue that chain could not be added, so the
    /// incomplete chain doesn't swallow an unrelated rule. Returns whether a rule was dropped.
    pub(crate) fn discard_open_chain(&mut self) -> bool {
        let open = self.open_chain().is_some();
        if open {
            self.rules.pop();
        }
        open
    }

    /// The last top-level rule, if its last link has the `chain` action.
    fn open_chain(&mut self) -> Option<&mut Rule> {
        let parent = self.rules.last_mut()?;
        let tail = parent.chain.last().unwrap_or(parent);
        if tail.metadata().has_chain {
            Some(parent)
        } else {
            None
        }
    }

    /// Find a rule by its ID.
    ///
    /// Returns a reference to the rule if found, None otherwise.
    pub(crate) fn find_by_id(&self, id: i32) -> Option<&Rule> {
        self.rules.iter().find(|r| r.metadata().id == id)
    }

    /// Delete rules by ID range (inclusive).
    pub(crate) fn delete_by_range(&mut self, start: i32, end: i32) {
        self.rules
            .retain(|r| r.metadata().id < start || r.metadata().id > end);
    }

    /// Delete rules by message.
    pub(crate) fn delete_by_msg(&mut self, msg: &str) {
        self.rules
            .retain(|r| r.metadata().msg.as_ref().is_none_or(|m| m.as_str() != msg));
    }

    /// Delete rules by tag.
    pub(crate) fn delete_by_tag(&mut self, tag: &str) {
        self.rules
            .retain(|r| !r.metadata().tags.contains(&tag.to_string()));
    }

    /// Update rules matching a tag with a callback.
    ///
    /// Returns the number of rules updated.
    pub(crate) fn update_by_tag<F>(&mut self, tag: &str, mut update_fn: F) -> usize
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

    /// The top-level rules, in order; chained rules are reached through their parent.
    pub(crate) fn iter_mut(&mut self) -> std::slice::IterMut<'_, Rule> {
        self.rules.iter_mut()
    }

    /// Get all rules in the group.
    pub(crate) fn get_rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Get count of rules in the group.
    pub(crate) fn count(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RulePhase;
    use crate::RuleVariable;
    use crate::rules::VariableSpec;
    use crate::seclang::{compile_sec_action, compile_sec_marker};

    /// A `SecAction` with `id`, `msg:test` and `tag:test`, and `extra` actions.
    fn new_test_rule(id: i32, extra: &str) -> Rule {
        compile_sec_action(&format!(r#""id:{id},msg:test,tag:test{extra}""#)).unwrap()
    }

    // Ported from: coraza/internal/corazawaf/rulegroup_test.go::TestRuleGroupDeleteByTag
    #[test]
    fn test_rulegroup_delete_by_tag() {
        let mut group = RuleGroup::new();
        let rule = new_test_rule(1, "");

        group.add(rule).expect("Failed to add rule");
        assert_eq!(group.count(), 1);

        group.delete_by_tag("test");
        assert_eq!(group.count(), 0);
    }

    // Ported from: coraza/internal/corazawaf/rulegroup_test.go::TestRuleGroupDeleteByMsg
    #[test]
    fn test_rulegroup_delete_by_msg() {
        let mut group = RuleGroup::new();
        let rule = new_test_rule(1, "");

        group.add(rule).expect("Failed to add rule");
        assert_eq!(group.count(), 1);

        group.delete_by_msg("test");
        assert_eq!(group.count(), 0);
    }

    // Ported from: coraza/internal/corazawaf/rulegroup_test.go::TestRuleGroupDeleteByID
    #[test]
    fn test_rulegroup_delete_by_range() {
        let mut group = RuleGroup::new();

        // Add 5 rules
        for id in 1..=5 {
            group.add(new_test_rule(id, "")).unwrap();
        }
        assert_eq!(group.count(), 5);

        // Delete rule 1, as `SecRuleRemoveById 1` does
        group.delete_by_range(1, 1);
        assert_eq!(group.count(), 4);

        // Delete range 2-4
        group.delete_by_range(2, 4);
        assert_eq!(group.count(), 1);
        assert_eq!(group.get_rules()[0].metadata().id, 5);
    }

    #[test]
    fn test_rulegroup_add_duplicate_id() {
        let mut group = RuleGroup::new();

        group.add(new_test_rule(1, "")).unwrap();

        // Try to add another rule with ID 1
        let result = group.add(new_test_rule(1, ""));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "duplicated rule id 1");
    }

    #[test]
    fn test_rulegroup_find_by_id() {
        let mut group = RuleGroup::new();

        group.add(new_test_rule(1, "")).unwrap();
        group.add(new_test_rule(2, "")).unwrap();

        assert!(group.find_by_id(1).is_some());
        assert!(group.find_by_id(2).is_some());
        assert!(group.find_by_id(3).is_none());
    }

    #[test]
    fn test_rulegroup_delete_preserves_order() {
        let mut group = RuleGroup::new();

        for id in 1..=5 {
            group.add(new_test_rule(id, "")).unwrap();
        }

        group.delete_by_range(3, 3);

        let ids: Vec<i32> = group.get_rules().iter().map(|r| r.metadata().id).collect();
        assert_eq!(ids, vec![1, 2, 4, 5]);
    }

    #[test]
    fn test_rulegroup_delete_by_tag_partial() {
        let mut group = RuleGroup::new();

        group.add(new_test_rule(1, ",tag:attack")).unwrap();
        // Only has "test" tag
        group.add(new_test_rule(2, "")).unwrap();

        group.delete_by_tag("attack");
        assert_eq!(group.count(), 1);
        assert_eq!(group.get_rules()[0].metadata().id, 2);
    }

    #[test]
    fn test_rulegroup_update_by_tag() {
        let mut group = RuleGroup::new();
        group.add(new_test_rule(1, ",tag:attack")).unwrap();
        group.add(new_test_rule(2, "")).unwrap();

        let count = group.update_by_tag("attack", |rule| {
            rule.variables_mut()
                .push(VariableSpec::new(RuleVariable::Args));
        });

        assert_eq!(count, 1);
        let variables: Vec<usize> = group
            .iter_mut()
            .map(|rule| rule.variables_mut().len())
            .collect();
        assert_eq!(variables, [1, 0]);
    }

    #[test]
    fn test_rulegroup_new_and_default() {
        let group1 = RuleGroup::new();
        let group2 = RuleGroup::default();

        assert_eq!(group1.count(), 0);
        assert_eq!(group2.count(), 0);
    }

    #[test]
    fn test_rule_phase_method() {
        let rule = new_test_rule(1, ",phase:2");

        assert_eq!(rule.phase(), RulePhase::RequestBody);
    }

    #[test]
    fn test_rule_is_sec_marker() {
        let rule1 = compile_sec_marker("MARKER1").unwrap();
        // No marker
        let rule2 = new_test_rule(2, "");

        assert!(rule1.is_sec_marker("MARKER1"));
        assert!(!rule1.is_sec_marker("MARKER2"));
        assert!(!rule2.is_sec_marker("MARKER1"));
    }
}
