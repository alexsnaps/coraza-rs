// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Action execution for rule evaluation.
//!
//! This module handles action execution during rule evaluation. Actions are
//! categorized by type and executed at different points in the rule flow.

use crate::actions::{Action, ActionType, Rule};
use crate::operators::TransactionState;

/// Named action wrapper for rule execution.
///
/// Stores an action along with its name for debugging and logging purposes.
/// Actions are stored as trait objects (`Box<dyn Action>`) because there are
/// 26 different action types with diverse behavior patterns.
///
/// # Why Box<dyn Action>?
///
/// Unlike operators (which use an enum), actions use dynamic dispatch because:
/// - 26 different action types with unique behavior (enum would be unwieldy)
/// - Actions initialized once at rule compile time (not per-request)
/// - Overhead is negligible compared to action execution itself
///
/// # Examples
///
/// ```
/// use coraza::rules::RuleAction;
/// use coraza::actions::{Action, DenyAction, Rule};
///
/// let mut rule = Rule::new();
/// let mut action: Box<dyn Action> = Box::new(DenyAction);
/// action.init(&mut rule, "").unwrap();
///
/// let rule_action = RuleAction::new("deny", action);
/// assert_eq!(rule_action.name(), "deny");
/// ```
pub struct RuleAction {
    /// Action name (e.g., "deny", "log", "setvar")
    name: String,

    /// The action implementation
    action: Box<dyn Action>,
}

impl RuleAction {
    /// Create a new rule action.
    ///
    /// # Arguments
    ///
    /// * `name` - Action name for logging/debugging
    /// * `action` - Initialized action instance
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::rules::RuleAction;
    /// use coraza::actions::DenyAction;
    ///
    /// let rule_action = RuleAction::new("deny", Box::new(DenyAction));
    /// ```
    pub fn new(name: impl Into<String>, action: Box<dyn Action>) -> Self {
        Self {
            name: name.into(),
            action,
        }
    }

    /// Get the action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the action type category.
    pub fn action_type(&self) -> ActionType {
        self.action.action_type()
    }

    /// Evaluate the action during transaction processing.
    ///
    /// # Arguments
    ///
    /// * `rule` - Immutable reference to rule metadata
    /// * `tx` - Mutable reference to transaction state
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::rules::RuleAction;
    /// use coraza::actions::{DenyAction, Rule};
    /// use coraza::transaction::Transaction;
    ///
    /// let rule = Rule::new();
    /// let rule_action = RuleAction::new("deny", Box::new(DenyAction));
    ///
    /// let mut tx = Transaction::new("test");
    /// rule_action.evaluate(&rule, &mut tx);
    /// ```
    pub fn evaluate(&self, rule: &Rule, tx: &mut dyn TransactionState) {
        self.action.evaluate(rule, tx);
    }
}

// Manual Debug impl since Box<dyn Action> doesn't auto-derive
impl std::fmt::Debug for RuleAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleAction")
            .field("name", &self.name)
            .field("action_type", &self.action.action_type())
            .finish()
    }
}

/// Execute actions based on their type and rule engine mode.
///
/// Actions are executed in three phases based on their type:
/// 1. **Nondisruptive**: Executed immediately when rule matches
/// 2. **Flow**: Executed after chain evaluation, always runs
/// 3. **Disruptive**: Executed after chain evaluation, only if rule engine is On
///
/// # Arguments
///
/// * `actions` - Slice of actions to execute
/// * `rule` - Rule metadata
/// * `tx` - Transaction state
/// * `action_filter` - Function to determine which actions to execute
///
/// # Examples
///
/// ```
/// use coraza::rules::execute_actions;
/// use coraza::actions::{ActionType, Rule};
/// use coraza::transaction::Transaction;
///
/// let actions = vec![];
/// let rule = Rule::new();
/// let mut tx = Transaction::new("test");
///
/// // Execute only nondisruptive actions
/// execute_actions(&actions, &rule, &mut tx, |action_type| {
///     action_type == ActionType::Nondisruptive
/// });
/// ```
pub fn execute_actions<F>(
    actions: &[RuleAction],
    rule: &Rule,
    tx: &mut dyn TransactionState,
    action_filter: F,
) where
    F: Fn(ActionType) -> bool,
{
    for action in actions {
        if action_filter(action.action_type()) {
            action.evaluate(rule, tx);
        }
    }
}

/// Execute nondisruptive actions immediately when rule matches.
///
/// Nondisruptive actions perform operations without affecting rule flow,
/// such as logging or variable modification. They execute regardless of
/// SecRuleEngine mode.
///
/// # Arguments
///
/// * `actions` - Slice of rule actions
/// * `rule` - Rule metadata
/// * `tx` - Transaction state
///
/// # Examples
///
/// ```
/// use coraza::rules::execute_nondisruptive_actions;
/// use coraza::actions::Rule;
/// use coraza::transaction::Transaction;
///
/// let actions = vec![];
/// let rule = Rule::new();
/// let mut tx = Transaction::new("test");
///
/// execute_nondisruptive_actions(&actions, &rule, &mut tx);
/// ```
pub fn execute_nondisruptive_actions(
    actions: &[RuleAction],
    rule: &Rule,
    tx: &mut dyn TransactionState,
) {
    execute_actions(actions, rule, tx, |action_type| {
        action_type == ActionType::Nondisruptive
    });
}

/// Execute flow and disruptive actions after chain evaluation.
///
/// Flow actions control rule processing and always execute. Disruptive actions
/// trigger WAF operations (blocking, etc.) and only execute if rule engine is On.
///
/// # Arguments
///
/// * `actions` - Slice of rule actions
/// * `rule` - Rule metadata
/// * `tx` - Transaction state
/// * `rule_engine_on` - Whether the rule engine is in enforcement mode
///
/// # Examples
///
/// ```
/// use coraza::rules::execute_flow_and_disruptive_actions;
/// use coraza::actions::Rule;
/// use coraza::transaction::Transaction;
///
/// let actions = vec![];
/// let rule = Rule::new();
/// let mut tx = Transaction::new("test");
///
/// // Rule engine is on - execute disruptive actions
/// execute_flow_and_disruptive_actions(&actions, &rule, &mut tx, true);
///
/// // Rule engine is detection only - skip disruptive actions
/// execute_flow_and_disruptive_actions(&actions, &rule, &mut tx, false);
/// ```
pub fn execute_flow_and_disruptive_actions(
    actions: &[RuleAction],
    rule: &Rule,
    tx: &mut dyn TransactionState,
    rule_engine_on: bool,
) {
    execute_actions(actions, rule, tx, |action_type| {
        // Flow actions always execute
        if action_type == ActionType::Flow {
            return true;
        }

        // Disruptive actions only execute if rule engine is On
        if action_type == ActionType::Disruptive {
            return rule_engine_on;
        }

        false
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::{DenyAction, LogAction, SkipAction};

    // Helper to create a test action
    fn create_deny_action() -> RuleAction {
        let mut action = Box::new(DenyAction);
        let mut rule = Rule::new();
        action.init(&mut rule, "").unwrap();
        RuleAction::new("deny", action)
    }

    fn create_log_action() -> RuleAction {
        let mut action = Box::new(LogAction);
        let mut rule = Rule::new();
        action.init(&mut rule, "").unwrap();
        RuleAction::new("log", action)
    }

    fn create_skip_action() -> RuleAction {
        let mut action = Box::new(SkipAction::new());
        let mut rule = Rule::new();
        action.init(&mut rule, "1").unwrap();
        RuleAction::new("skip", action)
    }

    // Ported from: coraza/internal/corazawaf/rule.go - ruleActionParams
    #[test]
    fn test_rule_action_creation() {
        let action = create_deny_action();

        assert_eq!(action.name(), "deny");
        assert_eq!(action.action_type(), ActionType::Disruptive);
    }

    #[test]
    fn test_rule_action_types() {
        let deny = create_deny_action();
        let log = create_log_action();
        let skip = create_skip_action();

        assert_eq!(deny.action_type(), ActionType::Disruptive);
        assert_eq!(log.action_type(), ActionType::Nondisruptive);
        assert_eq!(skip.action_type(), ActionType::Flow);
    }

    #[test]
    fn test_execute_actions_filter() {
        let actions = vec![
            create_deny_action(),
            create_log_action(),
            create_skip_action(),
        ];

        let rule = Rule::new();
        let mut tx = crate::transaction::Transaction::new("test");

        // Test that filter works - execute only nondisruptive actions
        execute_actions(&actions, &rule, &mut tx, |action_type| {
            action_type == ActionType::Nondisruptive
        });

        // We can verify the action types are correct
        assert_eq!(actions[0].action_type(), ActionType::Disruptive); // deny
        assert_eq!(actions[1].action_type(), ActionType::Nondisruptive); // log
        assert_eq!(actions[2].action_type(), ActionType::Flow); // skip
    }

    // Ported from: coraza/internal/corazawaf/rule.go::doEvaluate (lines 313-318)
    #[test]
    fn test_execute_nondisruptive_actions() {
        let actions = vec![
            create_deny_action(),
            create_log_action(),
            create_skip_action(),
        ];

        let rule = Rule::new();
        let mut tx = crate::transaction::Transaction::new("test");

        // This should execute only the log action
        execute_nondisruptive_actions(&actions, &rule, &mut tx);

        // We can't easily verify execution without more infrastructure,
        // but we can verify no panic occurred
    }

    // Ported from: coraza/internal/corazawaf/rule.go::doEvaluate (lines 374-383)
    #[test]
    fn test_execute_flow_and_disruptive_with_engine_on() {
        let actions = vec![
            create_deny_action(),
            create_log_action(),
            create_skip_action(),
        ];

        let rule = Rule::new();
        let mut tx = crate::transaction::Transaction::new("test");

        // Rule engine ON - both flow and disruptive should execute
        execute_flow_and_disruptive_actions(&actions, &rule, &mut tx, true);

        // We can't easily verify execution without more infrastructure,
        // but we can verify no panic occurred
    }

    #[test]
    fn test_execute_flow_and_disruptive_with_engine_off() {
        let actions = vec![
            create_deny_action(),
            create_log_action(),
            create_skip_action(),
        ];

        let rule = Rule::new();
        let mut tx = crate::transaction::Transaction::new("test");

        // Rule engine OFF - only flow should execute, not disruptive
        execute_flow_and_disruptive_actions(&actions, &rule, &mut tx, false);

        // We can't easily verify execution without more infrastructure,
        // but we can verify no panic occurred
    }

    #[test]
    fn test_multiple_actions_same_type() {
        let actions = vec![create_log_action(), create_log_action()];

        let rule = Rule::new();
        let mut tx = crate::transaction::Transaction::new("test");

        // Both nondisruptive actions should execute
        execute_nondisruptive_actions(&actions, &rule, &mut tx);
    }

    #[test]
    fn test_empty_actions() {
        let actions = vec![];
        let rule = Rule::new();
        let mut tx = crate::transaction::Transaction::new("test");

        // Should handle empty action list gracefully
        execute_nondisruptive_actions(&actions, &rule, &mut tx);
        execute_flow_and_disruptive_actions(&actions, &rule, &mut tx, true);
    }

    #[test]
    fn test_action_debug() {
        let action = create_deny_action();
        let debug_str = format!("{:?}", action);

        assert!(debug_str.contains("deny"));
        assert!(debug_str.contains("Disruptive"));
    }
}
