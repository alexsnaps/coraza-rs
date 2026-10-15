// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Action execution for rule evaluation.
//!
//! Actions run at different points in the rule flow depending on their
//! [`ActionType`]; see [`crate::rules::Rule::evaluate`].

use crate::actions::{Action, ActionType, RuleMetadata};
use crate::transaction::Transaction;

/// Runs, in order, the actions whose type `action_filter` accepts.
///
/// # Examples
///
/// ```
/// use coraza::rules::execute_actions;
/// use coraza::actions::{ActionType, RuleMetadata};
/// use coraza::transaction::Transaction;
///
/// let actions = vec![];
/// let rule = RuleMetadata::new();
/// let mut tx = Transaction::new("test");
///
/// // Execute only nondisruptive actions
/// execute_actions(&actions, &rule, &mut tx, |action_type| {
///     action_type == ActionType::Nondisruptive
/// });
/// ```
pub fn execute_actions<F>(
    actions: &[Action],
    rule: &RuleMetadata,
    tx: &mut Transaction,
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

/// Runs the non-disruptive actions, as done for each value a rule matches.
pub fn execute_nondisruptive_actions(
    actions: &[Action],
    rule: &RuleMetadata,
    tx: &mut Transaction,
) {
    execute_actions(actions, rule, tx, |action_type| {
        action_type == ActionType::Nondisruptive
    });
}

/// Runs the flow actions, and the disruptive ones if `rule_engine_on`, as done once a
/// rule's whole chain matched.
pub fn execute_flow_and_disruptive_actions(
    actions: &[Action],
    rule: &RuleMetadata,
    tx: &mut Transaction,
    rule_engine_on: bool,
) {
    execute_actions(actions, rule, tx, |action_type| match action_type {
        ActionType::Flow => true,
        ActionType::Disruptive => rule_engine_on,
        ActionType::Nondisruptive => false,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuleVariable;

    fn actions() -> Vec<Action> {
        let mut rule = RuleMetadata::new();
        ["deny", "setvar:tx.hit=1", "skip:2"]
            .into_iter()
            .map(|spec| {
                let (name, argument) = spec.split_once(':').unwrap_or((spec, ""));
                Action::parse(name, argument, &mut rule).unwrap().unwrap()
            })
            .collect()
    }

    fn rule() -> RuleMetadata {
        let mut rule = RuleMetadata::new();
        rule.id = 1;
        rule
    }

    #[test]
    fn test_execute_nondisruptive_actions_runs_only_those() {
        let mut tx = Transaction::new("test");
        execute_nondisruptive_actions(&actions(), &rule(), &mut tx);

        assert_eq!(
            tx.get_variable(RuleVariable::TX, Some("hit")).as_deref(),
            Some("1")
        );
        assert_eq!(tx.skip(), 0);
        assert!(tx.interruption().is_none());
    }

    #[test]
    fn test_execute_flow_and_disruptive_with_engine_on() {
        let mut tx = Transaction::new("test");
        execute_flow_and_disruptive_actions(&actions(), &rule(), &mut tx, true);

        assert_eq!(tx.skip(), 2);
        assert_eq!(tx.interruption().map(|i| i.action.as_str()), Some("deny"));
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("hit")), None);
    }

    #[test]
    fn test_execute_flow_and_disruptive_with_engine_off() {
        let mut tx = Transaction::new("test");
        execute_flow_and_disruptive_actions(&actions(), &rule(), &mut tx, false);

        assert_eq!(tx.skip(), 2);
        assert!(tx.interruption().is_none());
    }

    #[test]
    fn test_empty_actions() {
        let mut tx = Transaction::new("test");
        execute_nondisruptive_actions(&[], &rule(), &mut tx);
        execute_flow_and_disruptive_actions(&[], &rule(), &mut tx, true);
        assert!(tx.interruption().is_none());
    }
}
