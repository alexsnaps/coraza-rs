// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Flow control actions for controlling rule execution.
//!
//! Flow actions control the execution flow of rules, such as chaining rules
//! together or skipping over rules based on conditions.

use crate::actions::{Action, ActionError, ActionType, Rule, TransactionState};

/// `chain` action - Links rules together in an AND condition.
///
/// Creates a rule chain where the current rule is chained with the rule that
/// immediately follows it. Rule chains simulate AND conditions - the disruptive
/// actions in the first rule will trigger only if ALL chained rules match.
///
/// ## Chain Rules
///
/// These actions can ONLY be specified in the chain starter (first rule):
/// - Disruptive actions (deny, drop, redirect, etc.)
/// - Execution phases
/// - Metadata actions (id, rev, msg, tag, severity, logdata)
/// - skip, skipAfter
///
/// Non-disruptive actions can be used in any chained rule and execute when
/// that specific rule matches.
///
/// # Arguments
///
/// No arguments accepted
///
/// # Examples
///
/// ```text
/// # Refuse POST requests without Content-Length header
/// SecRule REQUEST_METHOD "^POST$" "phase:1,chain,t:none,id:105"
///     SecRule &REQUEST_HEADERS:Content-Length "@eq 0" "t:none"
/// ```
#[derive(Debug)]
pub struct ChainAction;

impl Action for ChainAction {
    fn init(&mut self, rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if !data.is_empty() {
            return Err(ActionError::UnexpectedArguments);
        }

        rule.has_chain = true;
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // Chain is a metadata action - doesn't execute at runtime
    }

    fn action_type(&self) -> ActionType {
        ActionType::Flow
    }
}

/// `skip` action - Skips over the next N rules on match.
///
/// Skips one or more rules (or chained rules) when the rule matches successfully.
/// Skip only works within the current processing phase, not across phases.
///
/// If you place a phase 2 rule after a phase 1 rule that uses skip, it will NOT
/// skip the phase 2 rule - it will skip the next phase 1 rule in that phase.
///
/// # Arguments
///
/// Number of rules to skip (must be >= 1)
///
/// # Examples
///
/// ```text
/// # Require Accept header, but not from localhost
/// SecRule REMOTE_ADDR "^127\.0\.0\.1$" "phase:1,skip:1,id:141"
///
/// # This rule is skipped when REMOTE_ADDR is 127.0.0.1
/// SecRule &REQUEST_HEADERS:Accept "@eq 0" "phase:1,id:142,deny,msg:'Missing Accept Header'"
/// ```
#[derive(Debug)]
pub struct SkipAction {
    count: i32,
}

impl SkipAction {
    pub fn new() -> Self {
        Self { count: 0 }
    }
}

impl Default for SkipAction {
    fn default() -> Self {
        Self::new()
    }
}

impl Action for SkipAction {
    fn init(&mut self, _rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if data.is_empty() {
            return Err(ActionError::MissingArguments);
        }

        let count = data
            .parse::<i32>()
            .map_err(|e| ActionError::InvalidArguments(format!("invalid skip count: {}", e)))?;

        if count < 1 {
            return Err(ActionError::InvalidArguments(format!(
                "invalid argument, {} must be greater than or equal to 1",
                count
            )));
        }

        self.count = count;
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, tx: &mut dyn TransactionState) {
        tx.set_skip(self.count);
    }

    fn action_type(&self) -> ActionType {
        ActionType::Flow
    }
}

/// `skipAfter` action - Skips rules until a specific marker.
///
/// Similar to `skip`, but instead of skipping a fixed number of rules,
/// it skips until reaching a rule or SecMarker with the specified ID.
/// Rule execution resumes with the first rule after the marker.
///
/// Like `skip`, this only works within the current processing phase.
///
/// # Arguments
///
/// Marker ID to skip to (required)
///
/// # Examples
///
/// ```text
/// # Require Accept header, but not from localhost
/// SecRule REMOTE_ADDR "^127\.0\.0\.1$" "phase:1,id:143,skipAfter:IGNORE_LOCALHOST"
///
/// # This rule is skipped when REMOTE_ADDR is 127.0.0.1
/// SecRule &REQUEST_HEADERS:Accept "@eq 0" "phase:1,deny,id:144,msg:'Missing Accept'"
/// SecMarker IGNORE_LOCALHOST
///
/// # Execution resumes here for localhost
/// ```
#[derive(Debug)]
pub struct SkipAfterAction {
    marker: String,
}

impl SkipAfterAction {
    pub fn new() -> Self {
        Self {
            marker: String::new(),
        }
    }
}

impl Default for SkipAfterAction {
    fn default() -> Self {
        Self::new()
    }
}

impl Action for SkipAfterAction {
    fn init(&mut self, _rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        let marker = crate::utils::strings::maybe_remove_quotes(data);
        if marker.is_empty() {
            return Err(ActionError::MissingArguments);
        }

        self.marker = marker.to_string();
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, tx: &mut dyn TransactionState) {
        tx.set_skip_after(&self.marker);
    }

    fn action_type(&self) -> ActionType {
        ActionType::Flow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock TransactionState for testing
    struct MockTransaction {
        skip: i32,
        skip_after: String,
    }

    impl MockTransaction {
        fn new() -> Self {
            Self {
                skip: 0,
                skip_after: String::new(),
            }
        }
    }

    impl TransactionState for MockTransaction {
        fn get_variable(
            &self,
            _variable: crate::RuleVariable,
            _key: Option<&str>,
        ) -> Option<String> {
            None
        }

        fn set_skip(&mut self, count: i32) {
            self.skip = count;
        }

        fn set_skip_after(&mut self, marker: &str) {
            self.skip_after = marker.to_string();
        }
    }

    // ChainAction Tests
    #[test]
    fn test_chain_no_arguments() {
        let mut rule = Rule::new();
        let mut action = ChainAction;
        assert!(action.init(&mut rule, "").is_ok());
        assert!(rule.has_chain, "has_chain should be true");
    }

    #[test]
    fn test_chain_unexpected_arguments() {
        let mut rule = Rule::new();
        let mut action = ChainAction;
        assert_eq!(
            action.init(&mut rule, "unexpected"),
            Err(ActionError::UnexpectedArguments)
        );
    }

    #[test]
    fn test_chain_action_type() {
        assert_eq!(ChainAction.action_type(), ActionType::Flow);
    }

    // SkipAction Tests
    #[test]
    fn test_skip_no_arguments() {
        let mut action = SkipAction::new();
        assert_eq!(
            action.init(&mut Rule::new(), ""),
            Err(ActionError::MissingArguments)
        );
    }

    #[test]
    fn test_skip_non_numeric() {
        let mut action = SkipAction::new();
        assert!(matches!(
            action.init(&mut Rule::new(), "abc"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_skip_negative() {
        let mut action = SkipAction::new();
        assert!(matches!(
            action.init(&mut Rule::new(), "-10"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_skip_zero() {
        let mut action = SkipAction::new();
        assert!(matches!(
            action.init(&mut Rule::new(), "0"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_skip_valid() {
        let mut action = SkipAction::new();
        assert!(action.init(&mut Rule::new(), "5").is_ok());
        assert_eq!(action.count, 5);
    }

    #[test]
    fn test_skip_evaluate() {
        let mut action = SkipAction::new();
        action.init(&mut Rule::new(), "3").unwrap();

        let mut tx = MockTransaction::new();
        action.evaluate(&Rule::new(), &mut tx);
        assert_eq!(tx.skip, 3);
    }

    #[test]
    fn test_skip_action_type() {
        assert_eq!(SkipAction::new().action_type(), ActionType::Flow);
    }

    // SkipAfterAction Tests
    #[test]
    fn test_skipafter_no_arguments() {
        let mut action = SkipAfterAction::new();
        assert_eq!(
            action.init(&mut Rule::new(), ""),
            Err(ActionError::MissingArguments)
        );
    }

    #[test]
    fn test_skipafter_valid() {
        let mut action = SkipAfterAction::new();
        assert!(action.init(&mut Rule::new(), "MARKER_NAME").is_ok());
        assert_eq!(action.marker, "MARKER_NAME");
    }

    #[test]
    fn test_skipafter_with_quotes() {
        let mut action = SkipAfterAction::new();
        assert!(action.init(&mut Rule::new(), "'MARKER_NAME'").is_ok());
        assert_eq!(action.marker, "MARKER_NAME");
    }

    #[test]
    fn test_skipafter_evaluate() {
        let mut action = SkipAfterAction::new();
        action.init(&mut Rule::new(), "END_CHECK").unwrap();

        let mut tx = MockTransaction::new();
        action.evaluate(&Rule::new(), &mut tx);
        assert_eq!(tx.skip_after, "END_CHECK");
    }

    #[test]
    fn test_skipafter_action_type() {
        assert_eq!(SkipAfterAction::new().action_type(), ActionType::Flow);
    }
}
