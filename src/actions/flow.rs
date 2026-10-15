// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Flow control actions for controlling rule execution.
//!
//! Flow actions control the execution flow of rules, such as chaining rules
//! together or skipping over rules based on conditions.

use crate::actions::{ActionError, RuleMetadata};
use crate::transaction::Transaction;

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
pub(super) fn chain(rule: &mut RuleMetadata, data: &str) -> Result<(), ActionError> {
    if !data.is_empty() {
        return Err(ActionError::UnexpectedArguments);
    }

    rule.has_chain = true;
    Ok(())
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkipAction {
    count: i32,
}

impl SkipAction {
    /// Parses the number of rules to skip (at least 1).
    pub fn parse(data: &str) -> Result<Self, ActionError> {
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

        Ok(Self { count })
    }

    pub fn evaluate(&self, tx: &mut Transaction) {
        tx.set_skip(self.count);
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkipAfterAction {
    marker: String,
}

impl SkipAfterAction {
    /// Parses the label of the `SecMarker` to skip to.
    pub fn parse(data: &str) -> Result<Self, ActionError> {
        let marker = crate::utils::strings::maybe_remove_quotes(data);
        if marker.is_empty() {
            return Err(ActionError::MissingArguments);
        }
        Ok(Self {
            marker: marker.to_string(),
        })
    }

    pub fn evaluate(&self, tx: &mut Transaction) {
        tx.set_skip_after(&self.marker);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ChainAction Tests
    #[test]
    fn test_chain_no_arguments() {
        let mut rule = RuleMetadata::new();
        assert!(chain(&mut rule, "").is_ok());
        assert!(rule.has_chain, "has_chain should be true");
    }

    #[test]
    fn test_chain_unexpected_arguments() {
        let mut rule = RuleMetadata::new();
        assert_eq!(
            chain(&mut rule, "unexpected"),
            Err(ActionError::UnexpectedArguments)
        );
    }

    #[test]
    fn test_skip_no_arguments() {
        assert_eq!(
            SkipAction::parse("").map(|_| ()),
            Err(ActionError::MissingArguments)
        );
    }

    #[test]
    fn test_skip_non_numeric() {
        assert!(matches!(
            SkipAction::parse("abc").map(|_| ()),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_skip_negative() {
        assert!(matches!(
            SkipAction::parse("-10").map(|_| ()),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_skip_zero() {
        assert!(matches!(
            SkipAction::parse("0").map(|_| ()),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_skip_valid() {
        let action = SkipAction::parse("5").unwrap();
        assert_eq!(action.count, 5);
    }

    #[test]
    fn test_skip_evaluate() {
        let action = SkipAction::parse("3").unwrap();

        let mut tx = Transaction::new("action-test");
        action.evaluate(&mut tx);
        assert_eq!(tx.skip(), 3);
    }

    #[test]
    fn test_skipafter_no_arguments() {
        assert_eq!(
            SkipAfterAction::parse("").map(|_| ()),
            Err(ActionError::MissingArguments)
        );
    }

    #[test]
    fn test_skipafter_valid() {
        let action = SkipAfterAction::parse("MARKER_NAME").unwrap();
        assert_eq!(action.marker, "MARKER_NAME");
    }

    #[test]
    fn test_skipafter_with_quotes() {
        let action = SkipAfterAction::parse("'MARKER_NAME'").unwrap();
        assert_eq!(action.marker, "MARKER_NAME");
    }

    #[test]
    fn test_skipafter_evaluate() {
        let action = SkipAfterAction::parse("END_CHECK").unwrap();

        let mut tx = Transaction::new("action-test");
        action.evaluate(&mut tx);
        assert_eq!(tx.skip_after(), "END_CHECK");
    }
}
