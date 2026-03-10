// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Special actions for advanced rule processing.
//!
//! These actions provide specialized functionality for variable capturing,
//! transformation pipelines, and HTTP status code configuration.

use crate::actions::{Action, ActionError, ActionType, Rule, TransactionState};

/// `capture` action - Enables regex capturing.
///
/// When used with the `@rx` operator, captures regex groups into TX variables.
/// Up to 10 captures (TX.0 through TX.9) are created on successful pattern match.
/// TX.0 always contains the entire matched area; TX.1-TX.9 contain captured groups.
///
/// **Note:** This action is currently forced by the implementation and may be
/// made optional in the future.
///
/// # Arguments
///
/// No arguments accepted
///
/// # Examples
///
/// ```text
/// # Capture username and validate length
/// SecRule REQUEST_BODY "^username=(\w{25,})" "phase:2,capture,t:none,chain,id:105"
///     SecRule TX:1 "(?:(?:a(dmin|nonymous)))"
/// ```
#[derive(Debug)]
pub struct CaptureAction;

impl Action for CaptureAction {
    fn init(&mut self, rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if !data.is_empty() {
            return Err(ActionError::UnexpectedArguments);
        }

        rule.capture = true;
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // Capture is a metadata action - doesn't execute at runtime
    }

    fn action_type(&self) -> ActionType {
        ActionType::Nondisruptive
    }
}

/// `multimatch` action - Perform multiple operator invocations.
///
/// Normally, variables are inspected only once per rule, after all transformations
/// have been applied. With `multimatch`, variables are checked before and after
/// **every** transformation function that changes the input.
///
/// This allows detection of attacks that might be hidden by transformations.
///
/// # Arguments
///
/// No arguments accepted
///
/// # Examples
///
/// ```text
/// # Check for "attack" before and after each transformation
/// SecRule ARGS "attack" "phase:1,log,deny,id:119,t:removeNulls,t:lowercase,multimatch"
/// ```
#[derive(Debug)]
pub struct MultimatchAction;

impl Action for MultimatchAction {
    fn init(&mut self, rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if !data.is_empty() {
            return Err(ActionError::UnexpectedArguments);
        }

        rule.multi_match = true;
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // Multimatch is a metadata action - doesn't execute at runtime
    }

    fn action_type(&self) -> ActionType {
        ActionType::Nondisruptive
    }
}

/// `status` action - Sets HTTP status code for blocking.
///
/// Specifies the response status code to use with `deny` and `redirect` actions.
/// If not set, `deny` defaults to status 403.
///
/// # Arguments
///
/// HTTP status code (numeric, typically 200-599)
///
/// # Examples
///
/// ```text
/// # Deny with custom status code
/// SecDefaultAction "phase:1,log,deny,id:145,status:403"
///
/// # Redirect with 301 (permanent)
/// SecRule ARGS:old_param ".*" "redirect:http://new.example.com,status:301,id:146"
/// ```
#[derive(Debug)]
pub struct StatusAction;

impl Action for StatusAction {
    fn init(&mut self, rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if data.is_empty() {
            return Err(ActionError::MissingArguments);
        }

        let status = data
            .parse::<i32>()
            .map_err(|e| ActionError::InvalidArguments(format!("invalid status code: {}", e)))?;

        // TODO: Validate status code range (200-599)?
        // For now, accept any valid integer like Go implementation
        rule.status = status;
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // Status is a data action - doesn't execute at runtime
    }

    fn action_type(&self) -> ActionType {
        ActionType::Data
    }
}

/// `t` action - Apply transformations to rule variables.
///
/// Specifies the transformation pipeline to use before matching. Transformations
/// are applied in the order specified. Using `t:none` clears all previous
/// transformations (useful to avoid inheriting from SecDefaultAction).
///
/// # Arguments
///
/// - `none` - Clear all transformations
/// - `<transformation_name>` - Add a transformation to the pipeline
///
/// # Examples
///
/// ```text
/// # Clear defaults and apply specific transformations
/// SecRule ARGS "(asfunction|javascript|vbscript)" \
///   "id:146,t:none,t:htmlEntityDecode,t:lowercase,t:removeNulls,t:removeWhitespace"
///
/// # Add to default transformations
/// SecRule REQUEST_URI "@rx attack" "id:147,t:urlDecode"
/// ```
#[derive(Debug)]
pub struct TAction;

impl Action for TAction {
    fn init(&mut self, rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if data.is_empty() {
            return Err(ActionError::MissingArguments);
        }

        // Special case: "none" clears all transformations
        if data == "none" {
            rule.transformations.clear();
            return Ok(());
        }

        // TODO: Validate transformation exists when we implement transformation registry
        // For now, just store the name - validation will happen at rule execution time
        rule.transformations.push(data.to_string());
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // Transformation is a metadata action - doesn't execute at runtime
    }

    fn action_type(&self) -> ActionType {
        ActionType::Nondisruptive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CaptureAction Tests
    #[test]
    fn test_capture_no_arguments() {
        let mut rule = Rule::new();
        let mut action = CaptureAction;
        assert!(action.init(&mut rule, "").is_ok());
        assert!(rule.capture, "capture should be enabled");
    }

    #[test]
    fn test_capture_unexpected_arguments() {
        let mut rule = Rule::new();
        let mut action = CaptureAction;
        assert_eq!(
            action.init(&mut rule, "abc"),
            Err(ActionError::UnexpectedArguments)
        );
    }

    #[test]
    fn test_capture_action_type() {
        assert_eq!(CaptureAction.action_type(), ActionType::Nondisruptive);
    }

    // MultimatchAction Tests
    #[test]
    fn test_multimatch_no_arguments() {
        let mut rule = Rule::new();
        let mut action = MultimatchAction;
        assert!(action.init(&mut rule, "").is_ok());
        assert!(rule.multi_match, "multi_match should be enabled");
    }

    #[test]
    fn test_multimatch_unexpected_arguments() {
        let mut rule = Rule::new();
        let mut action = MultimatchAction;
        assert_eq!(
            action.init(&mut rule, "abc"),
            Err(ActionError::UnexpectedArguments)
        );
    }

    #[test]
    fn test_multimatch_action_type() {
        assert_eq!(MultimatchAction.action_type(), ActionType::Nondisruptive);
    }

    // StatusAction Tests
    #[test]
    fn test_status_no_arguments() {
        let mut action = StatusAction;
        assert_eq!(
            action.init(&mut Rule::new(), ""),
            Err(ActionError::MissingArguments)
        );
    }

    #[test]
    fn test_status_non_numeric() {
        let mut action = StatusAction;
        assert!(matches!(
            action.init(&mut Rule::new(), "abc"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_status_valid() {
        let mut rule = Rule::new();
        let mut action = StatusAction;
        assert!(action.init(&mut rule, "403").is_ok());
        assert_eq!(rule.status, 403);
    }

    #[test]
    fn test_status_various_codes() {
        for status_code in &[200, 301, 302, 403, 404, 500, 503] {
            let mut rule = Rule::new();
            let mut action = StatusAction;
            assert!(action.init(&mut rule, &status_code.to_string()).is_ok());
            assert_eq!(rule.status, *status_code);
        }
    }

    #[test]
    fn test_status_action_type() {
        assert_eq!(StatusAction.action_type(), ActionType::Data);
    }

    // TAction Tests
    #[test]
    fn test_t_no_arguments() {
        let mut action = TAction;
        assert_eq!(
            action.init(&mut Rule::new(), ""),
            Err(ActionError::MissingArguments)
        );
    }

    #[test]
    fn test_t_none_clears_transformations() {
        let mut rule = Rule::new();

        // Add some transformations first
        rule.transformations.push("lowercase".to_string());
        rule.transformations.push("uppercase".to_string());
        assert_eq!(rule.transformations.len(), 2);

        // Apply t:none
        let mut action = TAction;
        assert!(action.init(&mut rule, "none").is_ok());
        assert_eq!(
            rule.transformations.len(),
            0,
            "transformations should be cleared"
        );
    }

    #[test]
    fn test_t_adds_transformation() {
        let mut rule = Rule::new();
        let mut action = TAction;
        assert!(action.init(&mut rule, "lowercase").is_ok());
        assert_eq!(rule.transformations.len(), 1);
        assert_eq!(rule.transformations[0], "lowercase");
    }

    #[test]
    fn test_t_multiple_transformations() {
        let mut rule = Rule::new();

        let mut action1 = TAction;
        assert!(action1.init(&mut rule, "lowercase").is_ok());

        let mut action2 = TAction;
        assert!(action2.init(&mut rule, "urlDecode").is_ok());

        assert_eq!(rule.transformations.len(), 2);
        assert_eq!(rule.transformations[0], "lowercase");
        assert_eq!(rule.transformations[1], "urlDecode");
    }

    #[test]
    fn test_t_unknown_transformation() {
        // TODO: Add validation when transformation registry is implemented
        // For now, we accept any transformation name
        let mut rule = Rule::new();
        let mut action = TAction;
        assert!(action.init(&mut rule, "unknownTransformation").is_ok());
        assert_eq!(rule.transformations.len(), 1);
        assert_eq!(rule.transformations[0], "unknownTransformation");
    }

    #[test]
    fn test_t_action_type() {
        assert_eq!(TAction.action_type(), ActionType::Nondisruptive);
    }
}
