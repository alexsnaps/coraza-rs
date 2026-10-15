// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Special actions for advanced rule processing.
//!
//! These actions provide specialized functionality for variable capturing,
//! transformation pipelines, and HTTP status code configuration.

use crate::actions::{ActionError, RuleMetadata};
use crate::transformations;

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
pub(super) fn capture(rule: &mut RuleMetadata, data: &str) -> Result<(), ActionError> {
    if !data.is_empty() {
        return Err(ActionError::UnexpectedArguments);
    }

    rule.capture = true;
    Ok(())
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
pub(super) fn multimatch(rule: &mut RuleMetadata, data: &str) -> Result<(), ActionError> {
    if !data.is_empty() {
        return Err(ActionError::UnexpectedArguments);
    }

    rule.multi_match = true;
    Ok(())
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
pub(super) fn status(rule: &mut RuleMetadata, data: &str) -> Result<(), ActionError> {
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
pub(super) fn t(rule: &mut RuleMetadata, data: &str) -> Result<(), ActionError> {
    if data.is_empty() {
        return Err(ActionError::MissingArguments);
    }

    // `t:none` drops the transformations listed before it (including defaults)
    if data.eq_ignore_ascii_case("none") {
        rule.transformations.clear();
        return Ok(());
    }

    let function = transformations::by_name(data).ok_or_else(|| {
        ActionError::InvalidArguments(format!("unknown transformation: {}", data))
    })?;
    rule.transformations
        .add(data, function)
        .map_err(ActionError::InvalidArguments)
}

#[cfg(test)]
mod tests {
    use super::*;

    // CaptureAction Tests
    #[test]
    fn test_capture_no_arguments() {
        let mut rule = RuleMetadata::new();
        assert!(capture(&mut rule, "").is_ok());
        assert!(rule.capture, "capture should be enabled");
    }

    #[test]
    fn test_capture_unexpected_arguments() {
        let mut rule = RuleMetadata::new();
        assert_eq!(
            capture(&mut rule, "abc"),
            Err(ActionError::UnexpectedArguments)
        );
    }

    #[test]
    fn test_multimatch_no_arguments() {
        let mut rule = RuleMetadata::new();
        assert!(multimatch(&mut rule, "").is_ok());
        assert!(rule.multi_match, "multi_match should be enabled");
    }

    #[test]
    fn test_multimatch_unexpected_arguments() {
        let mut rule = RuleMetadata::new();
        assert_eq!(
            multimatch(&mut rule, "abc"),
            Err(ActionError::UnexpectedArguments)
        );
    }

    #[test]
    fn test_status_no_arguments() {
        assert_eq!(
            status(&mut RuleMetadata::new(), ""),
            Err(ActionError::MissingArguments)
        );
    }

    #[test]
    fn test_status_non_numeric() {
        assert!(matches!(
            status(&mut RuleMetadata::new(), "abc"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_status_valid() {
        let mut rule = RuleMetadata::new();
        assert!(status(&mut rule, "403").is_ok());
        assert_eq!(rule.status, 403);
    }

    #[test]
    fn test_status_various_codes() {
        for status_code in &[200, 301, 302, 403, 404, 500, 503] {
            let mut rule = RuleMetadata::new();
            assert!(status(&mut rule, &status_code.to_string()).is_ok());
            assert_eq!(rule.status, *status_code);
        }
    }

    #[test]
    fn test_t_no_arguments() {
        assert_eq!(
            t(&mut RuleMetadata::new(), ""),
            Err(ActionError::MissingArguments)
        );
    }

    #[test]
    fn test_t_none_clears_transformations() {
        let mut rule = RuleMetadata::new();

        // Add some transformations first
        t(&mut rule, "lowercase").unwrap();
        t(&mut rule, "uppercase").unwrap();
        assert_eq!(rule.transformations.len(), 2);

        // Apply t:none
        assert!(t(&mut rule, "none").is_ok());
        assert_eq!(
            rule.transformations.len(),
            0,
            "transformations should be cleared"
        );
    }

    #[test]
    fn test_t_adds_transformation() {
        let mut rule = RuleMetadata::new();
        assert!(t(&mut rule, "lowercase").is_ok());
        assert_eq!(rule.transformations.names(), vec!["lowercase"]);
    }

    #[test]
    fn test_t_multiple_transformations() {
        let mut rule = RuleMetadata::new();

        assert!(t(&mut rule, "lowercase").is_ok());

        assert!(t(&mut rule, "urlDecode").is_ok());

        assert_eq!(rule.transformations.names(), vec!["lowercase", "urlDecode"]);
        assert_eq!(rule.transformations.apply("A%42").0, "aB");
    }

    #[test]
    fn test_t_unknown_transformation() {
        let mut rule = RuleMetadata::new();
        assert!(matches!(
            t(&mut rule, "unknownTransformation"),
            Err(ActionError::InvalidArguments(_))
        ));
        assert!(rule.transformations.is_empty());
    }
}
