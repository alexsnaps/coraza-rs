// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Operator parser for SecRule directives.
//!
//! Parses operator syntax like:
//! - `@rx pattern` - Regex operator
//! - `@pm word1 word2` - Pattern match
//! - `!@streq value` - Negated string equality
//! - `pattern` - Default to @rx (implicit)
//! - `!pattern` - Negated @rx (implicit)

use crate::operators::{OperatorContext, OperatorEnum};
use crate::rules::RuleOperator;

use crate::seclang::CompileError;

type ParseResult<T> = Result<T, CompileError>;

/// Parse operator from SecRule syntax
///
/// Parses operator specifications like:
/// - `@rx attack` - Regex operator
/// - `@streq admin` - String equality
/// - `!@contains bad` - Negated contains
/// - `attack` - Default to @rx (implicit)
/// - `!attack` - Negated @rx (implicit)
///
/// # Arguments
///
/// * `input` - Operator specification string
///
/// # Returns
///
/// The operator, with its function name (e.g. `"!@streq"`, which marks it negated) and argument
///
/// # Example
///
/// ```
/// use coraza::seclang::parse_operator;
///
/// // Parse explicit operator
/// let op = parse_operator("@rx attack")?;
/// assert_eq!((op.function(), op.data()), ("@rx", "attack"));
///
/// // Parse implicit @rx
/// let op = parse_operator("attack")?;
/// assert_eq!((op.function(), op.data()), ("@rx", "attack"));
///
/// // Parse negated operator
/// let op = parse_operator("!@streq admin")?;
/// assert_eq!((op.function(), op.data()), ("!@streq", "admin"));
/// assert!(op.is_negated());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn parse_operator(input: &str) -> ParseResult<RuleOperator> {
    parse_operator_in(input, &OperatorContext::default())
}

/// Like [`parse_operator`], creating the operator in `context`.
pub(crate) fn parse_operator_in(
    input: &str,
    context: &OperatorContext<'_>,
) -> ParseResult<RuleOperator> {
    // Normalize input to ensure it starts with @ or !@
    let normalized = normalize_operator(input);

    // Split on first space to get operator name and arguments
    let (op_raw, op_data) = normalized
        .split_once(' ')
        .map(|(name, args)| (name.trim(), args.trim()))
        .unwrap_or((normalized.trim(), ""));

    // Extract operator name without @ or !@ prefix
    let op_name = extract_operator_name(op_raw);

    let operator = OperatorEnum::with_context(op_name, op_data, context)
        .map_err(|e| CompileError::new(format!("failed to create @{} operator: {}", op_name, e)))?;

    Ok(RuleOperator::new(operator, op_raw, op_data))
}

/// Normalize operator string to ensure it starts with @ or !@
///
/// Handles default @rx operator:
/// - "" → "@rx"
/// - "pattern" → "@rx pattern"
/// - "!" → "!@rx"
/// - "!pattern" → "!@rx pattern"
/// - "@rx pattern" → "@rx pattern" (unchanged)
/// - "!@rx pattern" → "!@rx pattern" (unchanged)
fn normalize_operator(input: &str) -> String {
    let input = input.trim();
    let len = input.len();

    // Empty string → @rx
    if len == 0 {
        return "@rx".to_string();
    }

    let first_char = input.chars().next().unwrap();

    // Already starts with @ or !@ → no change needed
    if first_char == '@' {
        return input.to_string();
    }

    if first_char == '!' {
        if len == 1 {
            // "!" alone → "!@rx"
            return "!@rx".to_string();
        }

        let second_char = input.chars().nth(1).unwrap();
        if second_char == '@' {
            // Already "!@..." → no change
            return input.to_string();
        } else {
            // "!pattern" → "!@rx pattern"
            return format!("!@rx {}", &input[1..]);
        }
    }

    // No @ or ! prefix → default to @rx
    format!("@rx {}", input)
}

/// Extract operator name without @ or !@ prefix
///
/// - "@rx" → "rx"
/// - "!@pm" → "pm"
/// - "@streq" → "streq"
fn extract_operator_name(op_raw: &str) -> &str {
    if let Some(stripped) = op_raw.strip_prefix("!@") {
        stripped
    } else if let Some(stripped) = op_raw.strip_prefix('@') {
        stripped
    } else {
        op_raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_empty() {
        assert_eq!(normalize_operator(""), "@rx");
    }

    #[test]
    fn test_normalize_pattern_only() {
        assert_eq!(normalize_operator("attack"), "@rx attack");
    }

    #[test]
    fn test_normalize_negation_only() {
        assert_eq!(normalize_operator("!"), "!@rx");
    }

    #[test]
    fn test_normalize_negation_pattern() {
        assert_eq!(normalize_operator("!attack"), "!@rx attack");
    }

    #[test]
    fn test_normalize_explicit_operator() {
        assert_eq!(normalize_operator("@rx attack"), "@rx attack");
    }

    #[test]
    fn test_normalize_negated_operator() {
        assert_eq!(normalize_operator("!@rx attack"), "!@rx attack");
    }

    #[test]
    fn test_extract_operator_name_with_at() {
        assert_eq!(extract_operator_name("@rx"), "rx");
        assert_eq!(extract_operator_name("@pm"), "pm");
    }

    #[test]
    fn test_extract_operator_name_with_negation() {
        assert_eq!(extract_operator_name("!@rx"), "rx");
        assert_eq!(extract_operator_name("!@streq"), "streq");
    }

    #[test]
    fn test_parse_rx_operator() {
        let op = parse_operator("@rx attack").unwrap();
        assert_eq!(op.function(), "@rx");
        assert_eq!(op.data(), "attack");
    }

    #[test]
    fn test_parse_implicit_rx() {
        let op = parse_operator("attack").unwrap();
        assert_eq!(op.function(), "@rx");
        assert_eq!(op.data(), "attack");
    }

    #[test]
    fn test_parse_negated_operator() {
        let op = parse_operator("!@streq admin").unwrap();
        assert_eq!(op.function(), "!@streq");
        assert_eq!(op.data(), "admin");
    }

    #[test]
    fn test_parse_negated_implicit_rx() {
        let op = parse_operator("!attack").unwrap();
        assert_eq!(op.function(), "!@rx");
        assert_eq!(op.data(), "attack");
    }

    #[test]
    fn test_parse_operator_no_arguments() {
        let op = parse_operator("@pm").unwrap();
        assert_eq!(op.function(), "@pm");
        assert_eq!(op.data(), "");
    }

    #[test]
    fn test_parse_streq_operator() {
        let op = parse_operator("@streq admin").unwrap();
        assert_eq!(op.function(), "@streq");
        assert_eq!(op.data(), "admin");
    }

    #[test]
    fn test_parse_contains_operator() {
        let op = parse_operator("@contains bad").unwrap();
        assert_eq!(op.function(), "@contains");
        assert_eq!(op.data(), "bad");
    }

    #[test]
    fn test_parse_eq_operator() {
        let op = parse_operator("@eq 5").unwrap();
        assert_eq!(op.function(), "@eq");
        assert_eq!(op.data(), "5");
    }

    #[test]
    fn test_parse_unknown_operator() {
        let result = parse_operator("@unknownop test");
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("unknown operator"));
    }

    #[test]
    fn test_parse_operator_case_insensitive() {
        let op1 = parse_operator("@RX attack").unwrap();
        let op2 = parse_operator("@rx attack").unwrap();
        let op3 = parse_operator("@Rx attack").unwrap();

        assert_eq!(op1.function(), "@RX");
        assert_eq!(op2.function(), "@rx");
        assert_eq!(op3.function(), "@Rx");
        // All should work (case-insensitive lookup)
    }

    #[test]
    fn test_parse_operator_with_multiple_spaces() {
        let op = parse_operator("@rx   attack   pattern  ").unwrap();
        assert_eq!(op.function(), "@rx");
        assert_eq!(op.data(), "attack   pattern"); // Preserves internal spaces
    }

    #[test]
    fn test_parse_negation_only() {
        let op = parse_operator("!").unwrap();
        assert_eq!(op.function(), "!@rx");
        assert_eq!(op.data(), "");
    }
}
