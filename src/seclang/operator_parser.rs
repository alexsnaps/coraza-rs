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

use crate::operators::*;
use crate::rules::OperatorEnum;

/// Parse error for operator syntax
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorParseError {
    pub message: String,
}

impl std::fmt::Display for OperatorParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for OperatorParseError {}

impl OperatorParseError {
    fn new(message: String) -> Self {
        Self { message }
    }
}

type ParseResult<T> = Result<T, OperatorParseError>;

/// Parsed operator result
///
/// Contains the operator information needed to create a RuleOperator.
#[derive(Debug, Clone)]
pub struct ParsedOperator {
    /// Operator enum instance (the actual operator logic)
    pub operator: OperatorEnum,

    /// Original operator string with @ and ! (for metadata)
    /// Examples: "@rx", "!@streq", "@pm"
    pub function_name: String,

    /// Operator arguments/data (pattern, value, etc.)
    pub arguments: String,
}

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
/// ParsedOperator with operator, function name, and arguments
///
/// # Example
///
/// ```
/// use coraza::seclang::parse_operator;
///
/// // Parse explicit operator
/// let op = parse_operator("@rx attack")?;
/// // op.function_name = "@rx"
/// // op.arguments = "attack"
///
/// // Parse implicit @rx
/// let op = parse_operator("attack")?;
/// // op.function_name = "@rx"
/// // op.arguments = "attack"
///
/// // Parse negated operator
/// let op = parse_operator("!@streq admin")?;
/// // op.function_name = "!@streq"
/// // op.arguments = "admin"
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn parse_operator(input: &str) -> ParseResult<ParsedOperator> {
    // Normalize input to ensure it starts with @ or !@
    let normalized = normalize_operator(input);

    // Split on first space to get operator name and arguments
    let (op_raw, op_data) = normalized
        .split_once(' ')
        .map(|(name, args)| (name.trim(), args.trim()))
        .unwrap_or((normalized.trim(), ""));

    // Extract operator name without @ or !@ prefix
    let op_name = extract_operator_name(op_raw);

    // Look up operator from registry and create instance
    let operator = create_operator(op_name, op_data)?;

    Ok(ParsedOperator {
        operator,
        function_name: op_raw.to_string(),
        arguments: op_data.to_string(),
    })
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

/// Create operator instance from name and arguments
///
/// Looks up operator by name and creates an instance with the given arguments.
fn create_operator(name: &str, arguments: &str) -> ParseResult<OperatorEnum> {
    // Convert operator name to lowercase for case-insensitive lookup
    let name_lower = name.to_lowercase();

    match name_lower.as_str() {
        "rx" => {
            let op = rx(arguments).map_err(|e| {
                OperatorParseError::new(format!("failed to create @rx operator: {}", e))
            })?;
            Ok(op.into())
        }
        "pm" => {
            let op = pm(arguments).map_err(|e| {
                OperatorParseError::new(format!("failed to create @pm operator: {}", e))
            })?;
            Ok(op.into())
        }
        "streq" => {
            let op = streq(arguments).map_err(|e| {
                OperatorParseError::new(format!("failed to create @streq operator: {}", e))
            })?;
            Ok(op.into())
        }
        "strmatch" => {
            let op = strmatch(arguments).map_err(|e| {
                OperatorParseError::new(format!("failed to create @strmatch operator: {}", e))
            })?;
            Ok(op.into())
        }
        "contains" => {
            let op = contains(arguments).map_err(|e| {
                OperatorParseError::new(format!("failed to create @contains operator: {}", e))
            })?;
            Ok(op.into())
        }
        "beginswith" => {
            let op = begins_with(arguments).map_err(|e| {
                OperatorParseError::new(format!("failed to create @beginsWith operator: {}", e))
            })?;
            Ok(op.into())
        }
        "endswith" => {
            let op = ends_with(arguments).map_err(|e| {
                OperatorParseError::new(format!("failed to create @endsWith operator: {}", e))
            })?;
            Ok(op.into())
        }
        "eq" => {
            let op = eq(arguments).map_err(|e| {
                OperatorParseError::new(format!("failed to create @eq operator: {}", e))
            })?;
            Ok(op.into())
        }
        "ge" => {
            let op = ge(arguments).map_err(|e| {
                OperatorParseError::new(format!("failed to create @ge operator: {}", e))
            })?;
            Ok(op.into())
        }
        "gt" => {
            let op = gt(arguments).map_err(|e| {
                OperatorParseError::new(format!("failed to create @gt operator: {}", e))
            })?;
            Ok(op.into())
        }
        "le" => {
            let op = le(arguments).map_err(|e| {
                OperatorParseError::new(format!("failed to create @le operator: {}", e))
            })?;
            Ok(op.into())
        }
        "lt" => {
            let op = lt(arguments).map_err(|e| {
                OperatorParseError::new(format!("failed to create @lt operator: {}", e))
            })?;
            Ok(op.into())
        }
        "within" => {
            let op = within(arguments).map_err(|e| {
                OperatorParseError::new(format!("failed to create @within operator: {}", e))
            })?;
            Ok(op.into())
        }
        "ipmatch" => {
            let op = ip_match(arguments).map_err(|e| {
                OperatorParseError::new(format!("failed to create @ipMatch operator: {}", e))
            })?;
            Ok(op.into())
        }
        _ => Err(OperatorParseError::new(format!(
            "unknown operator: {}",
            name
        ))),
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
        assert_eq!(op.function_name, "@rx");
        assert_eq!(op.arguments, "attack");
    }

    #[test]
    fn test_parse_implicit_rx() {
        let op = parse_operator("attack").unwrap();
        assert_eq!(op.function_name, "@rx");
        assert_eq!(op.arguments, "attack");
    }

    #[test]
    fn test_parse_negated_operator() {
        let op = parse_operator("!@streq admin").unwrap();
        assert_eq!(op.function_name, "!@streq");
        assert_eq!(op.arguments, "admin");
    }

    #[test]
    fn test_parse_negated_implicit_rx() {
        let op = parse_operator("!attack").unwrap();
        assert_eq!(op.function_name, "!@rx");
        assert_eq!(op.arguments, "attack");
    }

    #[test]
    fn test_parse_operator_no_arguments() {
        let op = parse_operator("@pm").unwrap();
        assert_eq!(op.function_name, "@pm");
        assert_eq!(op.arguments, "");
    }

    #[test]
    fn test_parse_streq_operator() {
        let op = parse_operator("@streq admin").unwrap();
        assert_eq!(op.function_name, "@streq");
        assert_eq!(op.arguments, "admin");
    }

    #[test]
    fn test_parse_contains_operator() {
        let op = parse_operator("@contains bad").unwrap();
        assert_eq!(op.function_name, "@contains");
        assert_eq!(op.arguments, "bad");
    }

    #[test]
    fn test_parse_eq_operator() {
        let op = parse_operator("@eq 5").unwrap();
        assert_eq!(op.function_name, "@eq");
        assert_eq!(op.arguments, "5");
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

        assert_eq!(op1.function_name, "@RX");
        assert_eq!(op2.function_name, "@rx");
        assert_eq!(op3.function_name, "@Rx");
        // All should work (case-insensitive lookup)
    }

    #[test]
    fn test_parse_operator_with_multiple_spaces() {
        let op = parse_operator("@rx   attack   pattern  ").unwrap();
        assert_eq!(op.function_name, "@rx");
        assert_eq!(op.arguments, "attack   pattern"); // Preserves internal spaces
    }

    #[test]
    fn test_parse_negation_only() {
        let op = parse_operator("!").unwrap();
        assert_eq!(op.function_name, "!@rx");
        assert_eq!(op.arguments, "");
    }
}
