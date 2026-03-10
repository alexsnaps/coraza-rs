// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Rule compilation from SecLang directives.
//!
//! Compiles SecRule, SecAction, and SecMarker directives into executable Rule structures.

use crate::actions::ActionError;
use crate::rules::{Rule, RuleAction, RuleOperator};
use crate::seclang::{parse_actions, parse_operator, parse_variables};
use crate::utils::strings::maybe_remove_quotes;

/// Compilation error for SecLang rules
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    pub message: String,
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CompileError {}

impl CompileError {
    fn new(message: String) -> Self {
        Self { message }
    }
}

impl From<String> for CompileError {
    fn from(message: String) -> Self {
        Self { message }
    }
}

impl From<ActionError> for CompileError {
    fn from(err: ActionError) -> Self {
        Self {
            message: format!("action error: {}", err),
        }
    }
}

type CompileResult<T> = Result<T, CompileError>;

/// Compile a SecRule directive into a Rule.
///
/// Parses the format: `SecRule VARIABLES OPERATOR ACTIONS`
///
/// # Arguments
///
/// * `input` - Full SecRule directive string (without "SecRule" prefix)
///
/// # Example
///
/// ```
/// use coraza::seclang::compile_sec_rule;
///
/// let rule = compile_sec_rule("ARGS \"@rx attack\" \"id:1,deny,log\"")?;
/// assert_eq!(rule.metadata().id, 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn compile_sec_rule(input: &str) -> CompileResult<Rule> {
    // Parse the three components: VARIABLES OPERATOR ACTIONS
    let (vars, operator, actions) = parse_rule_with_operator(input)?;

    // Parse variables
    let variable_specs = parse_variables(&vars)
        .map_err(|e| CompileError::new(format!("failed to parse variables '{}': {}", vars, e)))?;

    // Parse operator
    let parsed_operator = parse_operator(&operator).map_err(|e| {
        CompileError::new(format!("failed to parse operator '{}': {}", operator, e))
    })?;

    // Parse actions (if any)
    let parsed_actions = if actions.is_empty() {
        Vec::new()
    } else {
        parse_actions(&actions).map_err(|e| {
            CompileError::new(format!("failed to parse actions '{}': {}", actions, e))
        })?
    };

    // Build rule
    let mut rule = Rule::new();

    // Add variables
    for var_spec in variable_specs {
        rule = rule.add_variable(var_spec);
    }

    // Add operator
    let operator_instance = RuleOperator::new(
        parsed_operator.operator,
        parsed_operator.function_name,
        parsed_operator.arguments,
    );
    rule = rule.with_operator(operator_instance);

    // Initialize and add actions
    for mut parsed_action in parsed_actions {
        // Initialize action with rule metadata
        parsed_action
            .action
            .init(rule.metadata_mut(), &parsed_action.value)?;

        // Create RuleAction and add to rule
        let rule_action = RuleAction::new(parsed_action.key, parsed_action.action);
        rule = rule.add_action(rule_action);
    }

    Ok(rule)
}

/// Compile a SecAction directive into a Rule.
///
/// Parses the format: `SecAction ACTIONS`
///
/// SecAction creates an operator-less rule that always matches.
///
/// # Arguments
///
/// * `input` - Full SecAction directive string (without "SecAction" prefix)
///
/// # Example
///
/// ```
/// use coraza::seclang::compile_sec_action;
///
/// let rule = compile_sec_action("\"id:1,deny,nolog\"")?;
/// assert_eq!(rule.metadata().id, 1);
/// assert!(rule.operator().is_none());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn compile_sec_action(input: &str) -> CompileResult<Rule> {
    // Remove quotes from actions
    let actions = maybe_remove_quotes(input);

    // Parse actions
    let parsed_actions = parse_actions(actions)
        .map_err(|e| CompileError::new(format!("failed to parse actions '{}': {}", actions, e)))?;

    // Build rule (no operator, no variables)
    let mut rule = Rule::new();

    // Initialize and add actions
    for mut parsed_action in parsed_actions {
        // Initialize action with rule metadata
        parsed_action
            .action
            .init(rule.metadata_mut(), &parsed_action.value)?;

        // Create RuleAction and add to rule
        let rule_action = RuleAction::new(parsed_action.key, parsed_action.action);
        rule = rule.add_action(rule_action);
    }

    Ok(rule)
}

/// Compile a SecMarker directive into a Rule.
///
/// Parses the format: `SecMarker LABEL`
///
/// SecMarker creates a flow control marker with no evaluation logic.
///
/// # Arguments
///
/// * `input` - Marker label
///
/// # Example
///
/// ```
/// use coraza::seclang::compile_sec_marker;
///
/// let rule = compile_sec_marker("BEGIN_PHASE_1")?;
/// // Marker rules have ID 0 and no operator
/// assert_eq!(rule.metadata().id, 0);
/// assert!(rule.operator().is_none());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn compile_sec_marker(input: &str) -> CompileResult<Rule> {
    let label = input.trim();

    if label.is_empty() {
        return Err(CompileError::new("SecMarker requires a label".to_string()));
    }

    // Create marker rule with ID 0
    let mut rule = Rule::new().with_id(0);

    // Set marker label in metadata
    rule.metadata_mut().sec_mark = Some(label.to_string());

    Ok(rule)
}

/// Parse a SecRule with operator into three parts: VARIABLES OPERATOR ACTIONS
///
/// Format: `VARIABLES "OPERATOR" "ACTIONS"`
///
/// Returns: (variables, operator, actions)
fn parse_rule_with_operator(data: &str) -> CompileResult<(String, String, String)> {
    let data = data.trim();

    // Split on first space to get variables
    let (vars, rest) = data.split_once(' ').ok_or_else(|| {
        CompileError::new(format!("invalid format for rule with operator: {:?}", data))
    })?;

    let rest = rest.trim_start();

    // Operator must be quoted
    if rest.is_empty() || !rest.starts_with('"') {
        return Err(CompileError::new(format!(
            "invalid operator for rule with operator: {:?}",
            data
        )));
    }

    // Extract quoted operator
    let (operator, rest) = cut_quoted_string(rest)?;
    let operator = maybe_remove_quotes(&operator);

    let rest = rest.trim_start();

    // Actions are optional
    if rest.is_empty() {
        return Ok((vars.to_string(), operator.to_string(), String::new()));
    }

    // Actions must be quoted
    if rest.len() < 2 || !rest.starts_with('"') || !rest.ends_with('"') {
        return Err(CompileError::new(format!(
            "invalid actions for rule with operator: {:?}",
            data
        )));
    }

    let actions = maybe_remove_quotes(rest);

    Ok((vars.to_string(), operator.to_string(), actions.to_string()))
}

/// Cut a quoted string from the beginning of input.
///
/// Returns: (quoted_string, remaining_input)
///
/// Handles escaped quotes: `"value with \" quote"` correctly
fn cut_quoted_string(s: &str) -> CompileResult<(String, String)> {
    if s.is_empty() || !s.starts_with('"') {
        return Err(CompileError::new(format!(
            "expected quoted string: {:?}",
            s
        )));
    }

    let bytes = s.as_bytes();
    let mut previous_escape_count = 0;

    for i in 1..bytes.len() {
        // Search until first quote that isn't part of an escape sequence
        if bytes[i] != b'"' {
            if bytes[i] == b'\\' {
                previous_escape_count += 1;
            } else {
                previous_escape_count = 0;
            }
            continue;
        }

        // If the number of backslashes is odd, it's an escaped quote
        if previous_escape_count % 2 == 1 {
            previous_escape_count = 0;
            continue;
        }

        // Found unescaped closing quote
        let quoted = &s[..i + 1];
        let rest = &s[i + 1..];
        return Ok((quoted.to_string(), rest.to_string()));
    }

    Err(CompileError::new(format!(
        "expected terminating quote: {:?}",
        s
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cut_quoted_string_simple() {
        let (quoted, rest) = cut_quoted_string("\"value\" rest").unwrap();
        assert_eq!(quoted, "\"value\"");
        assert_eq!(rest, " rest");
    }

    #[test]
    fn test_cut_quoted_string_with_escaped_quote() {
        let (quoted, rest) = cut_quoted_string("\"val\\\"ue\" rest").unwrap();
        assert_eq!(quoted, "\"val\\\"ue\"");
        assert_eq!(rest, " rest");
    }

    #[test]
    fn test_cut_quoted_string_no_closing_quote() {
        let result = cut_quoted_string("\"unclosed");
        assert!(result.is_err());
    }

    #[test]
    fn test_cut_quoted_string_no_opening_quote() {
        let result = cut_quoted_string("value\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_rule_with_operator_simple() {
        let (vars, op, acts) =
            parse_rule_with_operator("ARGS \"@rx attack\" \"id:1,deny\"").unwrap();
        assert_eq!(vars, "ARGS");
        assert_eq!(op, "@rx attack");
        assert_eq!(acts, "id:1,deny");
    }

    #[test]
    fn test_parse_rule_with_operator_no_actions() {
        let (vars, op, acts) = parse_rule_with_operator("ARGS \"@rx attack\"").unwrap();
        assert_eq!(vars, "ARGS");
        assert_eq!(op, "@rx attack");
        assert_eq!(acts, "");
    }

    #[test]
    fn test_parse_rule_with_operator_escaped_quote_in_operator() {
        let (vars, op, acts) =
            parse_rule_with_operator("ARGS \"@rx \\\"quoted\\\"\" \"id:1\"").unwrap();
        assert_eq!(vars, "ARGS");
        assert_eq!(op, "@rx \\\"quoted\\\"");
        assert_eq!(acts, "id:1");
    }

    #[test]
    fn test_parse_rule_with_operator_multiple_variables() {
        let (vars, op, acts) =
            parse_rule_with_operator("ARGS|REQUEST_HEADERS \"@rx attack\" \"id:1\"").unwrap();
        assert_eq!(vars, "ARGS|REQUEST_HEADERS");
        assert_eq!(op, "@rx attack");
        assert_eq!(acts, "id:1");
    }

    #[test]
    fn test_compile_sec_rule_simple() {
        let rule = compile_sec_rule("ARGS \"@rx attack\" \"id:1,deny,log\"").unwrap();
        assert_eq!(rule.metadata().id, 1);
        assert!(rule.operator().is_some());
    }

    #[test]
    fn test_compile_sec_action_simple() {
        let rule = compile_sec_action("\"id:100,nolog\"").unwrap();
        assert_eq!(rule.metadata().id, 100);
        assert!(rule.operator().is_none());
    }

    #[test]
    fn test_compile_sec_marker_simple() {
        let rule = compile_sec_marker("BEGIN_TESTS").unwrap();
        assert_eq!(rule.metadata().id, 0);
        assert!(rule.operator().is_none());
        assert_eq!(rule.metadata().sec_mark, Some("BEGIN_TESTS".to_string()));
    }

    #[test]
    fn test_compile_sec_marker_empty() {
        let result = compile_sec_marker("");
        assert!(result.is_err());
    }
}
