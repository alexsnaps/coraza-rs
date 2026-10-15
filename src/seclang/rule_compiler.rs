// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Rule compilation from SecLang directives.
//!
//! Compiles SecRule, SecAction, and SecMarker directives into executable Rule structures.

use crate::actions::Action;
use crate::operators::OperatorContext;
use crate::rules::Rule;
use crate::seclang::CompileError;
use crate::seclang::action_parser::ParsedAction;
use crate::seclang::operator_parser::parse_operator_in;
use crate::seclang::{parse_actions, parse_variables};
use crate::utils::strings::maybe_remove_quotes;

type CompileResult<T> = Result<T, CompileError>;

/// Compile a SecRule directive into a Rule.
///
/// Parses the format: `SecRule VARIABLES OPERATOR ACTIONS`
///
/// # Arguments
///
/// * `input` - Full SecRule directive string (without "SecRule" prefix)
///
/// The operator is created in the default [`OperatorContext`]: a relative data file
/// is relative to the working directory.
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
    compile_sec_rule_in(input, &OperatorContext::default())
}

/// Like [`compile_sec_rule`], creating the operator in `context`.
pub(crate) fn compile_sec_rule_in(
    input: &str,
    context: &OperatorContext<'_>,
) -> CompileResult<Rule> {
    // Parse the three components: VARIABLES OPERATOR ACTIONS
    let (vars, operator, actions) = parse_rule_with_operator(input)?;

    // Parse variables
    let variable_specs = parse_variables(&vars)
        .map_err(|e| CompileError::new(format!("failed to parse variables '{}': {}", vars, e)))?;

    // Parse operator
    let rule_operator = parse_operator_in(&operator, context).map_err(|e| {
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

    rule = rule.with_operator(rule_operator);

    add_actions(rule, parsed_actions)
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
    add_actions(Rule::new(), parsed_actions)
}

/// Applies parsed actions to `rule` in order: metadata actions update its metadata,
/// the others are added to it (a later disruptive action replaces an earlier one).
fn add_actions(mut rule: Rule, parsed_actions: Vec<ParsedAction>) -> CompileResult<Rule> {
    for parsed in parsed_actions {
        if let Some(action) = Action::parse(&parsed.key, &parsed.value, rule.metadata_mut())? {
            rule = rule.add_action(action);
        }
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
    let mut label = input.trim();

    // Strip surrounding quotes if present
    if (label.starts_with('"') && label.ends_with('"'))
        || (label.starts_with('\'') && label.ends_with('\''))
    {
        label = &label[1..label.len() - 1];
    }

    if label.is_empty() {
        return Err(CompileError::new("SecMarker requires a label".to_string()));
    }

    // Create marker rule with ID 0 and phase Unknown (matches all phases)
    let mut rule = Rule::new().with_id(0);

    // Set marker label in metadata
    rule.metadata_mut().sec_mark = Some(label.to_string());
    rule.metadata_mut().phase = crate::RulePhase::Unknown;

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

    #[test]
    fn test_unknown_action_is_a_compile_error() {
        let err = compile_sec_action("id:1,unknownaction").unwrap_err();
        assert!(err.message.contains("unknown action"), "{}", err.message);
    }

    #[test]
    fn test_last_disruptive_action_wins() {
        let rule = compile_sec_action("id:1,deny,setvar:tx.a=1,drop").unwrap();
        let names: Vec<&str> = rule.actions().iter().map(|a| a.name()).collect();
        assert_eq!(names, ["setvar", "drop"]);
    }
}
