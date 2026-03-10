// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Variable parser for SecRule directives.
//!
//! Parses variable syntax like:
//! - `ARGS` - All arguments
//! - `ARGS:id` - Specific argument by key
//! - `ARGS:/regex/` - Arguments matching regex
//! - `!ARGS:id` - Negation (exception)
//! - `&ARGS` - Count of arguments
//! - `ARGS|HEADERS` - Multiple variables
//! - `XML:xpath` - XPath selection
//! - `JSON:path` - JSON path selection

use crate::rules::VariableSpec;
use crate::types::RuleVariable;
use regex::Regex;
use std::str::FromStr;

/// Parse error for variable syntax
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableParseError {
    pub message: String,
}

impl std::fmt::Display for VariableParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for VariableParseError {}

impl VariableParseError {
    fn new(message: String) -> Self {
        Self { message }
    }
}

type ParseResult<T> = Result<T, VariableParseError>;

/// Parsed variable result
///
/// Represents a single variable specification parsed from SecRule syntax.
#[derive(Debug, Clone)]
struct ParsedVariable {
    /// The variable type (ARGS, HEADERS, etc.)
    variable: RuleVariable,

    /// Optional key selector
    key: Option<String>,

    /// Is this a negation (!)
    is_negation: bool,

    /// Is this a count (&)
    is_count: bool,
}

/// Parse variables from SecRule syntax
///
/// Parses variable specifications like:
/// - `ARGS` - All arguments
/// - `ARGS:id` - Specific key
/// - `ARGS:/user.*/` - Regex key
/// - `!ARGS:id` - Negation
/// - `&ARGS` - Count
/// - `ARGS|HEADERS|TX` - Multiple variables
///
/// # Arguments
///
/// * `input` - Variable specification string
///
/// # Returns
///
/// Vector of VariableSpec objects
///
/// # Example
///
/// ```
/// use coraza::seclang::parse_variables;
///
/// // Parse simple variable
/// let vars = parse_variables("ARGS")?;
/// assert_eq!(vars.len(), 1);
///
/// // Parse multiple variables
/// let vars = parse_variables("ARGS|REQUEST_HEADERS")?;
/// assert_eq!(vars.len(), 2);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn parse_variables(input: &str) -> ParseResult<Vec<VariableSpec>> {
    if input.is_empty() {
        return Err(VariableParseError::new(
            "empty variable specification".to_string(),
        ));
    }

    let mut result = Vec::new();
    let mut parsed = parse_variable_list(input)?;

    // Convert parsed variables to VariableSpec
    for var in parsed.drain(..) {
        let spec = build_variable_spec(var)?;
        result.push(spec);
    }

    Ok(result)
}

/// Parse a list of variables (handles pipe-separated syntax)
fn parse_variable_list(input: &str) -> ParseResult<Vec<ParsedVariable>> {
    let bytes = input.as_bytes();
    let mut vars = Vec::new();

    // State machine states:
    // 0 = variable name
    // 1 = key
    // 2 = inside regex
    // 3 = inside xpath/jsonpath
    let mut state = 0;
    let mut is_negation = false;
    let mut is_count = false;
    let mut cur_var = Vec::new();
    let mut cur_key = Vec::new();
    let mut is_escaped = false;
    let mut is_quoted = false;

    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];

        // Check for variable end conditions
        let is_pipe = c == b'|' && state != 2; // Pipe not in regex
        let is_end = i + 1 >= bytes.len(); // Last character
        let is_regex_end = state == 2 && c == b'/' && !is_escaped; // Unescaped / in regex

        if is_pipe || is_end || is_regex_end {
            // Finalize current character if not pipe
            if !is_pipe {
                if state == 0 {
                    cur_var.push(c);
                } else if state != 2 || c != b'/' {
                    // Don't include closing / for regex
                    cur_key.push(c);
                }
            }

            // Parse variable name
            let var_name = String::from_utf8_lossy(&cur_var).to_string();
            let variable = RuleVariable::from_str(&var_name).map_err(|e| {
                VariableParseError::new(format!("invalid variable name '{}': {}", var_name, e))
            })?;

            // Check if variable can be selected (has key)
            if state == 1 && !cur_key.is_empty() && !variable.can_be_selected() {
                return Err(VariableParseError::new(format!(
                    "attempting to select a value inside a non-selectable collection: {}",
                    var_name
                )));
            }

            // Handle quoted keys
            if is_quoted {
                if i + 1 < bytes.len() && bytes[i + 1] != b'\'' && bytes[i] != b'\'' {
                    return Err(VariableParseError::new(format!(
                        "unclosed quote: {:?}",
                        String::from_utf8_lossy(&cur_key)
                    )));
                }
                i += 2; // Skip closing quote
                is_quoted = false;
            } else if state == 2 {
                i += 1; // Skip closing /
            }

            // Build key string
            let key = if cur_key.is_empty() {
                None
            } else {
                let key_str = String::from_utf8_lossy(&cur_key).to_string();
                if state == 2 {
                    // Regex key - add slashes
                    Some(format!("/{}/", key_str))
                } else {
                    Some(key_str)
                }
            };

            // Store parsed variable
            vars.push(ParsedVariable {
                variable,
                key,
                is_negation,
                is_count,
            });

            // Reset state
            cur_var.clear();
            cur_key.clear();
            is_count = false;
            is_negation = false;
            state = 0;

            i += 1;
            continue;
        }

        // State machine transitions
        match state {
            0 => {
                // Parsing variable name
                match c {
                    b'!' => is_negation = true,
                    b'&' => is_count = true,
                    b':' => state = 1, // Transition to key
                    _ => cur_var.push(c),
                }
            }
            1 => {
                // Parsing key
                if cur_key.is_empty() {
                    let var_name = String::from_utf8_lossy(&cur_var).to_string();
                    if var_name == "XML" || var_name == "JSON" {
                        // Start xpath/jsonpath
                        state = 3;
                        cur_key.push(c);
                    } else if c == b'/' {
                        // Start regex
                        state = 2;
                    } else if c == b'\'' {
                        // Start quoted key
                        is_quoted = true;
                    } else {
                        cur_key.push(c);
                    }
                } else if c == b'/' {
                    // Start regex
                    state = 2;
                } else if c == b'\'' {
                    is_quoted = true;
                } else {
                    cur_key.push(c);
                }
            }
            2 => {
                // Inside regex
                if c == b'/' && !is_escaped {
                    // Unescaped / ends regex
                    state = 1;
                } else if c == b'\\' {
                    cur_key.push(b'\\');
                    is_escaped = !is_escaped;
                } else {
                    cur_key.push(c);
                    if is_escaped {
                        is_escaped = false;
                    }
                }
            }
            3 => {
                // Inside xpath/jsonpath
                cur_key.push(c);
            }
            _ => unreachable!(),
        }

        i += 1;
    }

    if vars.is_empty() {
        return Err(VariableParseError::new("no variables parsed".to_string()));
    }

    Ok(vars)
}

/// Build VariableSpec from parsed variable
fn build_variable_spec(var: ParsedVariable) -> ParseResult<VariableSpec> {
    let mut spec = if let Some(key) = &var.key {
        // Check if key is a regex (starts and ends with /)
        if key.starts_with('/') && key.ends_with('/') && key.len() > 2 {
            // Regex key
            let pattern = &key[1..key.len() - 1];
            let regex = Regex::new(pattern).map_err(|e| {
                VariableParseError::new(format!("invalid regex pattern '{}': {}", pattern, e))
            })?;
            VariableSpec::new_regex(var.variable, regex)
        } else {
            // String key
            VariableSpec::new_string(var.variable, key.clone())
        }
    } else {
        // No key - match all
        VariableSpec::new(var.variable)
    };

    // Set count flag
    if var.is_count {
        spec.set_count(true);
    }

    // Handle negation by adding exception
    if var.is_negation
        && let Some(key) = var.key
    {
        if key.starts_with('/') && key.ends_with('/') && key.len() > 2 {
            // Regex exception
            let pattern = &key[1..key.len() - 1];
            let regex = Regex::new(pattern).map_err(|e| {
                VariableParseError::new(format!("invalid regex pattern '{}': {}", pattern, e))
            })?;
            spec.add_exception_regex(regex);
        } else {
            // String exception
            spec.add_exception_string(key);
        }
    }

    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_variable() {
        let vars = parse_variables("ARGS").unwrap();
        assert_eq!(vars.len(), 1);
        // Variable should match ARGS with no key
    }

    #[test]
    fn test_parse_variable_with_string_key() {
        let vars = parse_variables("ARGS:username").unwrap();
        assert_eq!(vars.len(), 1);
    }

    #[test]
    fn test_parse_variable_with_regex_key() {
        let vars = parse_variables("ARGS:/user.*/").unwrap();
        assert_eq!(vars.len(), 1);
    }

    #[test]
    fn test_parse_count_variable() {
        let vars = parse_variables("&ARGS").unwrap();
        assert_eq!(vars.len(), 1);
    }

    #[test]
    fn test_parse_negation_variable() {
        let vars = parse_variables("!ARGS:id").unwrap();
        assert_eq!(vars.len(), 1);
    }

    #[test]
    fn test_parse_multiple_variables() {
        let vars = parse_variables("ARGS|REQUEST_HEADERS").unwrap();
        assert_eq!(vars.len(), 2);
    }

    #[test]
    fn test_parse_multiple_variables_with_keys() {
        let vars = parse_variables("ARGS:id|REQUEST_HEADERS:user-agent").unwrap();
        assert_eq!(vars.len(), 2);
    }

    #[test]
    fn test_parse_regex_with_escape() {
        let vars = parse_variables("ARGS:/test\\b/").unwrap();
        assert_eq!(vars.len(), 1);
    }

    #[test]
    fn test_parse_empty_input() {
        let result = parse_variables("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_variable() {
        let result = parse_variables("INVALID_VAR");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_non_selectable_with_key() {
        // REQUEST_URI cannot be selected with a key
        let result = parse_variables("REQUEST_URI:foo");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .message
                .contains("non-selectable collection")
        );
    }

    // Test cases from Go: TestParseRule
    #[test]
    fn test_parse_does_not_contain_escape_characters() {
        // ARGS_GET:/(test)/|REQUEST_XML
        let vars = parse_variables("ARGS_GET:/(test)/|REQUEST_XML").unwrap();
        assert_eq!(vars.len(), 2);
    }

    #[test]
    fn test_parse_last_variable_contains_escape_characters() {
        // ARGS_GET|REQUEST_XML:/(test)\b/
        let vars = parse_variables("ARGS_GET|REQUEST_XML:/(test)\\b/").unwrap();
        assert_eq!(vars.len(), 2);
    }

    #[test]
    fn test_parse_contains_escape_characters() {
        // ARGS_GET:/(test\b)/|REQUEST_XML
        let vars = parse_variables("ARGS_GET:/(test\\b)/|REQUEST_XML").unwrap();
        assert_eq!(vars.len(), 2);
    }
}
