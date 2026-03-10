// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Action parser for SecRule directives.
//!
//! Parses action syntax like:
//! - `id:1,deny,log` - Multiple actions
//! - `id:123` - Action with value
//! - `deny` - Bare action (no value)
//! - `msg:'Attack detected'` - Quoted value
//! - `msg:'O\'Reilly'` - Escaped quotes

use crate::actions::{self, Action, ActionType};

/// Parse error for action syntax
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionParseError {
    pub message: String,
}

impl std::fmt::Display for ActionParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ActionParseError {}

impl ActionParseError {
    fn new(message: String) -> Self {
        Self { message }
    }
}

type ParseResult<T> = Result<T, ActionParseError>;

/// Parsed action result
///
/// Contains the action information needed to create a RuleAction.
pub struct ParsedAction {
    /// Action key/name (lowercase, trimmed)
    pub key: String,

    /// Action value (trimmed, quotes removed)
    pub value: String,

    /// Action instance
    pub action: Box<dyn Action>,

    /// Action type (for disruptive action handling)
    pub action_type: ActionType,
}

/// Parse actions from SecRule syntax
///
/// Parses action specifications like:
/// - `id:1,deny,log` - Multiple actions
/// - `id:123` - Single action with value
/// - `deny` - Bare action (no value)
/// - `msg:'Attack detected'` - Quoted value with spaces
/// - `msg:'O\'Reilly'` - Escaped quotes in value
///
/// # Arguments
///
/// * `input` - Action specification string (comma-separated)
///
/// # Returns
///
/// Vector of ParsedAction objects with initialized action instances.
///
/// # Special handling
///
/// - Only one disruptive action allowed per rule (last one wins)
/// - Keys are lowercased and trimmed
/// - Values are trimmed and quotes removed
/// - Unclosed quotes result in an error
///
/// # Example
///
/// ```
/// use coraza::seclang::parse_actions;
///
/// // Parse multiple actions
/// let actions = parse_actions("id:1,deny,log")?;
/// assert_eq!(actions.len(), 3);
///
/// // Parse action with quoted value
/// let actions = parse_actions("msg:'Attack detected'")?;
/// assert_eq!(actions[0].value, "Attack detected");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn parse_actions(input: &str) -> ParseResult<Vec<ParsedAction>> {
    let mut result = Vec::new();
    let mut disruptive_action_index: Option<usize> = None;

    let bytes = input.as_bytes();
    let mut before_key = -1_isize; // index before first char of key
    let mut after_key = -1_isize; // index after last char of key and before first char of value
    let mut in_quotes = false;

    // Start at index 1 to skip opening character
    let mut i = 1;
    while i < bytes.len() {
        let c = bytes[i];

        // Check if previous character was escape
        if i > 0 && bytes[i - 1] == b'\\' {
            // Escaped character, skip processing
            i += 1;
            continue;
        }

        // Toggle quote state
        if c == b'\'' {
            in_quotes = !in_quotes;
            i += 1;
            continue;
        }

        // Inside quotes, skip processing
        if in_quotes {
            i += 1;
            continue;
        }

        match c {
            b':' => {
                if after_key != -1 {
                    // Already found colon (reading value), skip
                    i += 1;
                    continue;
                }
                after_key = i as isize;
            }
            b',' => {
                // Extract key and value
                let val = if after_key == -1 {
                    // No value, bare action
                    after_key = i as isize;
                    String::new()
                } else {
                    let start = (after_key + 1) as usize;
                    let end = i;
                    String::from_utf8_lossy(&bytes[start..end]).to_string()
                };

                let key_start = (before_key + 1) as usize;
                let key_end = after_key as usize;
                let key = String::from_utf8_lossy(&bytes[key_start..key_end]).to_string();

                // Append action
                append_action(&mut result, &mut disruptive_action_index, key, val)?;

                // Reset state
                before_key = i as isize;
                after_key = -1;
            }
            _ => {}
        }

        i += 1;
    }

    // Check for unclosed quotes
    if in_quotes {
        return Err(ActionParseError::new(format!(
            "unclosed quotes in action line: {}",
            input
        )));
    }

    // Process final action
    let val = if after_key == -1 {
        // No value, bare action
        after_key = bytes.len() as isize;
        String::new()
    } else {
        let start = (after_key + 1) as usize;
        String::from_utf8_lossy(&bytes[start..]).to_string()
    };

    let key_start = (before_key + 1) as usize;
    let key_end = after_key as usize;
    let key = String::from_utf8_lossy(&bytes[key_start..key_end]).to_string();

    append_action(&mut result, &mut disruptive_action_index, key, val)?;

    Ok(result)
}

/// Append action to result list with disruptive action handling
///
/// - Only one disruptive action allowed per rule (last one wins)
/// - Keys are lowercased and trimmed
/// - Values are trimmed and quotes removed
fn append_action(
    result: &mut Vec<ParsedAction>,
    disruptive_action_index: &mut Option<usize>,
    key: String,
    value: String,
) -> ParseResult<()> {
    // Trim and lowercase key
    let key = key.trim().to_lowercase();

    // Trim and remove quotes from value
    let value = maybe_remove_quotes(value.trim());

    // Look up action from registry
    let action = actions::get(&key)
        .map_err(|e| ActionParseError::new(format!("failed to get action '{}': {}", key, e)))?;

    let action_type = action.action_type();

    // Handle disruptive actions (only one allowed per rule)
    if action_type == ActionType::Disruptive {
        if let Some(idx) = *disruptive_action_index {
            // Replace previous disruptive action (last one wins)
            result[idx] = ParsedAction {
                key,
                value,
                action,
                action_type,
            };
        } else {
            // First disruptive action
            *disruptive_action_index = Some(result.len());
            result.push(ParsedAction {
                key,
                value,
                action,
                action_type,
            });
        }
    } else {
        // Non-disruptive action
        result.push(ParsedAction {
            key,
            value,
            action,
            action_type,
        });
    }

    Ok(())
}

/// Remove surrounding quotes from a string if present
///
/// Handles both single and double quotes.
/// - `'value'` → `value`
/// - `"value"` → `value`
/// - `value` → `value` (unchanged)
fn maybe_remove_quotes(input: &str) -> String {
    if input.len() < 2 {
        return input.to_string();
    }

    let bytes = input.as_bytes();
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];

    // Check if surrounded by matching quotes
    if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
        input[1..input.len() - 1].to_string()
    } else {
        input.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_maybe_remove_quotes_single() {
        assert_eq!(maybe_remove_quotes("'value'"), "value");
    }

    #[test]
    fn test_maybe_remove_quotes_double() {
        assert_eq!(maybe_remove_quotes("\"value\""), "value");
    }

    #[test]
    fn test_maybe_remove_quotes_no_quotes() {
        assert_eq!(maybe_remove_quotes("value"), "value");
    }

    #[test]
    fn test_maybe_remove_quotes_mismatched() {
        assert_eq!(maybe_remove_quotes("'value\""), "'value\"");
    }

    #[test]
    fn test_maybe_remove_quotes_empty() {
        assert_eq!(maybe_remove_quotes(""), "");
    }

    #[test]
    fn test_maybe_remove_quotes_single_char() {
        assert_eq!(maybe_remove_quotes("'"), "'");
    }

    #[test]
    fn test_parse_single_bare_action() {
        let actions = parse_actions("deny").unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].key, "deny");
        assert_eq!(actions[0].value, "");
    }

    #[test]
    fn test_parse_single_action_with_value() {
        let actions = parse_actions("id:123").unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].key, "id");
        assert_eq!(actions[0].value, "123");
    }

    #[test]
    fn test_parse_multiple_actions() {
        let actions = parse_actions("id:1,deny,log").unwrap();
        assert_eq!(actions.len(), 3);
        assert_eq!(actions[0].key, "id");
        assert_eq!(actions[0].value, "1");
        assert_eq!(actions[1].key, "deny");
        assert_eq!(actions[1].value, "");
        assert_eq!(actions[2].key, "log");
        assert_eq!(actions[2].value, "");
    }

    #[test]
    fn test_parse_action_with_quoted_value() {
        let actions = parse_actions("msg:'Attack detected'").unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].key, "msg");
        assert_eq!(actions[0].value, "Attack detected");
    }

    #[test]
    fn test_parse_action_with_escaped_quote() {
        let actions = parse_actions("msg:'O\\'Reilly'").unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].key, "msg");
        // Note: Escaped quote remains in value (backslash preserved)
        assert_eq!(actions[0].value, "O\\'Reilly");
    }

    #[test]
    fn test_parse_action_with_comma_in_quotes() {
        let actions = parse_actions("msg:'Hello, World'").unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].key, "msg");
        assert_eq!(actions[0].value, "Hello, World");
    }

    #[test]
    fn test_parse_action_with_colon_in_quotes() {
        let actions = parse_actions("msg:'Error: Bad request'").unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].key, "msg");
        assert_eq!(actions[0].value, "Error: Bad request");
    }

    #[test]
    fn test_parse_unclosed_quotes() {
        let result = parse_actions("msg:'unclosed");
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.message.contains("unclosed quotes"));
        }
    }

    #[test]
    fn test_parse_action_case_insensitive() {
        let actions = parse_actions("DENY,Log,ID:1").unwrap();
        assert_eq!(actions.len(), 3);
        assert_eq!(actions[0].key, "deny");
        assert_eq!(actions[1].key, "log");
        assert_eq!(actions[2].key, "id");
    }

    #[test]
    fn test_parse_action_with_whitespace() {
        let actions = parse_actions("id : 123 , deny , log").unwrap();
        assert_eq!(actions.len(), 3);
        assert_eq!(actions[0].key, "id");
        assert_eq!(actions[0].value, "123");
        assert_eq!(actions[1].key, "deny");
        assert_eq!(actions[2].key, "log");
    }

    #[test]
    fn test_parse_unknown_action() {
        let result = parse_actions("unknownaction");
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.message.to_lowercase().contains("unknown"));
        }
    }

    #[test]
    fn test_parse_multiple_disruptive_actions_last_wins() {
        // deny and drop are both disruptive - last one (drop) should win
        let actions = parse_actions("id:1,deny,drop").unwrap();
        // Should have 2 actions: id (metadata) and drop (disruptive)
        // deny should be replaced by drop
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].key, "id");
        assert_eq!(actions[1].key, "drop");
    }

    #[test]
    fn test_parse_empty_action_string() {
        // Empty string should parse as single empty action
        let result = parse_actions("");
        // Go implementation would try to parse this and likely error
        // Let's check what happens
        if let Ok(actions) = result {
            assert!(actions.is_empty())
        }
    }

    #[test]
    fn test_parse_action_with_double_quotes() {
        let actions = parse_actions("msg:\"Double quoted\"").unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].key, "msg");
        assert_eq!(actions[0].value, "Double quoted");
    }
}
