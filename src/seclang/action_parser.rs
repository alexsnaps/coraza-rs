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

use crate::seclang::CompileError;
use crate::utils::strings::maybe_remove_quotes;

type ParseResult<T> = Result<T, CompileError>;

/// One action of a rule's action list, as written; see [`crate::actions::Action::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAction {
    /// Action key/name (lowercase, trimmed)
    pub key: String,

    /// Action value (trimmed, quotes removed); empty if the action has none
    pub value: String,
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
/// The actions in order, as name/value pairs; whether each name is a known action is
/// checked when the rule is compiled.
///
/// # Special handling
///
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
/// let actions = parse_actions("phase:2,auditlog,allow,log,id:5000003,msg:'msn bot'")?;
/// assert_eq!(actions.len(), 6);
///
/// // Parse action with quoted value
/// let actions = parse_actions("msg:'Attack detected'")?;
/// assert_eq!(actions[0].value, "Attack detected");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn parse_actions(input: &str) -> ParseResult<Vec<ParsedAction>> {
    let mut result = Vec::new();
    if input.trim().is_empty() {
        return Ok(result);
    }

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
                append_action(&mut result, key, val)?;

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
        return Err(CompileError::new(format!(
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

    append_action(&mut result, key, val)?;

    Ok(result)
}

/// Appends an action, with its key trimmed and lowercased and its value trimmed and unquoted.
fn append_action(result: &mut Vec<ParsedAction>, key: String, value: String) -> ParseResult<()> {
    result.push(ParsedAction {
        key: key.trim().to_lowercase(),
        value: maybe_remove_quotes(value.trim()).to_string(),
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_parse_empty_action_string() {
        assert!(parse_actions("").unwrap().is_empty());
        assert!(parse_actions("  ").unwrap().is_empty());
    }

    #[test]
    fn test_parse_action_with_double_quotes() {
        let actions = parse_actions("msg:\"Double quoted\"").unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].key, "msg");
        assert_eq!(actions[0].value, "Double quoted");
    }
}
