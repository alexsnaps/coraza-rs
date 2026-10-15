// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Macro expansion for operator parameters.
//!
//! Macros allow operators to reference variables at runtime using the syntax
//! `%{VARIABLE.key}`. For example: `%{TX.score}` or `%{ARGS.id}`.

use crate::transaction::Transaction;
use crate::types::RuleVariable;
use std::fmt;

/// A macro that can expand variable references at runtime.
///
/// Macros parse strings like `"value is %{TX.count}"` and can expand them
/// using transaction state: `"value is 42"`.
///
/// # Examples
///
/// ```
/// use coraza::operators::macros::Macro;
/// use coraza::types::RuleVariable;
///
/// // Parse a macro with variable reference
/// let macro_obj = Macro::new("%{TX.score}").unwrap();
///
/// // Plain text (no variables)
/// let macro_obj = Macro::new("plain text").unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct Macro {
    original: String,
    tokens: Vec<MacroToken>,
}

#[derive(Debug, Clone, PartialEq)]
struct MacroToken {
    text: String,
    variable: Option<RuleVariable>,
    key: Option<String>,
}

/// Error type for macro parsing.
#[derive(Debug, Clone, PartialEq)]
pub struct MacroError {
    message: String,
}

impl MacroError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for MacroError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "macro error: {}", self.message)
    }
}

impl std::error::Error for MacroError {}

impl Macro {
    /// Creates an empty macro (no expansion).
    ///
    /// Returns a macro that will always expand to an empty string.
    /// This is useful as a placeholder value.
    pub fn empty() -> Self {
        Self {
            original: String::new(),
            tokens: vec![],
        }
    }

    /// Creates a new macro from a string pattern.
    ///
    /// Empty strings are allowed and will be returned unchanged during expansion.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Variable syntax is malformed (e.g., `%{tx.` without closing `}`)
    /// - Variable name is unknown
    pub fn new(input: &str) -> Result<Self, MacroError> {
        // Empty strings are allowed - they simply expand to empty strings
        if input.is_empty() {
            return Ok(Self {
                original: String::new(),
                tokens: vec![],
            });
        }

        let tokens = Self::compile(input)?;
        Ok(Self {
            original: input.to_string(),
            tokens,
        })
    }

    /// Expands the macro with the variables of `tx`.
    pub fn expand(&self, tx: &Transaction) -> String {
        // Handle empty macros
        if self.tokens.is_empty() {
            return String::new();
        }

        // Rules' msg and logdata are expanded for every rule evaluated
        let mut result = String::with_capacity(self.original.len());
        for token in &self.tokens {
            result.push_str(Self::expand_token(tx, token));
        }
        result
    }

    /// The token's text, or the value of its variable if that is set.
    fn expand_token<'a>(tx: &'a Transaction, token: &'a MacroToken) -> &'a str {
        match token.variable {
            Some(variable) => tx
                .variable_value(variable, token.key.as_deref())
                .unwrap_or(&token.text),
            None => &token.text,
        }
    }

    /// Returns the original macro string.
    pub fn as_str(&self) -> &str {
        &self.original
    }

    /// Parses the input string into macro tokens.
    fn compile(input: &str) -> Result<Vec<MacroToken>, MacroError> {
        if input.is_empty() {
            return Err(MacroError::new("empty macro"));
        }

        let mut tokens = Vec::new();
        let mut current = String::new();
        let mut in_macro = false;
        let bytes = input.as_bytes();
        let len = bytes.len();
        let mut i = 0;

        while i < len {
            let c = bytes[i];

            // Check for macro start: %{
            if c == b'%' && i + 1 < len && bytes[i + 1] == b'{' {
                // Save any pending text
                if !current.is_empty() {
                    tokens.push(MacroToken {
                        text: current.clone(),
                        variable: None,
                        key: None,
                    });
                    current.clear();
                }
                in_macro = true;
                i += 2; // Skip %{
                continue;
            }

            // Inside a macro
            if in_macro {
                if c == b'}' {
                    // End of macro
                    in_macro = false;

                    if current.is_empty() {
                        return Err(MacroError::new("empty variable name"));
                    }

                    if current.ends_with('.') {
                        return Err(MacroError::new("empty variable key"));
                    }

                    // Parse variable.key
                    let (var_name, key) = match current.split_once('.') {
                        Some((v, k)) => (v, Some(k.to_lowercase())),
                        None => (current.as_str(), None),
                    };

                    let variable = var_name
                        .parse::<RuleVariable>()
                        .map_err(|_| MacroError::new(format!("unknown variable {:?}", var_name)))?;

                    tokens.push(MacroToken {
                        text: current.clone(),
                        variable: Some(variable),
                        key,
                    });
                    current.clear();
                    i += 1;
                    continue;
                }

                // Validate macro character
                if !Self::is_valid_macro_char(c) {
                    return Err(MacroError::new(format!(
                        "malformed variable starting with \"%{{{}\"",
                        current
                    )));
                }

                current.push(c as char);

                if i + 1 == len {
                    return Err(MacroError::new("malformed variable: no closing braces"));
                }
            } else {
                // Regular text
                current.push(c as char);
            }

            i += 1;
        }

        // Check if we're still inside a macro (unclosed)
        if in_macro {
            return Err(MacroError::new("malformed variable: no closing braces"));
        }

        // Save any remaining text
        if !current.is_empty() {
            tokens.push(MacroToken {
                text: current,
                variable: None,
                key: None,
            });
        }

        Ok(tokens)
    }

    fn is_valid_macro_char(c: u8) -> bool {
        matches!(c, b'[' | b']' | b'.' | b'_' | b'-' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z')
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::Transaction;

    #[test]
    fn test_new_macro_empty() {
        // Empty strings are allowed
        let m = Macro::new("").unwrap();
        assert_eq!(m.as_str(), "");
        assert_eq!(m.expand(&Transaction::default()), "");
    }

    #[test]
    fn test_new_macro_plain_text() {
        let m = Macro::new("some string").unwrap();
        assert_eq!(m.as_str(), "some string");
    }

    #[test]
    fn test_compile_single_percent() {
        let m = Macro::new("%").unwrap();
        assert!(m.expand(&Transaction::default()).contains('%'));
    }

    #[test]
    fn test_compile_empty_braces() {
        assert!(Macro::new("%{}").is_err());
    }

    #[test]
    fn test_compile_missing_key() {
        assert!(Macro::new("%{tx.}").is_err());
    }

    #[test]
    fn test_compile_malformed_no_closing() {
        assert!(Macro::new("%{tx.count").is_err());
        assert!(Macro::new("something %{tx.count").is_err());
    }

    #[test]
    fn test_compile_unknown_variable() {
        let err = Macro::new("%{unknown_variable.x}").unwrap_err();
        assert!(err.message.contains("unknown variable"));
    }

    #[test]
    fn test_compile_valid_macro() {
        let m = Macro::new("%{TX.count}").unwrap();
        assert_eq!(m.tokens.len(), 1);
        assert_eq!(m.tokens[0].variable, Some(RuleVariable::TX));
        assert_eq!(m.tokens[0].key, Some("count".to_string()));

        let m = Macro::new("%{ARGS.exec}").unwrap();
        assert_eq!(m.tokens.len(), 1);
        assert_eq!(m.tokens[0].variable, Some(RuleVariable::Args));
        assert_eq!(m.tokens[0].key, Some("exec".to_string()));
    }

    #[test]
    fn test_compile_multi_variable() {
        let m = Macro::new("%{TX.id} got %{TX.count} items").unwrap();
        assert_eq!(m.tokens.len(), 4);

        // Token 0: %{TX.id}
        assert_eq!(m.tokens[0].variable, Some(RuleVariable::TX));
        assert_eq!(m.tokens[0].key, Some("id".to_string()));

        // Token 1: " got "
        assert_eq!(m.tokens[1].variable, None);
        assert_eq!(m.tokens[1].text, " got ");

        // Token 2: %{TX.count}
        assert_eq!(m.tokens[2].variable, Some(RuleVariable::TX));
        assert_eq!(m.tokens[2].key, Some("count".to_string()));

        // Token 3: " items"
        assert_eq!(m.tokens[3].variable, None);
        assert_eq!(m.tokens[3].text, " items");
    }

    #[test]
    fn test_expand_plain_text() {
        let m = Macro::new("static text").unwrap();
        assert_eq!(m.expand(&Transaction::default()), "static text");
    }

    fn mock_tx() -> Transaction {
        let mut tx = Transaction::new("macro-test");
        let Some(crate::transaction::VariableCollection::Map(vars)) =
            tx.collection_mut(RuleVariable::TX)
        else {
            unreachable!("TX is a map");
        };
        vars.add("score", "42");
        vars.add("id", "test-123");
        tx.args_mut().add("count", "10");
        tx
    }

    #[test]
    fn test_expand_with_tx() {
        let m = Macro::new("%{TX.score}").unwrap();
        let tx = mock_tx();
        assert_eq!(m.expand(&tx), "42");
    }

    #[test]
    fn test_expand_multi_variable() {
        let m = Macro::new("ID: %{TX.id} Score: %{TX.score}").unwrap();
        let tx = mock_tx();
        assert_eq!(m.expand(&tx), "ID: test-123 Score: 42");
    }

    #[test]
    fn test_expand_missing_key() {
        let m = Macro::new("%{TX.missing}").unwrap();
        let tx = mock_tx();
        // Returns original text if key not found
        assert_eq!(m.expand(&tx), "TX.missing");
    }

    #[test]
    fn test_expand_kinds_of_variables() {
        let mut tx = mock_tx();
        tx.process_connection("10.0.0.1", 1234, "10.0.0.2", 80);

        let m = Macro::new("from %{REMOTE_ADDR}").unwrap();
        assert_eq!(m.expand(&tx), "from 10.0.0.1");
        // A collection's keys are looked up ignoring case
        let m = Macro::new("%{TX.SCORE}").unwrap();
        assert_eq!(m.expand(&tx), "42");
        // A names collection expands to the key, if present
        let m = Macro::new("%{ARGS_NAMES.count}/%{ARGS_NAMES.missing}").unwrap();
        assert_eq!(m.expand(&tx), "count/ARGS_NAMES.missing");
        let m = Macro::new("a %{TX.missing} b %{TX.score}").unwrap();
        assert_eq!(m.expand(&tx), "a TX.missing b 42");
    }
}
