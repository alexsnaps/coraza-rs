// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Macro expansion for operator parameters.
//!
//! Macros allow operators to reference variables at runtime using the syntax
//! `%{VARIABLE.key}`. For example: `%{TX.score}` or `%{ARGS.id}`.

use crate::types::RuleVariable;
use std::fmt;

/// Transaction state for variable lookups and capturing.
///
/// This trait provides access to variable collections during rule evaluation
/// and supports capturing regex groups for use in rule actions.
pub trait TransactionState {
    /// Get a variable value by variable type and optional key.
    ///
    /// Returns the first value if the variable contains multiple values.
    fn get_variable(&self, variable: RuleVariable, key: Option<&str>) -> Option<String>;

    /// Check if capturing is enabled for this evaluation.
    ///
    /// When capturing is enabled, operators like `@rx` will store matched
    /// groups for later use in rule actions. Returns false by default.
    fn capturing(&self) -> bool {
        false
    }

    /// Capture a field value at the given index.
    ///
    /// Used by regex operators to store captured groups. Index 0 is the full match,
    /// indices 1-9 are capturing groups. ModSecurity limits captures to 9 groups.
    ///
    /// # Arguments
    /// * `index` - Capture index (0 = full match, 1-9 = groups)
    /// * `value` - The captured string value
    fn capture_field(&mut self, index: usize, value: &str) {
        let _ = (index, value); // Suppress unused warnings for default impl
    }

    /// Interrupt the transaction with the given action.
    ///
    /// Called by disruptive actions like `deny`, `drop`, and `redirect` to
    /// stop transaction processing.
    ///
    /// # Arguments
    /// * `rule_id` - ID of the rule that triggered the interruption
    /// * `action` - Action name (e.g., "deny", "drop", "redirect")
    /// * `status` - HTTP status code
    /// * `data` - Additional data (e.g., redirect URL)
    fn interrupt(&mut self, rule_id: i32, action: &str, status: i32, data: &str) {
        let _ = (rule_id, action, status, data); // Suppress unused warnings for default impl
    }

    /// Set the allow type for the transaction.
    ///
    /// Called by the `allow` action to control which phases are skipped.
    ///
    /// # Arguments
    /// * `allow_type` - The type of allow (All, Phase, or Request)
    fn set_allow_type(&mut self, allow_type: crate::actions::AllowType) {
        let _ = allow_type; // Suppress unused warnings for default impl
    }

    /// Get a mutable reference to a collection by variable.
    ///
    /// Used by variable manipulation actions like `setvar` to modify collections.
    ///
    /// # Arguments
    /// * `variable` - The variable identifying which collection to retrieve
    ///
    /// # Returns
    /// A mutable reference to the collection, or None if not available
    fn collection_mut(
        &mut self,
        variable: RuleVariable,
    ) -> Option<&mut dyn crate::collection::MapCollection> {
        let _ = variable; // Suppress unused warnings for default impl
        None
    }

    /// Set the number of rules to skip.
    ///
    /// Called by the `skip` action to skip the next N rules in the current phase.
    ///
    /// # Arguments
    /// * `count` - Number of rules to skip (must be >= 1)
    fn set_skip(&mut self, count: i32) {
        let _ = count; // Suppress unused warnings for default impl
    }

    /// Set the marker to skip to.
    ///
    /// Called by the `skipAfter` action to skip rules until reaching a marker.
    ///
    /// # Arguments
    /// * `marker` - Marker ID to skip to
    fn set_skip_after(&mut self, marker: &str) {
        let _ = marker; // Suppress unused warnings for default impl
    }

    // ===== CTL Action Methods =====

    /// Set rule engine status (called by ctl:ruleEngine).
    fn ctl_set_rule_engine(&mut self, status: crate::RuleEngineStatus) {
        let _ = status;
    }

    /// Set request body access (called by ctl:requestBodyAccess).
    fn ctl_set_request_body_access(&mut self, enabled: bool) {
        let _ = enabled;
    }

    /// Set request body limit (called by ctl:requestBodyLimit).
    fn ctl_set_request_body_limit(&mut self, limit: i64) {
        let _ = limit;
    }

    /// Set force request body variable (called by ctl:forceRequestBodyVariable).
    fn ctl_set_force_request_body_variable(&mut self, enabled: bool) {
        let _ = enabled;
    }

    /// Set response body access (called by ctl:responseBodyAccess).
    fn ctl_set_response_body_access(&mut self, enabled: bool) {
        let _ = enabled;
    }

    /// Set response body limit (called by ctl:responseBodyLimit).
    fn ctl_set_response_body_limit(&mut self, limit: i64) {
        let _ = limit;
    }

    /// Set force response body variable (called by ctl:forceResponseBodyVariable).
    fn ctl_set_force_response_body_variable(&mut self, enabled: bool) {
        let _ = enabled;
    }

    /// Get last processed phase (used by CTL to check phase restrictions).
    fn ctl_last_phase(&self) -> Option<crate::types::RulePhase> {
        None
    }
}

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

    /// Expands the macro using transaction state.
    ///
    /// If no transaction state is provided, returns the original text
    /// (variables are not expanded).
    ///
    /// This method uses static dispatch (generics) for zero-overhead abstraction.
    /// The compiler can inline the entire expansion path.
    pub fn expand<TX: TransactionState + ?Sized>(&self, tx: Option<&TX>) -> String {
        // Handle empty macros
        if self.tokens.is_empty() {
            return String::new();
        }

        match tx {
            None => self.original.clone(),
            Some(tx) => {
                if self.tokens.len() == 1 {
                    Self::expand_token(tx, &self.tokens[0])
                } else {
                    let mut result = String::new();
                    for token in &self.tokens {
                        result.push_str(&Self::expand_token(tx, token));
                    }
                    result
                }
            }
        }
    }

    fn expand_token<TX: TransactionState + ?Sized>(tx: &TX, token: &MacroToken) -> String {
        match (&token.variable, &token.key) {
            (Some(var), key) => {
                let key_str = key.as_deref();
                tx.get_variable(*var, key_str)
                    .unwrap_or_else(|| token.text.clone())
            }
            (None, _) => token.text.clone(),
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
        assert_eq!(m.expand(None::<&Transaction>), "");
    }

    #[test]
    fn test_new_macro_plain_text() {
        let m = Macro::new("some string").unwrap();
        assert_eq!(m.as_str(), "some string");
    }

    #[test]
    fn test_compile_single_percent() {
        let m = Macro::new("%").unwrap();
        assert!(m.expand(None::<&Transaction>).contains('%'));
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
    fn test_expand_no_tx() {
        let m = Macro::new("static text").unwrap();
        assert_eq!(m.expand(None::<&Transaction>), "static text");

        let m = Macro::new("%{TX.score}").unwrap();
        assert_eq!(m.expand(None::<&Transaction>), "%{TX.score}");
    }

    // Mock transaction state for testing
    struct MockTx;

    impl TransactionState for MockTx {
        fn get_variable(&self, variable: RuleVariable, key: Option<&str>) -> Option<String> {
            match (variable, key) {
                (RuleVariable::TX, Some("score")) => Some("42".to_string()),
                (RuleVariable::TX, Some("id")) => Some("test-123".to_string()),
                (RuleVariable::Args, Some("count")) => Some("10".to_string()),
                _ => None,
            }
        }
    }

    #[test]
    fn test_expand_with_tx() {
        let m = Macro::new("%{TX.score}").unwrap();
        let tx = MockTx;
        assert_eq!(m.expand(Some(&tx)), "42");
    }

    #[test]
    fn test_expand_multi_variable() {
        let m = Macro::new("ID: %{TX.id} Score: %{TX.score}").unwrap();
        let tx = MockTx;
        assert_eq!(m.expand(Some(&tx)), "ID: test-123 Score: 42");
    }

    #[test]
    fn test_expand_missing_key() {
        let m = Macro::new("%{TX.missing}").unwrap();
        let tx = MockTx;
        // Returns original text if key not found
        assert_eq!(m.expand(Some(&tx)), "TX.missing");
    }
}
