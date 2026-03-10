// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Variable extraction system for rule evaluation.
//!
//! This module handles extracting values from transaction collections based on
//! variable specifications. It supports:
//! - String key matching (e.g., ARGS:user)
//! - Regex key matching (e.g., ARGS:/user.*/)
//! - Exceptions/negations (e.g., ARGS|!ARGS:id)
//! - Count mode (e.g., &ARGS returns count instead of values)

use regex::Regex;

use crate::collection::MatchData;
use crate::transaction::Transaction;
use crate::types::RuleVariable;

/// Key selector for a rule variable.
///
/// Variables can be selected by:
/// - String literal: `ARGS:username`
/// - Regex pattern: `ARGS:/user.*/`
/// - All keys: `ARGS` (no key specified)
#[derive(Debug, Clone)]
pub enum VariableKey {
    /// Match a specific key (case-sensitive or case-insensitive depending on variable)
    String(String),
    /// Match keys using a regex pattern
    Regex(Regex),
}

/// Exception (negation) for a rule variable.
///
/// Exceptions exclude specific keys from matching. For example:
/// - `ARGS|!ARGS:id` - Match all ARGS except 'id'
/// - `HEADERS|!HEADERS:/cookie.*/` - Match all headers except those matching /cookie.*/
#[derive(Debug, Clone)]
pub struct VariableException {
    /// String key to exclude
    key_str: Option<String>,
    /// Regex pattern to exclude
    key_rx: Option<Regex>,
}

impl VariableException {
    /// Create a new string-based exception.
    pub fn new_string(key: String) -> Self {
        Self {
            key_str: Some(key),
            key_rx: None,
        }
    }

    /// Create a new regex-based exception.
    pub fn new_regex(pattern: Regex) -> Self {
        Self {
            key_str: None,
            key_rx: Some(pattern),
        }
    }

    /// Check if a key matches this exception.
    ///
    /// Keys are compared case-insensitively.
    fn matches(&self, key: &str) -> bool {
        let key_lower = key.to_lowercase();

        if let Some(ref rx) = self.key_rx {
            return rx.is_match(&key_lower);
        }

        if let Some(ref s) = self.key_str {
            return s.to_lowercase() == key_lower;
        }

        false
    }
}

/// Rule variable specification for extracting values from transactions.
///
/// A rule variable specifies what data to extract from a transaction, including:
/// - Which collection to inspect (ARGS, HEADERS, TX, etc.)
/// - Which key(s) to match (literal string, regex, or all)
/// - Which keys to exclude (exceptions)
/// - Whether to return the count instead of values
///
/// # Examples
///
/// ```
/// use coraza::rules::VariableSpec;
/// use coraza::types::RuleVariable;
///
/// // Match all ARGS
/// let var = VariableSpec::new(RuleVariable::Args);
///
/// // Match specific ARGS:username
/// let var = VariableSpec::new_string(RuleVariable::Args, "username".to_string());
///
/// // Count all ARGS
/// let var = VariableSpec::new_count(RuleVariable::Args);
/// ```
#[derive(Debug, Clone)]
pub struct VariableSpec {
    /// The variable collection to inspect
    variable: RuleVariable,

    /// Optional key selector (string or regex)
    key: Option<VariableKey>,

    /// If true, return count instead of values
    count: bool,

    /// List of key exceptions to exclude from matches
    exceptions: Vec<VariableException>,
}

impl VariableSpec {
    /// Create a new rule variable for all keys in a collection.
    pub fn new(variable: RuleVariable) -> Self {
        Self {
            variable,
            key: None,
            count: false,
            exceptions: Vec::new(),
        }
    }

    /// Create a new rule variable with a string key selector.
    pub fn new_string(variable: RuleVariable, key: String) -> Self {
        Self {
            variable,
            key: Some(VariableKey::String(key)),
            count: false,
            exceptions: Vec::new(),
        }
    }

    /// Create a new rule variable with a regex key selector.
    pub fn new_regex(variable: RuleVariable, pattern: Regex) -> Self {
        Self {
            variable,
            key: Some(VariableKey::Regex(pattern)),
            count: false,
            exceptions: Vec::new(),
        }
    }

    /// Create a new rule variable in count mode.
    ///
    /// Count mode returns the number of matching values instead of the values themselves.
    pub fn new_count(variable: RuleVariable) -> Self {
        Self {
            variable,
            key: None,
            count: true,
            exceptions: Vec::new(),
        }
    }

    /// Add a string-based exception to this variable.
    pub fn add_exception_string(&mut self, key: String) {
        self.exceptions.push(VariableException::new_string(key));
    }

    /// Add a regex-based exception to this variable.
    pub fn add_exception_regex(&mut self, pattern: Regex) {
        self.exceptions.push(VariableException::new_regex(pattern));
    }

    /// Enable count mode.
    pub fn set_count(&mut self, count: bool) {
        self.count = count;
    }

    /// Extract values from a transaction based on this variable specification.
    ///
    /// This method:
    /// 1. Gets the collection for this variable from the transaction
    /// 2. Extracts matching keys based on the key selector (string, regex, or all)
    /// 3. Filters out any keys that match exceptions
    /// 4. Returns either the values or the count
    ///
    /// # Arguments
    ///
    /// * `tx` - Transaction to extract values from
    ///
    /// # Returns
    ///
    /// Vector of MatchData containing the matched variable, key, and value.
    /// If count mode is enabled, returns a single MatchData with the count as the value.
    pub fn get_matches(&self, tx: &Transaction) -> Vec<MatchData> {
        // Get the collection for this variable
        let Some(collection) = tx.get_collection(self.variable) else {
            return Vec::new();
        };

        // Extract matches based on key type
        let mut matches = match &self.key {
            Some(VariableKey::Regex(rx)) => {
                // Regex key matching - collection must support Keyed trait
                if let Some(keyed) = collection.as_keyed() {
                    keyed.find_regex(rx)
                } else {
                    Vec::new()
                }
            }
            Some(VariableKey::String(key)) => {
                // String key matching - collection must support Keyed trait
                if let Some(keyed) = collection.as_keyed() {
                    keyed.find_string(key)
                } else {
                    Vec::new()
                }
            }
            None => {
                // No key specified - match all
                collection.find_all()
            }
        };

        // Filter out exceptions
        if !self.exceptions.is_empty() {
            matches.retain(|m| !self.exceptions.iter().any(|ex| ex.matches(&m.key)));
        }

        // Return count or values
        if self.count {
            let count = matches.len();
            let key = match &self.key {
                Some(VariableKey::String(s)) => s.clone(),
                _ => String::new(),
            };

            vec![MatchData::new(self.variable, key, count.to_string())]
        } else {
            matches
        }
    }

    /// Get the variable type.
    pub fn variable(&self) -> RuleVariable {
        self.variable
    }

    /// Check if this variable is in count mode.
    pub fn is_count(&self) -> bool {
        self.count
    }

    /// Get the number of exceptions.
    pub fn exception_count(&self) -> usize {
        self.exceptions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collection::MapCollection;
    use crate::transaction::Transaction;

    // ============================================================================
    // Unit Tests - Basic type functionality
    // ============================================================================

    #[test]
    fn test_variable_key_string() {
        let key = VariableKey::String("username".to_string());
        assert!(matches!(key, VariableKey::String(_)));
    }

    #[test]
    fn test_variable_key_regex() {
        let rx = Regex::new("user.*").unwrap();
        let key = VariableKey::Regex(rx);
        assert!(matches!(key, VariableKey::Regex(_)));
    }

    #[test]
    fn test_exception_string_match() {
        let ex = VariableException::new_string("host".to_string());
        assert!(ex.matches("host"));
        assert!(ex.matches("HOST")); // Case-insensitive
        assert!(ex.matches("HoSt")); // Case-insensitive
        assert!(!ex.matches("hostname"));
    }

    #[test]
    fn test_exception_regex_match() {
        let rx = Regex::new("ho.*").unwrap();
        let ex = VariableException::new_regex(rx);
        assert!(ex.matches("host"));
        assert!(ex.matches("hostname"));
        assert!(!ex.matches("user"));
    }

    #[test]
    fn test_exception_case_insensitive() {
        let ex = VariableException::new_string("Cookie".to_string());
        assert!(ex.matches("cookie"));
        assert!(ex.matches("COOKIE"));
        assert!(ex.matches("Cookie"));
    }

    #[test]
    fn test_variable_spec_new() {
        let var = VariableSpec::new(RuleVariable::Args);
        assert_eq!(var.variable(), RuleVariable::Args);
        assert!(!var.is_count());
        assert_eq!(var.exception_count(), 0);
    }

    #[test]
    fn test_variable_spec_new_string() {
        let var = VariableSpec::new_string(RuleVariable::Args, "username".to_string());
        assert!(matches!(var.key, Some(VariableKey::String(_))));
    }

    #[test]
    fn test_variable_spec_new_regex() {
        let rx = Regex::new("user.*").unwrap();
        let var = VariableSpec::new_regex(RuleVariable::Args, rx);
        assert!(matches!(var.key, Some(VariableKey::Regex(_))));
    }

    #[test]
    fn test_variable_spec_new_count() {
        let var = VariableSpec::new_count(RuleVariable::Args);
        assert!(var.is_count());
    }

    #[test]
    fn test_variable_spec_add_exception_string() {
        let mut var = VariableSpec::new(RuleVariable::Args);
        var.add_exception_string("id".to_string());
        assert_eq!(var.exception_count(), 1);
    }

    #[test]
    fn test_variable_spec_add_exception_regex() {
        let mut var = VariableSpec::new(RuleVariable::Args);
        let rx = Regex::new("id.*").unwrap();
        var.add_exception_regex(rx);
        assert_eq!(var.exception_count(), 1);
    }

    #[test]
    fn test_variable_spec_set_count() {
        let mut var = VariableSpec::new(RuleVariable::Args);
        assert!(!var.is_count());
        var.set_count(true);
        assert!(var.is_count());
        var.set_count(false);
        assert!(!var.is_count());
    }

    // ============================================================================
    // Integration Tests - Variable extraction with Transaction
    // Ported from: coraza/internal/corazawaf/transaction_test.go
    // ============================================================================

    /// Create a test transaction with some sample data.
    ///
    /// Ports the makeTransaction helper from Go tests.
    fn make_transaction() -> Transaction {
        let mut tx = Transaction::new("test-tx");

        // Add request headers (case-insensitive)
        tx.request_headers_mut().add("Host", "www.test.com:80");
        tx.request_headers_mut().add("User-Agent", "Mozilla/5.0");
        tx.request_headers_mut()
            .add("Accept", "text/html,application/json");
        tx.request_headers_mut().add("Accept-Encoding", "gzip");
        tx.request_headers_mut().add("Cookie", "session=abc123");

        // Add GET parameters
        tx.args_get_mut().add("id", "123");
        tx.args_get_mut().add("name", "test");

        tx
    }

    // Ported from: TestTxVariables

    #[test]
    fn test_variable_extraction_regex_key() {
        let tx = make_transaction();

        // Test regex key matching: REQUEST_HEADERS:/ho.*/
        let rx = Regex::new("ho.*").unwrap();
        let var = VariableSpec::new_regex(RuleVariable::RequestHeaders, rx);
        let matches = var.get_matches(&tx);

        // Should match "host" header
        assert_eq!(matches.len(), 1, "expected 1 match for /ho.*/");
        assert_eq!(matches[0].value, "www.test.com:80");
    }

    #[test]
    fn test_variable_extraction_regex_key_count() {
        let tx = make_transaction();

        // Test count mode with regex key
        let rx = Regex::new("ho.*").unwrap();
        let mut var = VariableSpec::new_regex(RuleVariable::RequestHeaders, rx);
        var.set_count(true);
        let matches = var.get_matches(&tx);

        // Should return count as string
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].value, "1");
    }

    #[test]
    fn test_variable_extraction_all_count() {
        let tx = make_transaction();

        // Test count mode without key (count all)
        let var = VariableSpec::new_count(RuleVariable::RequestHeaders);
        let matches = var.get_matches(&tx);

        // Should count all headers
        assert_eq!(matches.len(), 1);
        let count: usize = matches[0].value.parse().unwrap();
        assert_eq!(count, 5, "expected 5 request headers");
    }

    #[test]
    fn test_variable_extraction_string_key() {
        let tx = make_transaction();

        // Test string key matching: ARGS_GET:id
        let var = VariableSpec::new_string(RuleVariable::ArgsGet, "id".to_string());
        let matches = var.get_matches(&tx);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].value, "123");
    }

    #[test]
    fn test_variable_extraction_all_keys() {
        let tx = make_transaction();

        // Test no key (match all): ARGS_GET
        let var = VariableSpec::new(RuleVariable::ArgsGet);
        let matches = var.get_matches(&tx);

        // Should return both id and name
        assert_eq!(matches.len(), 2);

        // Verify both values are present (order may vary)
        let values: Vec<&str> = matches.iter().map(|m| m.value.as_str()).collect();
        assert!(values.contains(&"123"));
        assert!(values.contains(&"test"));
    }

    // Ported from: TestTxVariablesExceptions

    #[test]
    fn test_variable_extraction_string_exception() {
        let tx = make_transaction();

        // Test exception: REQUEST_HEADERS:/ho.*/ but !REQUEST_HEADERS:host
        let rx = Regex::new("ho.*").unwrap();
        let mut var = VariableSpec::new_regex(RuleVariable::RequestHeaders, rx);
        var.add_exception_string("host".to_string());
        let matches = var.get_matches(&tx);

        // Should NOT match because "host" is excepted
        assert_eq!(
            matches.len(),
            0,
            "REQUEST_HEADERS:host should not match due to exception"
        );
    }

    #[test]
    fn test_variable_extraction_regex_exception() {
        let tx = make_transaction();

        // Test regex exception: REQUEST_HEADERS:/ho.*/ but !REQUEST_HEADERS:/ho.*/
        let rx = Regex::new("ho.*").unwrap();
        let mut var = VariableSpec::new_regex(RuleVariable::RequestHeaders, rx.clone());
        var.add_exception_regex(rx);
        let matches = var.get_matches(&tx);

        // Should NOT match because /ho.*/ exception blocks all matches
        assert_eq!(
            matches.len(),
            0,
            "REQUEST_HEADERS:host should not match due to regex exception"
        );
    }

    #[test]
    fn test_variable_extraction_no_exceptions() {
        let tx = make_transaction();

        // Verify that without exceptions, we get matches
        let rx = Regex::new("ho.*").unwrap();
        let var = VariableSpec::new_regex(RuleVariable::RequestHeaders, rx);
        let matches = var.get_matches(&tx);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].value, "www.test.com:80");
    }

    #[test]
    fn test_variable_extraction_case_insensitive_exception() {
        let tx = make_transaction();

        // Test case-insensitive exception matching
        let mut var = VariableSpec::new_string(RuleVariable::RequestHeaders, "host".to_string());
        var.add_exception_string("HOST".to_string()); // Different case
        let matches = var.get_matches(&tx);

        // Should NOT match due to case-insensitive exception matching
        assert_eq!(matches.len(), 0, "Exception should be case-insensitive");
    }

    #[test]
    fn test_variable_extraction_multiple_exceptions() {
        let tx = make_transaction();

        // Test multiple exceptions: ARGS_GET except id and name
        let mut var = VariableSpec::new(RuleVariable::ArgsGet);
        var.add_exception_string("id".to_string());
        var.add_exception_string("name".to_string());
        let matches = var.get_matches(&tx);

        // Should match nothing (both args are excepted)
        assert_eq!(matches.len(), 0, "All args should be excepted");
    }

    #[test]
    fn test_variable_extraction_partial_exceptions() {
        let tx = make_transaction();

        // Test partial exceptions: ARGS_GET except id
        let mut var = VariableSpec::new(RuleVariable::ArgsGet);
        var.add_exception_string("id".to_string());
        let matches = var.get_matches(&tx);

        // Should match only "name"
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].key, "name");
        assert_eq!(matches[0].value, "test");
    }

    #[test]
    fn test_variable_extraction_count_with_exceptions() {
        let tx = make_transaction();

        // Test count mode with exceptions
        let mut var = VariableSpec::new_count(RuleVariable::ArgsGet);
        var.add_exception_string("id".to_string());
        let matches = var.get_matches(&tx);

        // Should count only non-excepted values
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].value, "1"); // Only "name" counted
    }
}
