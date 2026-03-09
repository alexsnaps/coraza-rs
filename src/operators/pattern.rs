// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Pattern matching operators.
//!
//! This module implements operators for regular expression and multi-pattern matching
//! with macro expansion support.

use crate::operators::{Macro, MacroError, Operator, TransactionState};
use aho_corasick::AhoCorasick;
use regex::Regex;

/// Regular expression operator.
///
/// Performs pattern matching using RE2-compatible regular expressions.
/// By default enables dotall mode where `.` matches newlines for compatibility
/// with ModSecurity.
///
/// Supports macro expansion for pattern values.
///
/// Note: This simplified version does not support capturing groups (yet).
///
/// # Examples
///
/// ```
/// use coraza::operators::{NoTx, Operator, rx};
///
/// let op = rx("som(.*)ta").unwrap();
/// assert!(op.evaluate(None::<&NoTx>, "somedata"));
/// assert!(!op.evaluate(None::<&NoTx>, "notdata"));
///
/// // Unicode support
/// let op = rx("ハロー").unwrap();
/// assert!(op.evaluate(None::<&NoTx>, "ハローワールド"));
/// ```
#[derive(Debug, Clone)]
pub struct Rx {
    macro_param: Macro,
    // Cached regex when no macro expansion is needed
    cached_regex: Option<Regex>,
}

impl Operator for Rx {
    fn evaluate<TX: TransactionState>(&self, tx: Option<&TX>, input: &str) -> bool {
        // If we have a cached regex and no transaction state, use the cache
        if tx.is_none()
            && let Some(ref regex) = self.cached_regex
        {
            return regex.is_match(input);
        }

        // Otherwise expand macro and compile regex on the fly
        let pattern = self.macro_param.expand(tx);
        let pattern_with_flags = format!("(?s){}", pattern);

        // If regex compilation fails, return false (no match)
        match Regex::new(&pattern_with_flags) {
            Ok(regex) => regex.is_match(input),
            Err(_) => false,
        }
    }
}

/// Creates a new `rx` operator.
///
/// The pattern is automatically wrapped with `(?s)` to enable dotall mode,
/// where `.` matches newlines (ModSecurity compatibility).
///
/// # Errors
///
/// Returns an error if:
/// - The parameter contains invalid macro syntax
/// - The regex pattern is invalid (when no macros are present)
pub fn rx(pattern: &str) -> Result<Rx, Box<dyn std::error::Error>> {
    let macro_param = Macro::new(pattern)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

    // Try to pre-compile regex if there are no variables
    let cached_regex = if pattern.contains("%{") {
        None
    } else {
        let pattern_with_flags = format!("(?s){}", pattern);
        Some(Regex::new(&pattern_with_flags)?)
    };

    Ok(Rx {
        macro_param,
        cached_regex,
    })
}

/// Phrase matching operator.
///
/// Performs case-insensitive multi-pattern matching using the Aho-Corasick
/// algorithm for efficient substring searching. Matches space-separated
/// keywords or patterns.
///
/// All patterns are matched case-insensitively.
///
/// Supports macro expansion for pattern values.
///
/// # Examples
///
/// ```
/// use coraza::operators::{NoTx, Operator, pm};
///
/// let op = pm("WebZIP WebCopier Webster").unwrap();
/// assert!(op.evaluate(None::<&NoTx>, "User-Agent: WebZIP/1.0"));
/// assert!(op.evaluate(None::<&NoTx>, "WEBZIP is here")); // Case-insensitive
/// assert!(!op.evaluate(None::<&NoTx>, "Mozilla/5.0"));
/// ```
#[derive(Debug, Clone)]
pub struct Pm {
    macro_param: Macro,
    // Cached matcher when no macro expansion is needed
    cached_matcher: Option<AhoCorasick>,
}

impl Operator for Pm {
    fn evaluate<TX: TransactionState>(&self, tx: Option<&TX>, input: &str) -> bool {
        // If we have a cached matcher and no transaction state, use the cache
        if tx.is_none()
            && let Some(ref matcher) = self.cached_matcher
        {
            return matcher.is_match(input);
        }

        // Otherwise expand macro and build matcher on the fly
        let patterns = self.macro_param.expand(tx);
        let patterns_lower = patterns.to_lowercase();
        let dict: Vec<&str> = patterns_lower.split(' ').collect();

        match AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&dict)
        {
            Ok(matcher) => matcher.is_match(input),
            Err(_) => false,
        }
    }
}

/// Creates a new `pm` operator.
///
/// The parameter is a space-separated list of patterns to match.
/// All matching is case-insensitive.
///
/// # Errors
///
/// Returns an error if the parameter contains invalid macro syntax.
pub fn pm(patterns: &str) -> Result<Pm, MacroError> {
    let macro_param = Macro::new(patterns)?;

    // Try to pre-build matcher if there are no variables
    let cached_matcher = if patterns.contains("%{") {
        None
    } else {
        let patterns_lower = patterns.to_lowercase();
        let dict: Vec<&str> = patterns_lower.split(' ').collect();

        AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&dict)
            .ok()
    };

    Ok(Pm {
        macro_param,
        cached_matcher,
    })
}

/// Within operator.
///
/// Returns true if the input value (needle) is found anywhere within the
/// parameter (haystack). This is the inverse of `contains` - it checks if
/// the input is contained in the parameter string.
///
/// Supports macro expansion for parameter values.
///
/// # Examples
///
/// ```
/// use coraza::operators::{NoTx, Operator, within};
///
/// // Check if input is within allowed values
/// let op = within("GET,POST,HEAD").unwrap();
/// assert!(op.evaluate(None::<&NoTx>, "GET"));
/// assert!(op.evaluate(None::<&NoTx>, "POST"));
/// assert!(!op.evaluate(None::<&NoTx>, "DELETE"));
///
/// // Works with any haystack
/// let op = within("abcdefghij").unwrap();
/// assert!(op.evaluate(None::<&NoTx>, "def"));
/// assert!(!op.evaluate(None::<&NoTx>, "xyz"));
/// ```
#[derive(Debug, Clone)]
pub struct Within {
    macro_param: Macro,
}

impl Operator for Within {
    fn evaluate<TX: TransactionState>(&self, tx: Option<&TX>, input: &str) -> bool {
        let haystack = self.macro_param.expand(tx);
        haystack.contains(input)
    }
}

/// Creates a new `within` operator.
///
/// # Errors
///
/// Returns an error if the parameter contains invalid macro syntax.
pub fn within(haystack: &str) -> Result<Within, MacroError> {
    Ok(Within {
        macro_param: Macro::new(haystack)?,
    })
}

/// String match operator.
///
/// Performs case-sensitive substring matching. This is an alias for the
/// `contains` operator, provided for ModSecurity compatibility.
///
/// Supports macro expansion for parameter values.
///
/// # Examples
///
/// ```
/// use coraza::operators::{NoTx, Operator, strmatch};
///
/// let op = strmatch("WebZIP").unwrap();
/// assert!(op.evaluate(None::<&NoTx>, "User-Agent: WebZIP/1.0"));
/// assert!(!op.evaluate(None::<&NoTx>, "User-Agent: webzip")); // Case-sensitive
/// ```
#[derive(Debug, Clone)]
pub struct StrMatch {
    macro_param: Macro,
}

impl Operator for StrMatch {
    fn evaluate<TX: TransactionState>(&self, tx: Option<&TX>, input: &str) -> bool {
        let needle = self.macro_param.expand(tx);
        input.contains(&needle)
    }
}

/// Creates a new `strmatch` operator.
///
/// # Errors
///
/// Returns an error if the parameter contains invalid macro syntax.
pub fn strmatch(pattern: &str) -> Result<StrMatch, MacroError> {
    Ok(StrMatch {
        macro_param: Macro::new(pattern)?,
    })
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::operators::NoTx;
    use crate::types::RuleVariable;

    // Mock transaction state for testing macro expansion
    struct MockTx;

    impl TransactionState for MockTx {
        fn get_variable(&self, variable: RuleVariable, key: Option<&str>) -> Option<String> {
            match (variable, key) {
                (RuleVariable::TX, Some("pattern")) => Some("test.*data".to_string()),
                (RuleVariable::TX, Some("keywords")) => Some("malware virus trojan".to_string()),
                (RuleVariable::TX, Some("methods")) => Some("GET,POST,HEAD".to_string()),
                (RuleVariable::TX, Some("search")) => Some("admin".to_string()),
                _ => None,
            }
        }
    }

    #[test]
    fn test_rx_basic() {
        let op = rx("som(.*)ta").unwrap();
        assert!(op.evaluate(None::<&NoTx>, "somedata"));
        assert!(!op.evaluate(None::<&NoTx>, "notdata"));
    }

    #[test]
    fn test_rx_unicode() {
        let op = rx("ハロー").unwrap();
        assert!(op.evaluate(None::<&NoTx>, "ハローワールド"));
        assert!(!op.evaluate(None::<&NoTx>, "グッバイワールド"));
    }

    #[test]
    fn test_rx_dotall_mode() {
        // Dotall mode enabled by default - . matches newlines
        let op = rx("hello.*world").unwrap();
        assert!(op.evaluate(None::<&NoTx>, "hello\nworld"));
        assert!(op.evaluate(None::<&NoTx>, "hello world"));
    }

    #[test]
    fn test_rx_case_sensitive() {
        let op = rx("test").unwrap();
        assert!(op.evaluate(None::<&NoTx>, "test"));
        assert!(!op.evaluate(None::<&NoTx>, "TEST"));

        // Case-insensitive with flag
        let op = rx("(?i)test").unwrap();
        assert!(op.evaluate(None::<&NoTx>, "test"));
        assert!(op.evaluate(None::<&NoTx>, "TEST"));
    }

    #[test]
    fn test_rx_anchors() {
        let op = rx("^GET").unwrap();
        assert!(op.evaluate(None::<&NoTx>, "GET /index.html"));
        assert!(!op.evaluate(None::<&NoTx>, " GET /index.html"));

        let op = rx("\\.php$").unwrap();
        assert!(op.evaluate(None::<&NoTx>, "/index.php"));
        assert!(!op.evaluate(None::<&NoTx>, "/index.php?id=1"));
    }

    #[test]
    fn test_rx_invalid_pattern() {
        assert!(rx("(unclosed").is_err());
        assert!(rx("[unclosed").is_err());
    }

    #[test]
    fn test_rx_with_macro() {
        let op = rx("%{TX.pattern}").unwrap();
        let tx = MockTx;

        assert!(op.evaluate(Some(&tx), "testXYZdata"));
        assert!(op.evaluate(Some(&tx), "test123data"));
        assert!(!op.evaluate(Some(&tx), "notmatching"));
    }

    #[test]
    fn test_pm_basic() {
        let op = pm("WebZIP WebCopier Webster").unwrap();
        assert!(op.evaluate(None::<&NoTx>, "User-Agent: WebZIP/1.0"));
        assert!(op.evaluate(None::<&NoTx>, "WebCopier tool"));
        assert!(op.evaluate(None::<&NoTx>, "Webster here"));
        assert!(!op.evaluate(None::<&NoTx>, "Mozilla/5.0"));
    }

    #[test]
    fn test_pm_case_insensitive() {
        let op = pm("WebZIP").unwrap();
        assert!(op.evaluate(None::<&NoTx>, "WEBZIP"));
        assert!(op.evaluate(None::<&NoTx>, "webzip"));
        assert!(op.evaluate(None::<&NoTx>, "WebZIP"));
        assert!(op.evaluate(None::<&NoTx>, "WeBzIp"));
    }

    #[test]
    fn test_pm_multiple_matches() {
        let op = pm("<script> javascript: onerror=").unwrap();
        assert!(op.evaluate(None::<&NoTx>, "<script>alert(1)</script>"));
        assert!(op.evaluate(None::<&NoTx>, "javascript:void(0)"));
        assert!(op.evaluate(None::<&NoTx>, "<img onerror=alert(1)>"));
    }

    #[test]
    fn test_pm_single_pattern() {
        let op = pm("malware").unwrap();
        assert!(op.evaluate(None::<&NoTx>, "this is malware"));
        assert!(!op.evaluate(None::<&NoTx>, "this is safe"));
    }

    #[test]
    fn test_pm_empty_pattern() {
        let op = pm("").unwrap();
        // Empty pattern matches empty string in input
        assert!(op.evaluate(None::<&NoTx>, "anything"));
    }

    #[test]
    fn test_pm_with_macro() {
        let op = pm("%{TX.keywords}").unwrap();
        let tx = MockTx;

        assert!(op.evaluate(Some(&tx), "detected malware here"));
        assert!(op.evaluate(Some(&tx), "virus found"));
        assert!(op.evaluate(Some(&tx), "trojan detected"));
        assert!(!op.evaluate(Some(&tx), "clean file"));
    }

    #[test]
    fn test_within_basic() {
        let op = within("GET,POST,HEAD").unwrap();
        assert!(op.evaluate(None::<&NoTx>, "GET"));
        assert!(op.evaluate(None::<&NoTx>, "POST"));
        assert!(op.evaluate(None::<&NoTx>, "HEAD"));
        assert!(!op.evaluate(None::<&NoTx>, "DELETE"));
        assert!(!op.evaluate(None::<&NoTx>, "PUT"));
    }

    #[test]
    fn test_within_substring() {
        let op = within("abcdefghij").unwrap();
        assert!(op.evaluate(None::<&NoTx>, "abc"));
        assert!(op.evaluate(None::<&NoTx>, "def"));
        assert!(op.evaluate(None::<&NoTx>, "j"));
        assert!(!op.evaluate(None::<&NoTx>, "xyz"));
    }

    #[test]
    fn test_within_exact_match() {
        let op = within("exact").unwrap();
        assert!(op.evaluate(None::<&NoTx>, "exact"));
        assert!(!op.evaluate(None::<&NoTx>, "not exact"));
    }

    #[test]
    fn test_within_empty_input() {
        let op = within("GET,POST").unwrap();
        assert!(op.evaluate(None::<&NoTx>, "")); // Empty string is in any string
    }

    #[test]
    fn test_within_case_sensitive() {
        let op = within("GET,POST").unwrap();
        assert!(op.evaluate(None::<&NoTx>, "GET"));
        assert!(!op.evaluate(None::<&NoTx>, "get")); // Case-sensitive
    }

    #[test]
    fn test_within_with_macro() {
        let op = within("%{TX.methods}").unwrap();
        let tx = MockTx;

        assert!(op.evaluate(Some(&tx), "GET"));
        assert!(op.evaluate(Some(&tx), "POST"));
        assert!(!op.evaluate(Some(&tx), "DELETE"));
    }

    #[test]
    fn test_strmatch_basic() {
        let op = strmatch("WebZIP").unwrap();
        assert!(op.evaluate(None::<&NoTx>, "User-Agent: WebZIP/1.0"));
        assert!(op.evaluate(None::<&NoTx>, "WebZIP"));
    }

    #[test]
    fn test_strmatch_case_sensitive() {
        let op = strmatch("WebZIP").unwrap();
        assert!(op.evaluate(None::<&NoTx>, "WebZIP"));
        assert!(!op.evaluate(None::<&NoTx>, "webzip")); // Case-sensitive
    }

    #[test]
    fn test_strmatch_path_traversal() {
        let op = strmatch("../../../").unwrap();
        assert!(op.evaluate(None::<&NoTx>, "GET /../../../etc/passwd"));
        assert!(!op.evaluate(None::<&NoTx>, "GET /index.html"));
    }

    #[test]
    fn test_strmatch_with_macro() {
        let op = strmatch("%{TX.search}").unwrap();
        let tx = MockTx;

        assert!(op.evaluate(Some(&tx), "/admin/login"));
        assert!(op.evaluate(Some(&tx), "administrator"));
        assert!(!op.evaluate(Some(&tx), "/user/profile"));
    }

    #[test]
    fn test_operator_constructor_with_invalid_macro() {
        // Empty parameters are allowed (macros accept empty strings)
        assert!(pm("").is_ok());
        assert!(within("").is_ok());
        assert!(strmatch("").is_ok());

        // Malformed macro
        assert!(pm("%{TX.").is_err());
        assert!(within("%{").is_err());
        assert!(strmatch("%{unknown_var}").is_err());
    }
}
