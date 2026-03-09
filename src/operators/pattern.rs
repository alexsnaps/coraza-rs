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
/// assert!(op.evaluate(None::<&mut NoTx>, "somedata"));
/// assert!(!op.evaluate(None::<&mut NoTx>, "notdata"));
///
/// // Unicode support
/// let op = rx("ハロー").unwrap();
/// assert!(op.evaluate(None::<&mut NoTx>, "ハローワールド"));
/// ```
#[derive(Debug, Clone)]
pub struct Rx {
    macro_param: Macro,
    // Cached regex when no macro expansion is needed
    cached_regex: Option<Regex>,
}

impl Operator for Rx {
    fn evaluate<TX: TransactionState>(&self, tx: Option<&mut TX>, input: &str) -> bool {
        // Determine if we're capturing based on transaction state
        let capturing = tx.as_ref().is_some_and(|t| t.capturing());

        // Fast path: use cached regex when available and no macro expansion needed
        if tx.is_none()
            && let Some(ref regex) = self.cached_regex
        {
            return regex.is_match(input);
        }

        // Expand macro if needed and compile regex
        let pattern = self.macro_param.expand(tx.as_deref());
        let pattern_with_flags = format!("(?s){}", pattern);

        let regex = match Regex::new(&pattern_with_flags) {
            Ok(re) => re,
            Err(_) => return false,
        };

        if capturing {
            // Capturing mode: find all matches including groups
            if let Some(captures) = regex.captures(input) {
                if let Some(tx_mut) = tx {
                    // Store full match and up to 9 capturing groups (ModSecurity limit)
                    for i in 0..=9 {
                        if let Some(capture) = captures.get(i) {
                            tx_mut.capture_field(i, capture.as_str());
                        } else {
                            break;
                        }
                    }
                }
                true
            } else {
                false
            }
        } else {
            // Non-capturing mode: fast path using is_match
            regex.is_match(input)
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
    let macro_param = Macro::new(pattern).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

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
/// assert!(op.evaluate(None::<&mut NoTx>, "User-Agent: WebZIP/1.0"));
/// assert!(op.evaluate(None::<&mut NoTx>, "WEBZIP is here")); // Case-insensitive
/// assert!(!op.evaluate(None::<&mut NoTx>, "Mozilla/5.0"));
/// ```
#[derive(Debug, Clone)]
pub struct Pm {
    macro_param: Macro,
    // Cached matcher when no macro expansion is needed
    cached_matcher: Option<AhoCorasick>,
}

impl Operator for Pm {
    fn evaluate<TX: TransactionState>(&self, mut tx: Option<&mut TX>, input: &str) -> bool {
        // Determine if we're capturing based on transaction state
        let capturing = tx.as_ref().is_some_and(|t| t.capturing());

        // If we have a cached matcher and no transaction state, use the cache
        if tx.is_none()
            && let Some(ref matcher) = self.cached_matcher
        {
            return matcher.is_match(input);
        }

        // Otherwise expand macro and build matcher on the fly
        let patterns = self.macro_param.expand(tx.as_deref());
        let patterns_lower = patterns.to_lowercase();
        let dict: Vec<&str> = patterns_lower.split(' ').collect();

        let matcher = match AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&dict)
        {
            Ok(m) => m,
            Err(_) => return false,
        };

        if capturing {
            // Capturing mode: collect all matches up to limit of 10
            let mut num_matches = 0;
            for mat in matcher.find_iter(input) {
                if let Some(ref mut tx_mut) = tx {
                    tx_mut.capture_field(num_matches, &input[mat.start()..mat.end()]);
                }
                num_matches += 1;
                if num_matches == 10 {
                    return true;
                }
            }
            num_matches > 0
        } else {
            // Fast path: just check if there's any match
            matcher.is_match(input)
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
/// assert!(op.evaluate(None::<&mut NoTx>, "GET"));
/// assert!(op.evaluate(None::<&mut NoTx>, "POST"));
/// assert!(!op.evaluate(None::<&mut NoTx>, "DELETE"));
///
/// // Works with any haystack
/// let op = within("abcdefghij").unwrap();
/// assert!(op.evaluate(None::<&mut NoTx>, "def"));
/// assert!(!op.evaluate(None::<&mut NoTx>, "xyz"));
/// ```
#[derive(Debug, Clone)]
pub struct Within {
    macro_param: Macro,
}

impl Operator for Within {
    fn evaluate<TX: TransactionState>(&self, tx: Option<&mut TX>, input: &str) -> bool {
        let haystack = self.macro_param.expand(tx.as_deref());
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
/// assert!(op.evaluate(None::<&mut NoTx>, "User-Agent: WebZIP/1.0"));
/// assert!(!op.evaluate(None::<&mut NoTx>, "User-Agent: webzip")); // Case-sensitive
/// ```
#[derive(Debug, Clone)]
pub struct StrMatch {
    macro_param: Macro,
}

impl Operator for StrMatch {
    fn evaluate<TX: TransactionState>(&self, tx: Option<&mut TX>, input: &str) -> bool {
        let needle = self.macro_param.expand(tx.as_deref());
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
        assert!(op.evaluate(None::<&mut NoTx>, "somedata"));
        assert!(!op.evaluate(None::<&mut NoTx>, "notdata"));
    }

    #[test]
    fn test_rx_unicode() {
        let op = rx("ハロー").unwrap();
        assert!(op.evaluate(None::<&mut NoTx>, "ハローワールド"));
        assert!(!op.evaluate(None::<&mut NoTx>, "グッバイワールド"));
    }

    #[test]
    fn test_rx_dotall_mode() {
        // Dotall mode enabled by default - . matches newlines
        let op = rx("hello.*world").unwrap();
        assert!(op.evaluate(None::<&mut NoTx>, "hello\nworld"));
        assert!(op.evaluate(None::<&mut NoTx>, "hello world"));
    }

    #[test]
    fn test_rx_case_sensitive() {
        let op = rx("test").unwrap();
        assert!(op.evaluate(None::<&mut NoTx>, "test"));
        assert!(!op.evaluate(None::<&mut NoTx>, "TEST"));

        // Case-insensitive with flag
        let op = rx("(?i)test").unwrap();
        assert!(op.evaluate(None::<&mut NoTx>, "test"));
        assert!(op.evaluate(None::<&mut NoTx>, "TEST"));
    }

    #[test]
    fn test_rx_anchors() {
        let op = rx("^GET").unwrap();
        assert!(op.evaluate(None::<&mut NoTx>, "GET /index.html"));
        assert!(!op.evaluate(None::<&mut NoTx>, " GET /index.html"));

        let op = rx("\\.php$").unwrap();
        assert!(op.evaluate(None::<&mut NoTx>, "/index.php"));
        assert!(!op.evaluate(None::<&mut NoTx>, "/index.php?id=1"));
    }

    #[test]
    fn test_rx_invalid_pattern() {
        assert!(rx("(unclosed").is_err());
        assert!(rx("[unclosed").is_err());
    }

    #[test]
    fn test_rx_with_macro() {
        let op = rx("%{TX.pattern}").unwrap();
        let mut tx = MockTx;

        assert!(op.evaluate(Some(&mut tx), "testXYZdata"));
        assert!(op.evaluate(Some(&mut tx), "test123data"));
        assert!(!op.evaluate(Some(&mut tx), "notmatching"));
    }

    #[test]
    fn test_pm_basic() {
        let op = pm("WebZIP WebCopier Webster").unwrap();
        assert!(op.evaluate(None::<&mut NoTx>, "User-Agent: WebZIP/1.0"));
        assert!(op.evaluate(None::<&mut NoTx>, "WebCopier tool"));
        assert!(op.evaluate(None::<&mut NoTx>, "Webster here"));
        assert!(!op.evaluate(None::<&mut NoTx>, "Mozilla/5.0"));
    }

    #[test]
    fn test_pm_case_insensitive() {
        let op = pm("WebZIP").unwrap();
        assert!(op.evaluate(None::<&mut NoTx>, "WEBZIP"));
        assert!(op.evaluate(None::<&mut NoTx>, "webzip"));
        assert!(op.evaluate(None::<&mut NoTx>, "WebZIP"));
        assert!(op.evaluate(None::<&mut NoTx>, "WeBzIp"));
    }

    #[test]
    fn test_pm_multiple_matches() {
        let op = pm("<script> javascript: onerror=").unwrap();
        assert!(op.evaluate(None::<&mut NoTx>, "<script>alert(1)</script>"));
        assert!(op.evaluate(None::<&mut NoTx>, "javascript:void(0)"));
        assert!(op.evaluate(None::<&mut NoTx>, "<img onerror=alert(1)>"));
    }

    #[test]
    fn test_pm_single_pattern() {
        let op = pm("malware").unwrap();
        assert!(op.evaluate(None::<&mut NoTx>, "this is malware"));
        assert!(!op.evaluate(None::<&mut NoTx>, "this is safe"));
    }

    #[test]
    fn test_pm_empty_pattern() {
        let op = pm("").unwrap();
        // Empty pattern matches empty string in input
        assert!(op.evaluate(None::<&mut NoTx>, "anything"));
    }

    #[test]
    fn test_pm_with_macro() {
        let op = pm("%{TX.keywords}").unwrap();
        let mut tx = MockTx;

        assert!(op.evaluate(Some(&mut tx), "detected malware here"));
        assert!(op.evaluate(Some(&mut tx), "virus found"));
        assert!(op.evaluate(Some(&mut tx), "trojan detected"));
        assert!(!op.evaluate(Some(&mut tx), "clean file"));
    }

    #[test]
    fn test_within_basic() {
        let op = within("GET,POST,HEAD").unwrap();
        assert!(op.evaluate(None::<&mut NoTx>, "GET"));
        assert!(op.evaluate(None::<&mut NoTx>, "POST"));
        assert!(op.evaluate(None::<&mut NoTx>, "HEAD"));
        assert!(!op.evaluate(None::<&mut NoTx>, "DELETE"));
        assert!(!op.evaluate(None::<&mut NoTx>, "PUT"));
    }

    #[test]
    fn test_within_substring() {
        let op = within("abcdefghij").unwrap();
        assert!(op.evaluate(None::<&mut NoTx>, "abc"));
        assert!(op.evaluate(None::<&mut NoTx>, "def"));
        assert!(op.evaluate(None::<&mut NoTx>, "j"));
        assert!(!op.evaluate(None::<&mut NoTx>, "xyz"));
    }

    #[test]
    fn test_within_exact_match() {
        let op = within("exact").unwrap();
        assert!(op.evaluate(None::<&mut NoTx>, "exact"));
        assert!(!op.evaluate(None::<&mut NoTx>, "not exact"));
    }

    #[test]
    fn test_within_empty_input() {
        let op = within("GET,POST").unwrap();
        assert!(op.evaluate(None::<&mut NoTx>, "")); // Empty string is in any string
    }

    #[test]
    fn test_within_case_sensitive() {
        let op = within("GET,POST").unwrap();
        assert!(op.evaluate(None::<&mut NoTx>, "GET"));
        assert!(!op.evaluate(None::<&mut NoTx>, "get")); // Case-sensitive
    }

    #[test]
    fn test_within_with_macro() {
        let op = within("%{TX.methods}").unwrap();
        let mut tx = MockTx;

        assert!(op.evaluate(Some(&mut tx), "GET"));
        assert!(op.evaluate(Some(&mut tx), "POST"));
        assert!(!op.evaluate(Some(&mut tx), "DELETE"));
    }

    #[test]
    fn test_strmatch_basic() {
        let op = strmatch("WebZIP").unwrap();
        assert!(op.evaluate(None::<&mut NoTx>, "User-Agent: WebZIP/1.0"));
        assert!(op.evaluate(None::<&mut NoTx>, "WebZIP"));
    }

    #[test]
    fn test_strmatch_case_sensitive() {
        let op = strmatch("WebZIP").unwrap();
        assert!(op.evaluate(None::<&mut NoTx>, "WebZIP"));
        assert!(!op.evaluate(None::<&mut NoTx>, "webzip")); // Case-sensitive
    }

    #[test]
    fn test_strmatch_path_traversal() {
        let op = strmatch("../../../").unwrap();
        assert!(op.evaluate(None::<&mut NoTx>, "GET /../../../etc/passwd"));
        assert!(!op.evaluate(None::<&mut NoTx>, "GET /index.html"));
    }

    #[test]
    fn test_strmatch_with_macro() {
        let op = strmatch("%{TX.search}").unwrap();
        let mut tx = MockTx;

        assert!(op.evaluate(Some(&mut tx), "/admin/login"));
        assert!(op.evaluate(Some(&mut tx), "administrator"));
        assert!(!op.evaluate(Some(&mut tx), "/user/profile"));
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

    // Mock transaction with capturing support
    struct CapturingTx {
        captures: std::cell::RefCell<Vec<String>>,
    }

    impl CapturingTx {
        fn new() -> Self {
            Self {
                captures: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn get_capture(&self, index: usize) -> Option<String> {
            self.captures.borrow().get(index).cloned()
        }
    }

    impl TransactionState for CapturingTx {
        fn get_variable(&self, _variable: RuleVariable, _key: Option<&str>) -> Option<String> {
            None
        }

        fn capturing(&self) -> bool {
            true
        }

        fn capture_field(&mut self, index: usize, value: &str) {
            let mut caps = self.captures.borrow_mut();
            // Extend vector if needed
            while caps.len() <= index {
                caps.push(String::new());
            }
            caps[index] = value.to_string();
        }
    }

    #[test]
    fn test_rx_capturing_basic() {
        let op = rx("(\\w+)@(\\w+)\\.com").unwrap();
        let mut tx = CapturingTx::new();

        assert!(op.evaluate(Some(&mut tx), "user@example.com"));

        // Check captured groups
        assert_eq!(tx.get_capture(0), Some("user@example.com".to_string())); // Full match
        assert_eq!(tx.get_capture(1), Some("user".to_string())); // Group 1
        assert_eq!(tx.get_capture(2), Some("example".to_string())); // Group 2
    }

    #[test]
    fn test_rx_capturing_multiple_groups() {
        let op = rx("(\\d{3})-(\\d{3})-(\\d{4})").unwrap();
        let mut tx = CapturingTx::new();

        assert!(op.evaluate(Some(&mut tx), "123-456-7890"));

        // Check all groups
        assert_eq!(tx.get_capture(0), Some("123-456-7890".to_string()));
        assert_eq!(tx.get_capture(1), Some("123".to_string()));
        assert_eq!(tx.get_capture(2), Some("456".to_string()));
        assert_eq!(tx.get_capture(3), Some("7890".to_string()));
    }

    #[test]
    fn test_rx_capturing_nine_groups() {
        // Test ModSecurity's 9-group limit
        let op = rx("(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)").unwrap();
        let mut tx = CapturingTx::new();

        assert!(op.evaluate(Some(&mut tx), "abcdefghij"));

        // Check full match and first 9 groups
        assert_eq!(tx.get_capture(0), Some("abcdefghij".to_string()));
        assert_eq!(tx.get_capture(1), Some("a".to_string()));
        assert_eq!(tx.get_capture(2), Some("b".to_string()));
        assert_eq!(tx.get_capture(3), Some("c".to_string()));
        assert_eq!(tx.get_capture(4), Some("d".to_string()));
        assert_eq!(tx.get_capture(5), Some("e".to_string()));
        assert_eq!(tx.get_capture(6), Some("f".to_string()));
        assert_eq!(tx.get_capture(7), Some("g".to_string()));
        assert_eq!(tx.get_capture(8), Some("h".to_string()));
        assert_eq!(tx.get_capture(9), Some("i".to_string()));

        // 10th group should not be captured (ModSecurity limit)
        assert_eq!(tx.get_capture(10), None);
    }

    #[test]
    fn test_rx_no_match_with_capturing() {
        let op = rx("test(\\d+)").unwrap();
        let mut tx = CapturingTx::new();

        assert!(!op.evaluate(Some(&mut tx), "nodigits"));

        // No captures should be stored
        assert_eq!(tx.get_capture(0), None);
    }

    #[test]
    fn test_rx_capturing_disabled() {
        // Mock transaction that doesn't enable capturing
        struct NonCapturingTx;

        impl TransactionState for NonCapturingTx {
            fn get_variable(&self, _variable: RuleVariable, _key: Option<&str>) -> Option<String> {
                None
            }

            fn capturing(&self) -> bool {
                false
            }
        }

        let op = rx("(test)").unwrap();
        let mut tx = NonCapturingTx;

        // Should still match, but won't capture
        assert!(op.evaluate(Some(&mut tx), "test"));
    }

    #[test]
    fn test_pm_capturing_basic() {
        let op = pm("admin sql script").unwrap();
        let mut tx = CapturingTx::new();

        assert!(op.evaluate(Some(&mut tx), "This script contains admin panel"));

        // PM captures each matched pattern (not groups within a pattern)
        // Note: order depends on which patterns are found first in the input
        assert_eq!(tx.get_capture(0), Some("script".to_string())); // First match
        assert_eq!(tx.get_capture(1), Some("admin".to_string())); // Second match
    }

    #[test]
    fn test_pm_capturing_single_match() {
        let op = pm("malware virus trojan").unwrap();
        let mut tx = CapturingTx::new();

        assert!(op.evaluate(Some(&mut tx), "detected malware in file"));

        // Only one pattern matched
        assert_eq!(tx.get_capture(0), Some("malware".to_string()));
        assert_eq!(tx.get_capture(1), None);
    }

    #[test]
    fn test_pm_capturing_ten_matches() {
        // Test the 10-match limit
        let op = pm("a b c d e f g h i j k").unwrap();
        let mut tx = CapturingTx::new();

        assert!(op.evaluate(Some(&mut tx), "a b c d e f g h i j k"));

        // Should capture first 10 matches
        for i in 0..10 {
            assert!(tx.get_capture(i).is_some());
        }
        // 11th match should not be captured
        assert_eq!(tx.get_capture(10), None);
    }

    #[test]
    fn test_pm_capturing_case_insensitive() {
        let op = pm("admin").unwrap();
        let mut tx = CapturingTx::new();

        assert!(op.evaluate(Some(&mut tx), "ADMIN panel"));

        // Should capture the actual matched text (preserving case from input)
        assert_eq!(tx.get_capture(0), Some("ADMIN".to_string()));
    }

    #[test]
    fn test_pm_no_match_with_capturing() {
        let op = pm("malware virus").unwrap();
        let mut tx = CapturingTx::new();

        assert!(!op.evaluate(Some(&mut tx), "clean file"));

        // No captures should be stored
        assert_eq!(tx.get_capture(0), None);
    }

    #[test]
    fn test_pm_capturing_disabled() {
        struct NonCapturingTx;

        impl TransactionState for NonCapturingTx {
            fn get_variable(&self, _variable: RuleVariable, _key: Option<&str>) -> Option<String> {
                None
            }

            fn capturing(&self) -> bool {
                false
            }
        }

        let op = pm("admin").unwrap();
        let mut tx = NonCapturingTx;

        // Should still match, but won't capture
        assert!(op.evaluate(Some(&mut tx), "admin panel"));
    }
}
