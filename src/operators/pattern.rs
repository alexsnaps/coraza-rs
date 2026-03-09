// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Pattern matching operators.
//!
//! This module implements operators for regular expression and multi-pattern matching.

use crate::operators::Operator;
use aho_corasick::AhoCorasick;
use regex::Regex;

/// Regular expression operator.
///
/// Performs pattern matching using RE2-compatible regular expressions.
/// By default enables dotall mode where `.` matches newlines for compatibility
/// with ModSecurity.
///
/// Note: This simplified version does not support capturing groups (yet).
///
/// # Examples
///
/// ```
/// use coraza::operators::{Operator, rx};
///
/// let op = rx("som(.*)ta").unwrap();
/// assert!(op.evaluate("somedata"));
/// assert!(!op.evaluate("notdata"));
///
/// // Unicode support
/// let op = rx("ハロー").unwrap();
/// assert!(op.evaluate("ハローワールド"));
/// ```
#[derive(Debug, Clone)]
pub struct Rx {
    regex: Regex,
}

impl Operator for Rx {
    fn evaluate(&self, input: &str) -> bool {
        self.regex.is_match(input)
    }
}

/// Creates a new `rx` operator.
///
/// The pattern is automatically wrapped with `(?s)` to enable dotall mode,
/// where `.` matches newlines (ModSecurity compatibility).
///
/// # Errors
///
/// Returns an error if the regex pattern is invalid.
pub fn rx(pattern: &str) -> Result<Rx, regex::Error> {
    // Enable dotall mode (?s) by default for ModSecurity compatibility
    let pattern_with_flags = format!("(?s){}", pattern);
    let regex = Regex::new(&pattern_with_flags)?;
    Ok(Rx { regex })
}

/// Phrase matching operator.
///
/// Performs case-insensitive multi-pattern matching using the Aho-Corasick
/// algorithm for efficient substring searching. Matches space-separated
/// keywords or patterns.
///
/// All patterns are matched case-insensitively.
///
/// # Examples
///
/// ```
/// use coraza::operators::{Operator, pm};
///
/// let op = pm("WebZIP WebCopier Webster");
/// assert!(op.evaluate("User-Agent: WebZIP/1.0"));
/// assert!(op.evaluate("WEBZIP is here")); // Case-insensitive
/// assert!(!op.evaluate("Mozilla/5.0"));
/// ```
#[derive(Debug, Clone)]
pub struct Pm {
    matcher: AhoCorasick,
}

impl Operator for Pm {
    fn evaluate(&self, input: &str) -> bool {
        self.matcher.is_match(input)
    }
}

/// Creates a new `pm` operator.
///
/// The parameter is a space-separated list of patterns to match.
/// All matching is case-insensitive.
pub fn pm(patterns: &str) -> Pm {
    let patterns_lower = patterns.to_lowercase();
    let dict: Vec<&str> = patterns_lower.split(' ').collect();

    let matcher = AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(&dict)
        .expect("Failed to build Aho-Corasick matcher");

    Pm { matcher }
}

/// Within operator.
///
/// Returns true if the input value (needle) is found anywhere within the
/// parameter (haystack). This is the inverse of `contains` - it checks if
/// the input is contained in the parameter string.
///
/// # Examples
///
/// ```
/// use coraza::operators::{Operator, within};
///
/// // Check if input is within allowed values
/// let op = within("GET,POST,HEAD");
/// assert!(op.evaluate("GET"));
/// assert!(op.evaluate("POST"));
/// assert!(!op.evaluate("DELETE"));
///
/// // Works with any haystack
/// let op = within("abcdefghij");
/// assert!(op.evaluate("def"));
/// assert!(!op.evaluate("xyz"));
/// ```
#[derive(Debug, Clone)]
pub struct Within {
    haystack: String,
}

impl Operator for Within {
    fn evaluate(&self, input: &str) -> bool {
        self.haystack.contains(input)
    }
}

/// Creates a new `within` operator.
pub fn within(haystack: &str) -> Within {
    Within {
        haystack: haystack.to_string(),
    }
}

/// String match operator.
///
/// Performs case-sensitive substring matching. This is an alias for the
/// `contains` operator, provided for ModSecurity compatibility.
///
/// # Examples
///
/// ```
/// use coraza::operators::{Operator, strmatch};
///
/// let op = strmatch("WebZIP");
/// assert!(op.evaluate("User-Agent: WebZIP/1.0"));
/// assert!(!op.evaluate("User-Agent: webzip")); // Case-sensitive
/// ```
#[derive(Debug, Clone)]
pub struct StrMatch {
    needle: String,
}

impl Operator for StrMatch {
    fn evaluate(&self, input: &str) -> bool {
        input.contains(&self.needle)
    }
}

/// Creates a new `strmatch` operator.
pub fn strmatch(pattern: &str) -> StrMatch {
    StrMatch {
        needle: pattern.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rx_basic() {
        let op = rx("som(.*)ta").unwrap();
        assert!(op.evaluate("somedata"));
        assert!(!op.evaluate("notdata"));
    }

    #[test]
    fn test_rx_unicode() {
        let op = rx("ハロー").unwrap();
        assert!(op.evaluate("ハローワールド"));
        assert!(!op.evaluate("グッバイワールド"));
    }

    #[test]
    fn test_rx_dotall_mode() {
        // Dotall mode enabled by default - . matches newlines
        let op = rx("hello.*world").unwrap();
        assert!(op.evaluate("hello\nworld"));
        assert!(op.evaluate("hello world"));
    }

    #[test]
    fn test_rx_case_sensitive() {
        let op = rx("test").unwrap();
        assert!(op.evaluate("test"));
        assert!(!op.evaluate("TEST"));

        // Case-insensitive with flag
        let op = rx("(?i)test").unwrap();
        assert!(op.evaluate("test"));
        assert!(op.evaluate("TEST"));
    }

    #[test]
    fn test_rx_anchors() {
        let op = rx("^GET").unwrap();
        assert!(op.evaluate("GET /index.html"));
        assert!(!op.evaluate(" GET /index.html"));

        let op = rx("\\.php$").unwrap();
        assert!(op.evaluate("/index.php"));
        assert!(!op.evaluate("/index.php?id=1"));
    }

    #[test]
    fn test_rx_invalid_pattern() {
        assert!(rx("(unclosed").is_err());
        assert!(rx("[unclosed").is_err());
    }

    #[test]
    fn test_pm_basic() {
        let op = pm("WebZIP WebCopier Webster");
        assert!(op.evaluate("User-Agent: WebZIP/1.0"));
        assert!(op.evaluate("WebCopier tool"));
        assert!(op.evaluate("Webster here"));
        assert!(!op.evaluate("Mozilla/5.0"));
    }

    #[test]
    fn test_pm_case_insensitive() {
        let op = pm("WebZIP");
        assert!(op.evaluate("WEBZIP"));
        assert!(op.evaluate("webzip"));
        assert!(op.evaluate("WebZIP"));
        assert!(op.evaluate("WeBzIp"));
    }

    #[test]
    fn test_pm_multiple_matches() {
        let op = pm("<script> javascript: onerror=");
        assert!(op.evaluate("<script>alert(1)</script>"));
        assert!(op.evaluate("javascript:void(0)"));
        assert!(op.evaluate("<img onerror=alert(1)>"));
    }

    #[test]
    fn test_pm_single_pattern() {
        let op = pm("malware");
        assert!(op.evaluate("this is malware"));
        assert!(!op.evaluate("this is safe"));
    }

    #[test]
    fn test_pm_empty_pattern() {
        let op = pm("");
        // Empty pattern matches empty string in input
        assert!(op.evaluate("anything"));
    }

    #[test]
    fn test_within_basic() {
        let op = within("GET,POST,HEAD");
        assert!(op.evaluate("GET"));
        assert!(op.evaluate("POST"));
        assert!(op.evaluate("HEAD"));
        assert!(!op.evaluate("DELETE"));
        assert!(!op.evaluate("PUT"));
    }

    #[test]
    fn test_within_substring() {
        let op = within("abcdefghij");
        assert!(op.evaluate("abc"));
        assert!(op.evaluate("def"));
        assert!(op.evaluate("j"));
        assert!(!op.evaluate("xyz"));
    }

    #[test]
    fn test_within_exact_match() {
        let op = within("exact");
        assert!(op.evaluate("exact"));
        assert!(!op.evaluate("not exact"));
    }

    #[test]
    fn test_within_empty_input() {
        let op = within("GET,POST");
        assert!(op.evaluate("")); // Empty string is in any string
    }

    #[test]
    fn test_within_case_sensitive() {
        let op = within("GET,POST");
        assert!(op.evaluate("GET"));
        assert!(!op.evaluate("get")); // Case-sensitive
    }

    #[test]
    fn test_strmatch_basic() {
        let op = strmatch("WebZIP");
        assert!(op.evaluate("User-Agent: WebZIP/1.0"));
        assert!(op.evaluate("WebZIP"));
    }

    #[test]
    fn test_strmatch_case_sensitive() {
        let op = strmatch("WebZIP");
        assert!(op.evaluate("WebZIP"));
        assert!(!op.evaluate("webzip")); // Case-sensitive
    }

    #[test]
    fn test_strmatch_path_traversal() {
        let op = strmatch("../../../");
        assert!(op.evaluate("GET /../../../etc/passwd"));
        assert!(!op.evaluate("GET /index.html"));
    }
}
