// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Pattern matching operators.
//!
//! This module implements operators for regular expression and multi-pattern matching
//! with macro expansion support.

use std::path::Path;

use crate::operators::{Datasets, Macro, MacroError, Operator, Outputs, contains_bytes};
use crate::transaction::Transaction;
use crate::transformations::text_of;
use crate::utils::strings::x2c;
use aho_corasick::AhoCorasick;
use regex::Regex;

/// Regular expression operator.
///
/// Performs pattern matching using RE2-compatible regular expressions, as Go Coraza's
/// default build does: in dotall mode, where `.` matches newlines (as in ModSecurity),
/// and multiline mode, where `^` and `$` also match at line boundaries.
///
/// A pattern whose `\xHH` escapes spell bytes that aren't UTF-8, such as CRS's
/// `\x{e2}\x80[\x98\x99]` for `‘` and `’`, is matched on the value's bytes instead, as
/// written, as Go Coraza's binary matcher does: each escape is one byte, and classes
/// such as `\w` and case-insensitivity are ASCII only.
///
/// Supports macro expansion for pattern values. With `capture`, the match and its
/// first 9 groups are stored in `TX.0` to `TX.9`, a group that didn't take part as
/// empty.
#[derive(Debug, Clone)]
pub struct Rx {
    macro_param: Macro,
    // Cached regex when no macro expansion is needed
    cached_regex: Option<CompiledRx>,
}

/// An `@rx` pattern, compiled to match text, or bytes when its escapes spell bytes
/// that aren't UTF-8.
#[derive(Debug, Clone)]
enum CompiledRx {
    Text(Regex),
    Bytes(regex::bytes::Regex),
}

impl CompiledRx {
    fn new(pattern: &str) -> Result<Self, regex::Error> {
        if spells_non_utf8_bytes(pattern) {
            regex::bytes::RegexBuilder::new(&unbrace_byte_escapes(pattern))
                .unicode(false)
                .build()
                .map(Self::Bytes)
        } else {
            Regex::new(&format!("(?sm){pattern}")).map(Self::Text)
        }
    }

    /// Whether the pattern matches `input`: as it is for a pattern on bytes, as text
    /// (invalid UTF-8 replaced with U+FFFD) otherwise.
    fn is_match(&self, input: &[u8]) -> bool {
        match self {
            Self::Text(regex) => regex.is_match(&text_of(input)),
            Self::Bytes(regex) => regex.is_match(input),
        }
    }

    /// The first match and its groups, `None` for a group that didn't take part; `None`
    /// if nothing matches. A pattern on text matches `input` as [`CompiledRx::is_match`]
    /// does.
    fn captures(&self, input: &[u8]) -> Option<Vec<Option<Vec<u8>>>> {
        match self {
            Self::Text(regex) => regex.captures(&text_of(input)).map(|captures| {
                captures
                    .iter()
                    .map(|group| group.map(|group| group.as_str().as_bytes().to_vec()))
                    .collect()
            }),
            Self::Bytes(regex) => regex.captures(input).map(|captures| {
                captures
                    .iter()
                    .map(|group| group.map(|group| group.as_bytes().to_vec()))
                    .collect()
            }),
        }
    }
}

/// Whether the bytes `pattern`'s `\xHH` and `\x{HH}` escapes spell, with its other
/// characters, aren't UTF-8, as Go Coraza decides to match a pattern on bytes.
fn spells_non_utf8_bytes(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut spelled = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match byte_escape(&bytes[i..]) {
            Some((byte, length)) => {
                spelled.push(byte);
                i += length;
            }
            None if bytes[i] == b'\\' && i + 1 < bytes.len() => {
                spelled.extend_from_slice(&bytes[i..i + 2]);
                i += 2;
            }
            None => {
                spelled.push(bytes[i]);
                i += 1;
            }
        }
    }
    std::str::from_utf8(&spelled).is_err()
}

/// `pattern` with each `\x{HH}` written `\xHH`, which a byte regex reads as a byte
/// rather than as the character U+00HH.
fn unbrace_byte_escapes(pattern: &str) -> String {
    let mut unbraced = String::with_capacity(pattern.len());
    let mut rest = pattern;
    while let Some(c) = rest.chars().next() {
        let length = match byte_escape(rest.as_bytes()) {
            Some((byte, length)) => {
                unbraced.push_str(&format!("\\x{byte:02x}"));
                length
            }
            None => {
                // An escaped character keeps its backslash
                let escaped = match c {
                    '\\' => rest[1..].chars().next().map_or(0, char::len_utf8),
                    _ => 0,
                };
                let length = c.len_utf8() + escaped;
                unbraced.push_str(&rest[..length]);
                length
            }
        };
        rest = &rest[length..];
    }
    unbraced
}

/// The byte a `\xHH` or `\x{HH}` escape at the start of `pattern` writes, and the
/// escape's length.
fn byte_escape(pattern: &[u8]) -> Option<(u8, usize)> {
    let digits = |digits: &[u8]| {
        digits
            .iter()
            .all(u8::is_ascii_hexdigit)
            .then(|| x2c(digits))
    };
    match pattern {
        [b'\\', b'x', b'{', high, low, b'}', ..] => Some((digits(&[*high, *low])?, 6)),
        [b'\\', b'x', b'{', digit, b'}', ..] => Some((digits(&[b'0', *digit])?, 5)),
        [b'\\', b'x', high, low, ..] => Some((digits(&[*high, *low])?, 4)),
        _ => None,
    }
}

impl Operator for Rx {
    fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        // A pattern with macros is compiled for each value, once expanded
        let expanded;
        let regex = match &self.cached_regex {
            Some(regex) => regex,
            None => {
                let pattern = self.macro_param.expand(tx);
                match CompiledRx::new(&pattern) {
                    Ok(regex) => {
                        expanded = regex;
                        &expanded
                    }
                    Err(_) => return false,
                }
            }
        };

        if !out.wants_captures() {
            return regex.is_match(input);
        }
        let Some(groups) = regex.captures(input) else {
            return false;
        };
        // The full match and up to 9 capturing groups (ModSecurity limit)
        for (i, group) in groups.iter().take(10).enumerate() {
            out.capture(i, group.as_deref().unwrap_or(&[]));
        }
        true
    }
}

/// Creates a new `rx` operator.
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
        Some(CompiledRx::new(pattern)?)
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
#[derive(Debug, Clone)]
pub struct Pm {
    macro_param: Macro,
    // Cached matcher when no macro expansion is needed
    cached_matcher: Option<AhoCorasick>,
}

impl Operator for Pm {
    fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        // Phrases with macros are matched with a matcher built for each value, once expanded
        let expanded;
        let matcher = match &self.cached_matcher {
            Some(matcher) => matcher,
            None => {
                let patterns = self.macro_param.expand(tx).to_lowercase();
                let dict: Vec<&str> = patterns.split(' ').collect();
                match AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .build(&dict)
                {
                    Ok(matcher) => {
                        expanded = matcher;
                        &expanded
                    }
                    Err(_) => return false,
                }
            }
        };

        if out.wants_captures() {
            // Capturing mode: collect all matches up to limit of 10
            let mut num_matches = 0;
            for mat in matcher.find_iter(input) {
                out.capture(num_matches, &input[mat.start()..mat.end()]);
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

/// Phrase matching operator (from file).
///
/// Loads patterns from a file, then performs case-insensitive multi-pattern
/// matching identical to `@pm`. Each line in the file should contain one
/// pattern. Empty lines and lines starting with `#` are ignored.
///
/// # File Format
///
/// ```text
/// # Malicious user agents
/// WebZIP
/// WebCopier
/// Webster
/// WebStripper
/// ```
#[derive(Debug, Clone)]
pub struct PmFromFile {
    phrases: Phrases,
}

/// A fixed set of phrases, matched case-insensitively anywhere in the input, as `@pm`
/// matches them.
#[derive(Debug, Clone)]
struct Phrases {
    matcher: AhoCorasick,
}

impl Phrases {
    fn new(patterns: &[String]) -> Result<Self, String> {
        let matcher = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(patterns)
            .map_err(|e| format!("Failed to build matcher: {}", e))?;
        Ok(Self { matcher })
    }

    /// Whether a phrase occurs in `input`; when the rule captures, the first 10 occurrences
    /// are its captures, as found in `input`.
    fn evaluate(&self, _tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        if !out.wants_captures() {
            return self.matcher.is_match(input);
        }
        let mut matched = false;
        for (index, found) in self.matcher.find_iter(input).take(10).enumerate() {
            out.capture(index, &input[found.start()..found.end()]);
            matched = true;
        }
        matched
    }
}

impl PmFromFile {
    /// Creates a new `PmFromFile` operator by loading patterns from a file.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to file containing patterns (one per line); a relative path
    ///   is relative to the working directory
    ///
    /// # Returns
    ///
    /// `Ok(PmFromFile)` if file was read and at least one pattern was loaded,
    /// `Err` if file couldn't be read or no valid patterns were found.
    ///
    /// # File Format
    ///
    /// - One pattern per line
    /// - Empty lines are ignored
    /// - Lines starting with `#` are treated as comments and ignored
    /// - All patterns are matched case-insensitively
    pub fn new(file_path: impl AsRef<Path>) -> Result<Self, String> {
        let file_path = file_path.as_ref();
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read file {}: {}", file_path.display(), e))?;

        let mut patterns = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            patterns.push(line.to_string());
        }

        if patterns.is_empty() {
            return Err(format!(
                "No valid patterns found in {}",
                file_path.display()
            ));
        }

        Ok(Self {
            phrases: Phrases::new(&patterns)?,
        })
    }
}

impl Operator for PmFromFile {
    fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        self.phrases.evaluate(tx, input, out)
    }
}

/// Phrase matching operator (from a `SecDataset`).
///
/// Matches the items of a dataset as `@pm` matches its phrases.
#[derive(Debug, Clone)]
pub struct PmFromDataset {
    phrases: Phrases,
}

impl Operator for PmFromDataset {
    fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        self.phrases.evaluate(tx, input, out)
    }
}

/// Creates a new `@pmFromDataset` operator from the dataset `name` of `datasets`.
///
/// # Errors
///
/// If `datasets` has no dataset `name`.
pub fn pm_from_dataset(name: &str, datasets: &Datasets) -> Result<PmFromDataset, String> {
    let items = datasets
        .get(name)
        .ok_or_else(|| format!("dataset \"{}\" not found", name))?;
    Ok(PmFromDataset {
        phrases: Phrases::new(items)?,
    })
}

/// Creates a new `@pmFromFile` operator.
///
/// # Arguments
///
/// * `file_path` - Path to file containing patterns (one per line); a relative path
///   is relative to the working directory
pub fn pm_from_file(file_path: impl AsRef<Path>) -> Result<PmFromFile, String> {
    PmFromFile::new(file_path)
}

/// Within operator.
///
/// Returns true if the input value (needle) is found anywhere within the
/// parameter (haystack). This is the inverse of `contains` - it checks if
/// the input is contained in the parameter string.
///
/// Supports macro expansion for parameter values.
#[derive(Debug, Clone)]
pub struct Within {
    macro_param: Macro,
}

impl Operator for Within {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        let haystack = self.macro_param.expand(tx);
        contains_bytes(haystack.as_bytes(), input)
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
#[derive(Debug, Clone)]
pub struct StrMatch {
    macro_param: Macro,
}

impl Operator for StrMatch {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        let needle = self.macro_param.expand(tx);
        contains_bytes(input, needle.as_bytes())
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

/// `@restpath TEMPLATE`: matches a path against TEMPLATE, such as
/// `/users/{id}/{name}`, and puts what each `{name}` matched in `ARGS_PATH` (and
/// `ARGS`), as Go Coraza does.
///
/// A segment matches up to the next `/` or `?`. As in Go, the rest of TEMPLATE is a
/// regular expression, matched anywhere in the value.
#[derive(Debug, Clone)]
pub struct RestPath {
    regex: Regex,
}

impl Operator for RestPath {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        let input = text_of(input);
        let Some(captures) = self.regex.captures(&input) else {
            return false;
        };
        for name in self.regex.capture_names().flatten() {
            if let Some(segment) = captures.name(name) {
                out.add_path_argument(name, segment.as_str());
            }
        }
        true
    }
}

/// Creates a `@restpath` operator for `template`.
///
/// # Errors
///
/// If `template`, its segments replaced, isn't a valid regular expression, or a segment
/// name isn't a valid group name (letters, digits and `_`).
pub fn rest_path(template: &str) -> Result<RestPath, String> {
    let segment = Regex::new(r"\{([^}]+)\}").expect("valid segment pattern");
    let pattern = segment.replace_all(template, "(?P<$1>[^?/]+)");
    Regex::new(&pattern)
        .map(|regex| RestPath { regex })
        .map_err(|e| format!("invalid @restpath template {template:?}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::{Matches, evaluate_in};
    use crate::transaction::Transaction;
    use crate::types::RuleVariable;

    fn mock_tx() -> Transaction {
        let mut tx = Transaction::new("operator-test");
        let Some(crate::transaction::VariableCollection::Map(vars)) =
            tx.collection_mut(RuleVariable::TX)
        else {
            unreachable!("TX is a map");
        };
        vars.add("pattern", "test.*data");
        vars.add("keywords", "malware virus trojan");
        vars.add("methods", "GET,POST,HEAD");
        vars.add("search", "admin");
        tx
    }

    /// A transaction for tests of operators whose rule captures.
    fn capturing_tx() -> Transaction {
        Transaction::new("capture-test")
    }

    /// Capture `index`, as stored in `TX.<index>`.
    fn capture(tx: &Transaction, index: usize) -> Option<String> {
        tx.get_variable(RuleVariable::TX, Some(&index.to_string()))
    }

    #[test]
    fn test_rx_basic() {
        let op = rx("som(.*)ta").unwrap();
        assert!(op.matches("somedata"));
        assert!(!op.matches("notdata"));
    }

    #[test]
    fn test_rx_unicode() {
        let op = rx("ハロー").unwrap();
        assert!(op.matches("ハローワールド"));
        assert!(!op.matches("グッバイワールド"));
    }

    #[test]
    fn test_rx_dotall_mode() {
        // Dotall mode enabled by default - . matches newlines
        let op = rx("hello.*world").unwrap();
        assert!(op.matches("hello\nworld"));
        assert!(op.matches("hello world"));
    }

    #[test]
    fn test_rx_case_sensitive() {
        let op = rx("test").unwrap();
        assert!(op.matches("test"));
        assert!(!op.matches("TEST"));

        // Case-insensitive with flag
        let op = rx("(?i)test").unwrap();
        assert!(op.matches("test"));
        assert!(op.matches("TEST"));
    }

    #[test]
    fn test_rx_anchors() {
        let op = rx("^GET").unwrap();
        assert!(op.matches("GET /index.html"));
        assert!(!op.matches(" GET /index.html"));

        let op = rx("\\.php$").unwrap();
        assert!(op.matches("/index.php"));
        assert!(!op.matches("/index.php?id=1"));
    }

    #[test]
    fn test_rx_invalid_pattern() {
        assert!(rx("(unclosed").is_err());
        assert!(rx("[unclosed").is_err());
    }

    #[test]
    fn test_rx_with_macro() {
        let op = rx("%{TX.pattern}").unwrap();
        let mut tx = mock_tx();

        assert!(evaluate_in(&op, &mut tx, "testXYZdata", false));
        assert!(evaluate_in(&op, &mut tx, "test123data", false));
        assert!(!evaluate_in(&op, &mut tx, "notmatching", false));
    }

    #[test]
    fn test_pm_basic() {
        let op = pm("WebZIP WebCopier Webster").unwrap();
        assert!(op.matches("User-Agent: WebZIP/1.0"));
        assert!(op.matches("WebCopier tool"));
        assert!(op.matches("Webster here"));
        assert!(!op.matches("Mozilla/5.0"));
    }

    #[test]
    fn test_pm_case_insensitive() {
        let op = pm("WebZIP").unwrap();
        assert!(op.matches("WEBZIP"));
        assert!(op.matches("webzip"));
        assert!(op.matches("WebZIP"));
        assert!(op.matches("WeBzIp"));
    }

    #[test]
    fn test_pm_multiple_matches() {
        let op = pm("<script> javascript: onerror=").unwrap();
        assert!(op.matches("<script>alert(1)</script>"));
        assert!(op.matches("javascript:void(0)"));
        assert!(op.matches("<img onerror=alert(1)>"));
    }

    #[test]
    fn test_pm_single_pattern() {
        let op = pm("malware").unwrap();
        assert!(op.matches("this is malware"));
        assert!(!op.matches("this is safe"));
    }

    #[test]
    fn test_pm_empty_pattern() {
        let op = pm("").unwrap();
        // Empty pattern matches empty string in input
        assert!(op.matches("anything"));
    }

    #[test]
    fn test_pm_with_macro() {
        let op = pm("%{TX.keywords}").unwrap();
        let mut tx = mock_tx();

        assert!(evaluate_in(&op, &mut tx, "detected malware here", false));
        assert!(evaluate_in(&op, &mut tx, "virus found", false));
        assert!(evaluate_in(&op, &mut tx, "trojan detected", false));
        assert!(!evaluate_in(&op, &mut tx, "clean file", false));
    }

    #[test]
    fn test_within_basic() {
        let op = within("GET,POST,HEAD").unwrap();
        assert!(op.matches("GET"));
        assert!(op.matches("POST"));
        assert!(op.matches("HEAD"));
        assert!(!op.matches("DELETE"));
        assert!(!op.matches("PUT"));
    }

    #[test]
    fn test_within_substring() {
        let op = within("abcdefghij").unwrap();
        assert!(op.matches("abc"));
        assert!(op.matches("def"));
        assert!(op.matches("j"));
        assert!(!op.matches("xyz"));
    }

    #[test]
    fn test_within_exact_match() {
        let op = within("exact").unwrap();
        assert!(op.matches("exact"));
        assert!(!op.matches("not exact"));
    }

    #[test]
    fn test_within_empty_input() {
        let op = within("GET,POST").unwrap();
        assert!(op.matches("")); // Empty string is in any string
    }

    #[test]
    fn test_within_case_sensitive() {
        let op = within("GET,POST").unwrap();
        assert!(op.matches("GET"));
        assert!(!op.matches("get")); // Case-sensitive
    }

    #[test]
    fn test_within_with_macro() {
        let op = within("%{TX.methods}").unwrap();
        let mut tx = mock_tx();

        assert!(evaluate_in(&op, &mut tx, "GET", false));
        assert!(evaluate_in(&op, &mut tx, "POST", false));
        assert!(!evaluate_in(&op, &mut tx, "DELETE", false));
    }

    #[test]
    fn test_strmatch_basic() {
        let op = strmatch("WebZIP").unwrap();
        assert!(op.matches("User-Agent: WebZIP/1.0"));
        assert!(op.matches("WebZIP"));
    }

    #[test]
    fn test_strmatch_case_sensitive() {
        let op = strmatch("WebZIP").unwrap();
        assert!(op.matches("WebZIP"));
        assert!(!op.matches("webzip")); // Case-sensitive
    }

    #[test]
    fn test_strmatch_path_traversal() {
        let op = strmatch("../../../").unwrap();
        assert!(op.matches("GET /../../../etc/passwd"));
        assert!(!op.matches("GET /index.html"));
    }

    #[test]
    fn test_strmatch_with_macro() {
        let op = strmatch("%{TX.search}").unwrap();
        let mut tx = mock_tx();

        assert!(evaluate_in(&op, &mut tx, "/admin/login", false));
        assert!(evaluate_in(&op, &mut tx, "administrator", false));
        assert!(!evaluate_in(&op, &mut tx, "/user/profile", false));
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

    #[test]
    fn test_rx_capturing_basic() {
        let op = rx("(\\w+)@(\\w+)\\.com").unwrap();
        let mut tx = capturing_tx();

        assert!(evaluate_in(&op, &mut tx, "user@example.com", true));

        // Check captured groups
        assert_eq!(capture(&tx, 0), Some("user@example.com".to_string())); // Full match
        assert_eq!(capture(&tx, 1), Some("user".to_string())); // Group 1
        assert_eq!(capture(&tx, 2), Some("example".to_string())); // Group 2
    }

    #[test]
    fn test_rx_capturing_multiple_groups() {
        let op = rx("(\\d{3})-(\\d{3})-(\\d{4})").unwrap();
        let mut tx = capturing_tx();

        assert!(evaluate_in(&op, &mut tx, "123-456-7890", true));

        // Check all groups
        assert_eq!(capture(&tx, 0), Some("123-456-7890".to_string()));
        assert_eq!(capture(&tx, 1), Some("123".to_string()));
        assert_eq!(capture(&tx, 2), Some("456".to_string()));
        assert_eq!(capture(&tx, 3), Some("7890".to_string()));
    }

    #[test]
    fn test_rx_is_multiline() {
        // As in Go Coraza's default build: ^ and $ match at line boundaries too
        let op = rx("^b$").unwrap();
        assert!(op.matches("a\nb\nc"));
    }

    #[test]
    fn test_rx_byte_escapes() {
        // CRS 942432 spells U+2019 and U+00B4 by their UTF-8 bytes, as Go Coraza matches
        // such a pattern on bytes
        let op = rx(r"\x{c2}\x{b4}|\x{e2}\x80[\x98\x99]").unwrap();
        assert!(op.matches("id=’"));
        assert!(op.matches("´"));
        assert!(!op.matches("\u{e2}\u{80}\u{99}"));
        // An escaped backslash isn't an escape
        assert!(!spells_non_utf8_bytes(r"\\xbc"));
        assert!(rx(r"\\xbc").unwrap().matches(r"\xbc"));
        // Escapes that spell UTF-8 stay characters, as in Go
        assert!(!spells_non_utf8_bytes(r"\xe2\x80\x99"));
    }

    #[test]
    fn test_rx_capturing_group_not_taking_part() {
        // A group that didn't take part is captured empty, as in Go Coraza, and the
        // ones after it are still captured
        let op = rx("(a)?(b)").unwrap();
        let mut tx = capturing_tx();
        assert!(evaluate_in(&op, &mut tx, "b", true));
        assert_eq!(capture(&tx, 1), Some(String::new()));
        assert_eq!(capture(&tx, 2), Some("b".to_string()));

        // The same in a pattern matched on bytes
        let op = rx(r"(x)?(\xe2\x80[\x98\x99])").unwrap();
        let mut tx = capturing_tx();
        assert!(evaluate_in(&op, &mut tx, "’", true));
        assert_eq!(capture(&tx, 1), Some(String::new()));
        assert_eq!(capture(&tx, 2), Some("’".to_string()));
    }

    #[test]
    fn test_rx_capturing_nine_groups() {
        // Test ModSecurity's 9-group limit
        let op = rx("(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)").unwrap();
        let mut tx = capturing_tx();

        assert!(evaluate_in(&op, &mut tx, "abcdefghij", true));

        // Check full match and first 9 groups
        assert_eq!(capture(&tx, 0), Some("abcdefghij".to_string()));
        assert_eq!(capture(&tx, 1), Some("a".to_string()));
        assert_eq!(capture(&tx, 2), Some("b".to_string()));
        assert_eq!(capture(&tx, 3), Some("c".to_string()));
        assert_eq!(capture(&tx, 4), Some("d".to_string()));
        assert_eq!(capture(&tx, 5), Some("e".to_string()));
        assert_eq!(capture(&tx, 6), Some("f".to_string()));
        assert_eq!(capture(&tx, 7), Some("g".to_string()));
        assert_eq!(capture(&tx, 8), Some("h".to_string()));
        assert_eq!(capture(&tx, 9), Some("i".to_string()));

        // 10th group should not be captured (ModSecurity limit)
        assert_eq!(capture(&tx, 10), None);
    }

    #[test]
    fn test_rx_no_match_with_capturing() {
        let op = rx("test(\\d+)").unwrap();
        let mut tx = capturing_tx();

        assert!(!evaluate_in(&op, &mut tx, "nodigits", true));

        // No captures should be stored
        assert_eq!(capture(&tx, 0), None);
    }

    #[test]
    fn test_rx_capturing_disabled() {
        let op = rx("(test)").unwrap();
        let mut tx = Transaction::new("no-capture");

        // Should still match, but won't capture
        assert!(evaluate_in(&op, &mut tx, "test", false));
    }

    #[test]
    fn test_pm_capturing_basic() {
        let op = pm("admin sql script").unwrap();
        let mut tx = capturing_tx();

        assert!(evaluate_in(
            &op,
            &mut tx,
            "This script contains admin panel",
            true
        ));

        // PM captures each matched pattern (not groups within a pattern)
        // Note: order depends on which patterns are found first in the input
        assert_eq!(capture(&tx, 0), Some("script".to_string())); // First match
        assert_eq!(capture(&tx, 1), Some("admin".to_string())); // Second match
    }

    #[test]
    fn test_pm_capturing_single_match() {
        let op = pm("malware virus trojan").unwrap();
        let mut tx = capturing_tx();

        assert!(evaluate_in(&op, &mut tx, "detected malware in file", true));

        // Only one pattern matched
        assert_eq!(capture(&tx, 0), Some("malware".to_string()));
        assert_eq!(capture(&tx, 1), None);
    }

    #[test]
    fn test_pm_capturing_ten_matches() {
        // Test the 10-match limit
        let op = pm("a b c d e f g h i j k").unwrap();
        let mut tx = capturing_tx();

        assert!(evaluate_in(&op, &mut tx, "a b c d e f g h i j k", true));

        // Should capture first 10 matches
        for i in 0..10 {
            assert!(capture(&tx, i).is_some());
        }
        // 11th match should not be captured
        assert_eq!(capture(&tx, 10), None);
    }

    #[test]
    fn test_pm_capturing_case_insensitive() {
        let op = pm("admin").unwrap();
        let mut tx = capturing_tx();

        assert!(evaluate_in(&op, &mut tx, "ADMIN panel", true));

        // Should capture the actual matched text (preserving case from input)
        assert_eq!(capture(&tx, 0), Some("ADMIN".to_string()));
    }

    #[test]
    fn test_pm_no_match_with_capturing() {
        let op = pm("malware virus").unwrap();
        let mut tx = capturing_tx();

        assert!(!evaluate_in(&op, &mut tx, "clean file", true));

        // No captures should be stored
        assert_eq!(capture(&tx, 0), None);
    }

    #[test]
    fn test_pm_capturing_disabled() {
        let op = pm("admin").unwrap();
        let mut tx = Transaction::new("no-capture");

        // Should still match, but won't capture
        assert!(evaluate_in(&op, &mut tx, "admin panel", false));
    }

    #[test]
    fn test_pm_from_file() {
        use std::io::Write;

        // Create temporary file with patterns
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(temp_file, "# Bad user agents").unwrap();
        writeln!(temp_file, "WebZIP").unwrap();
        writeln!(temp_file).unwrap(); // Empty line
        writeln!(temp_file, "WebCopier").unwrap();
        writeln!(temp_file, "# Another comment").unwrap();
        writeln!(temp_file, "Webster").unwrap();
        temp_file.flush().unwrap();

        let op = pm_from_file(temp_file.path().to_str().unwrap()).unwrap();

        // Should match patterns from file (case-insensitive)
        assert!(op.matches("User-Agent: WebZIP/1.0"));
        assert!(op.matches("using WEBZIP client"));
        assert!(op.matches("webcopier tool"));
        assert!(op.matches("Webster"));

        // Should not match other patterns
        assert!(!op.matches("Mozilla/5.0"));
        assert!(!op.matches("Chrome"));
    }

    #[test]
    fn test_pm_from_file_capturing() {
        use std::io::Write;

        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(temp_file, "admin").unwrap();
        writeln!(temp_file, "user").unwrap();
        temp_file.flush().unwrap();

        let op = pm_from_file(temp_file.path().to_str().unwrap()).unwrap();
        let mut tx = capturing_tx();

        // Should capture matches
        assert!(evaluate_in(&op, &mut tx, "admin and user panel", true));
        assert_eq!(capture(&tx, 0).as_deref(), Some("admin"));
        assert_eq!(capture(&tx, 1).as_deref(), Some("user"));
        assert_eq!(capture(&tx, 2), None);
    }

    #[test]
    fn test_pm_from_file_empty() {
        use std::io::Write;

        // Create file with only comments
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(temp_file, "# Just comments").unwrap();
        writeln!(temp_file).unwrap();
        temp_file.flush().unwrap();

        let result = pm_from_file(temp_file.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No valid patterns"));
    }

    #[test]
    fn test_pm_from_file_not_found() {
        let result = pm_from_file("/nonexistent/file.txt");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to read file"));
    }

    /// The doc example of `operators::pattern::Rx`, before it became internal.
    #[test]
    fn doc_rx_type() {
        use crate::{operators::Operator, operators::rx};

        let op = rx("som(.*)ta").unwrap();
        let tx = crate::waf::Waf::default().new_transaction();
        let mut out = crate::operators::Outputs::default();
        assert!(op.evaluate(&tx, "somedata".as_bytes(), &mut out));
        assert!(!op.evaluate(&tx, "notdata".as_bytes(), &mut out));

        // Unicode support
        let op = rx("ハロー").unwrap();
        assert!(op.evaluate(&tx, "ハローワールド".as_bytes(), &mut out));
    }

    /// The doc example of `operators::pattern::Pm`, before it became internal.
    #[test]
    fn doc_pm_type() {
        use crate::{operators::Operator, operators::pm};

        let op = pm("WebZIP WebCopier Webster").unwrap();
        let tx = crate::waf::Waf::default().new_transaction();
        let mut out = crate::operators::Outputs::default();
        assert!(op.evaluate(&tx, "User-Agent: WebZIP/1.0".as_bytes(), &mut out));
        assert!(op.evaluate(&tx, "WEBZIP is here".as_bytes(), &mut out)); // Case-insensitive
        assert!(!op.evaluate(&tx, "Mozilla/5.0".as_bytes(), &mut out));
    }

    /// The doc example of `operators::pattern::Within`, before it became internal.
    #[test]
    fn doc_within_type() {
        use crate::{operators::Operator, operators::within};

        // Check if input is within allowed values
        let op = within("GET,POST,HEAD").unwrap();
        let tx = crate::waf::Waf::default().new_transaction();
        let mut out = crate::operators::Outputs::default();
        assert!(op.evaluate(&tx, "GET".as_bytes(), &mut out));
        assert!(op.evaluate(&tx, "POST".as_bytes(), &mut out));
        assert!(!op.evaluate(&tx, "DELETE".as_bytes(), &mut out));

        // Works with any haystack
        let op = within("abcdefghij").unwrap();
        assert!(op.evaluate(&tx, "def".as_bytes(), &mut out));
        assert!(!op.evaluate(&tx, "xyz".as_bytes(), &mut out));
    }

    /// The doc example of `operators::pattern::StrMatch`, before it became internal.
    #[test]
    fn doc_str_match_type() {
        use crate::{operators::Operator, operators::strmatch};

        let op = strmatch("WebZIP").unwrap();
        let tx = crate::waf::Waf::default().new_transaction();
        let mut out = crate::operators::Outputs::default();
        assert!(op.evaluate(&tx, "User-Agent: WebZIP/1.0".as_bytes(), &mut out));
        assert!(!op.evaluate(&tx, "User-Agent: webzip".as_bytes(), &mut out)); // Case-sensitive
    }
}
