//! Validation and utility operators.
//!
//! This module provides operators for validating encoding, byte ranges, and
//! utility operators that always match or never match.

use crate::operators::{Operator, Outputs};
use crate::transaction::Transaction;
use crate::transformations::text_of;

/// Unconditional match operator.
///
/// Forces the rule to always return true, unconditionally matching and firing all associated actions.
/// Useful for rules that should always execute their actions regardless of input, such as setting
/// variables, logging, or performing initialization tasks.
///
/// # Arguments
///
/// None. This operator takes no arguments.
///
/// # Returns
///
/// `true` (always, unconditionally)
///
/// # Examples
///
/// ```
/// # use coraza::operators::validation::unconditional_match;
/// # use coraza::operators::Operator;
/// // Always execute action
/// let op = unconditional_match();
/// let tx = coraza::waf::Waf::default().new_transaction();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(op.evaluate(&tx, "any input".as_bytes(), &mut out));
/// assert!(op.evaluate(&tx, "".as_bytes(), &mut out));
/// ```
#[derive(Debug, Clone, Copy)]
pub struct UnconditionalMatch;

impl Operator for UnconditionalMatch {
    fn evaluate(&self, _tx: &Transaction, _input: &[u8], _out: &mut Outputs) -> bool {
        true
    }
}

/// Creates a new `unconditionalMatch` operator.
///
/// # Examples
///
/// ```
/// # use coraza::operators::validation::unconditional_match;
/// # use coraza::operators::Operator;
/// let op = unconditional_match();
/// let tx = coraza::waf::Waf::default().new_transaction();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(op.evaluate(&tx, "test".as_bytes(), &mut out));
/// ```
pub fn unconditional_match() -> UnconditionalMatch {
    UnconditionalMatch
}

/// No match operator.
///
/// Forces the rule to always return false, effectively disabling rule matching unconditionally.
/// Useful for temporarily disabling rules without removing them, or for rules that only execute
/// actions without needing to match.
///
/// # Arguments
///
/// None. This operator takes no arguments.
///
/// # Returns
///
/// `false` (always, unconditionally)
///
/// # Examples
///
/// ```
/// # use coraza::operators::validation::no_match;
/// # use coraza::operators::Operator;
/// // Never matches
/// let op = no_match();
/// let tx = coraza::waf::Waf::default().new_transaction();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(!op.evaluate(&tx, "any input".as_bytes(), &mut out));
/// assert!(!op.evaluate(&tx, "".as_bytes(), &mut out));
/// ```
#[derive(Debug, Clone, Copy)]
pub struct NoMatch;

impl Operator for NoMatch {
    fn evaluate(&self, _tx: &Transaction, _input: &[u8], _out: &mut Outputs) -> bool {
        false
    }
}

/// Creates a new `noMatch` operator.
///
/// # Examples
///
/// ```
/// # use coraza::operators::validation::no_match;
/// # use coraza::operators::Operator;
/// let op = no_match();
/// let tx = coraza::waf::Waf::default().new_transaction();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(!op.evaluate(&tx, "test".as_bytes(), &mut out));
/// ```
pub fn no_match() -> NoMatch {
    NoMatch
}

/// Byte range validation operator.
///
/// Validates that the byte values used in input fall into the specified range(s).
/// Returns true (violation) if any byte is found outside the allowed ranges. Useful for
/// detecting binary data, control characters, or restricting character sets.
///
/// # Arguments
///
/// Comma-separated byte values or ranges (e.g., "10, 13, 32-126" for printable ASCII).
/// Ranges are specified as "start-end" and individual bytes as single numbers (0-255).
///
/// # Returns
///
/// `true` if any byte is outside the allowed range (violation detected), `false` if all bytes are valid.
///
/// # Examples
///
/// ```
/// # use coraza::operators::validation::validate_byte_range;
/// # use coraza::operators::Operator;
/// // Allow only printable ASCII
/// let op = validate_byte_range("32-126").unwrap();
/// let tx = coraza::waf::Waf::default().new_transaction();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(!op.evaluate(&tx, "Hello World".as_bytes(), &mut out)); // Valid
/// assert!(op.evaluate(&tx, "Hello\x00World".as_bytes(), &mut out)); // Invalid (null byte)
///
/// // Allow printable ASCII plus newline/tab
/// let op = validate_byte_range("10,13,32-126").unwrap();
/// assert!(!op.evaluate(&tx, "Hello\nWorld".as_bytes(), &mut out));
/// ```
#[derive(Debug, Clone)]
pub struct ValidateByteRange {
    /// Bitmap of valid bytes (256 possible byte values)
    valid_bytes: [bool; 256],
}

impl ValidateByteRange {
    /// Creates a new `ValidateByteRange` operator from a comma-separated list of bytes/ranges.
    ///
    /// # Arguments
    ///
    /// * `ranges` - Comma-separated list like "10,13,32-126"
    ///
    /// # Returns
    ///
    /// `Ok(ValidateByteRange)` if valid, `Err` if invalid byte values or ranges.
    ///
    /// # Examples
    ///
    /// ```
    /// # use coraza::operators::validation::ValidateByteRange;
    /// let op = ValidateByteRange::new("32-126").unwrap();
    /// let op = ValidateByteRange::new("10,13,32-126,128-255").unwrap();
    /// ```
    pub fn new(ranges: &str) -> Result<Self, String> {
        if ranges.is_empty() {
            // Empty range means allow all bytes (unconditional match for violations = always false)
            return Ok(ValidateByteRange {
                valid_bytes: [true; 256],
            });
        }

        let mut valid_bytes = [false; 256];

        for range_spec in ranges.split(',') {
            let range_spec = range_spec.trim();
            if range_spec.is_empty() {
                continue;
            }

            if let Some((start_str, end_str)) = range_spec.split_once('-') {
                // Range: "32-126"
                let start = start_str
                    .trim()
                    .parse::<u8>()
                    .map_err(|_| format!("invalid byte value: {}", start_str))?;
                let end = end_str
                    .trim()
                    .parse::<u8>()
                    .map_err(|_| format!("invalid byte value: {}", end_str))?;

                for byte_val in start..=end {
                    valid_bytes[byte_val as usize] = true;
                }
            } else {
                // Single byte: "10"
                let byte_val = range_spec
                    .parse::<u8>()
                    .map_err(|_| format!("invalid byte value: {}", range_spec))?;
                valid_bytes[byte_val as usize] = true;
            }
        }

        Ok(ValidateByteRange { valid_bytes })
    }
}

impl Operator for ValidateByteRange {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        if input.is_empty() {
            return false; // Empty input is valid
        }

        // Check each byte - return true (violation) if any byte is invalid
        for &byte in input {
            if !self.valid_bytes[byte as usize] {
                return true; // Violation detected
            }
        }

        false // All bytes are valid
    }
}

/// Creates a new `validateByteRange` operator.
///
/// # Examples
///
/// ```
/// # use coraza::operators::validation::validate_byte_range;
/// # use coraza::operators::Operator;
/// let op = validate_byte_range("32-126").unwrap();
/// let tx = coraza::waf::Waf::default().new_transaction();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(!op.evaluate(&tx, "valid ASCII".as_bytes(), &mut out));
/// ```
pub fn validate_byte_range(ranges: &str) -> Result<ValidateByteRange, String> {
    ValidateByteRange::new(ranges)
}

/// URL encoding validation operator.
///
/// Validates URL-encoded characters in the input string. Checks that percent-encoding
/// follows proper format (%XX where X is a hexadecimal digit). Returns true if invalid
/// encoding is detected (non-hex characters or incomplete sequences).
///
/// # Arguments
///
/// None. Operates on the target variable specified in the rule.
///
/// # Returns
///
/// `true` if invalid URL encoding is found (violation), `false` if encoding is valid.
///
/// # Examples
///
/// ```
/// # use coraza::operators::validation::validate_url_encoding;
/// # use coraza::operators::Operator;
/// let op = validate_url_encoding();
///
/// // Valid encodings
/// let tx = coraza::waf::Waf::default().new_transaction();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(!op.evaluate(&tx, "/path".as_bytes(), &mut out));
/// assert!(!op.evaluate(&tx, "/path%20with%20spaces".as_bytes(), &mut out));
/// assert!(!op.evaluate(&tx, "%2Fpath%3Ftest".as_bytes(), &mut out));
///
/// // Invalid encodings
/// assert!(op.evaluate(&tx, "/path%2".as_bytes(), &mut out)); // Incomplete
/// assert!(op.evaluate(&tx, "/path%ZZ".as_bytes(), &mut out)); // Non-hex
/// assert!(op.evaluate(&tx, "/path%2G".as_bytes(), &mut out)); // Non-hex
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ValidateUrlEncoding;

impl Operator for ValidateUrlEncoding {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        if input.is_empty() {
            return false; // Empty input is valid
        }

        let len = input.len();
        let mut i = 0;

        while i < len {
            if input[i] == b'%' {
                // Check if there are at least 2 more characters
                if i + 2 >= len {
                    return true; // Incomplete sequence (violation)
                }

                // Check if next two characters are hex digits
                let c1 = input[i + 1];
                let c2 = input[i + 2];

                if !c1.is_ascii_hexdigit() || !c2.is_ascii_hexdigit() {
                    return true; // Non-hexadecimal characters (violation)
                }

                i += 3; // Skip the %XX sequence
            } else {
                i += 1;
            }
        }

        false // All percent encodings are valid
    }
}

/// Creates a new `validateUrlEncoding` operator.
///
/// # Examples
///
/// ```
/// # use coraza::operators::validation::validate_url_encoding;
/// # use coraza::operators::Operator;
/// let op = validate_url_encoding();
/// let tx = coraza::waf::Waf::default().new_transaction();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(!op.evaluate(&tx, "/valid%20path".as_bytes(), &mut out));
/// assert!(op.evaluate(&tx, "/invalid%2".as_bytes(), &mut out));
/// ```
pub fn validate_url_encoding() -> ValidateUrlEncoding {
    ValidateUrlEncoding
}

/// UTF-8 encoding validation operator.
///
/// Checks whether the input is a valid UTF-8 encoded string. Detects encoding issues,
/// malformed sequences, and overlong encodings. Useful for preventing UTF-8 validation
/// attacks and ensuring proper character encoding.
///
/// # Arguments
///
/// None. Operates on the target variable specified in the rule.
///
/// # Returns
///
/// `true` if invalid UTF-8 encoding is found (violation), `false` if encoding is valid.
///
/// # Examples
///
/// ```
/// # use coraza::operators::validation::validate_utf8_encoding;
/// # use coraza::operators::Operator;
/// let op = validate_utf8_encoding();
///
/// // Valid UTF-8 (Rust &str is always valid UTF-8)
/// let tx = coraza::waf::Waf::default().new_transaction();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(!op.evaluate(&tx, "Hello".as_bytes(), &mut out));
/// assert!(!op.evaluate(&tx, "Hello 世界".as_bytes(), &mut out));
/// assert!(!op.evaluate(&tx, "".as_bytes(), &mut out));
/// assert!(!op.evaluate(&tx, "🦀".as_bytes(), &mut out));
///
/// // Note: Cannot test invalid UTF-8 with &str since Rust guarantees &str is valid UTF-8
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ValidateUtf8Encoding;

impl Operator for ValidateUtf8Encoding {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        // As in Go Coraza, a match is a value that isn't UTF-8
        std::str::from_utf8(input).is_err()
    }
}

/// Creates a new `validateUtf8Encoding` operator.
///
/// # Examples
///
/// ```
/// # use coraza::operators::validation::validate_utf8_encoding;
/// # use coraza::operators::Operator;
/// let op = validate_utf8_encoding();
/// let tx = coraza::waf::Waf::default().new_transaction();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(!op.evaluate(&tx, "valid UTF-8 ✓".as_bytes(), &mut out));
/// ```
pub fn validate_utf8_encoding() -> ValidateUtf8Encoding {
    ValidateUtf8Encoding
}

/// `@validateNid KIND REGEX`: finds national ids with REGEX and checks each, as Go
/// Coraza does: `cl` for Chilean RUTs (their check digit), `us` for US social security
/// numbers (their area, group and serial, and not all the same or consecutive digits).
///
/// Matches if one of the first 10 found is valid; each valid one is captured, at the
/// index it was found at.
#[derive(Debug, Clone)]
pub struct ValidateNid {
    kind: NidKind,
    regex: regex::Regex,
}

#[derive(Debug, Clone, Copy)]
enum NidKind {
    /// Chile
    Cl,
    /// United States
    Us,
}

impl Operator for ValidateNid {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        let input = text_of(input);
        let mut valid = false;
        for (index, found) in self.regex.find_iter(&input).take(10).enumerate() {
            let nid = found.as_str();
            let checks = match self.kind {
                NidKind::Cl => is_rut(nid),
                NidKind::Us => is_ssn(nid),
            };
            if checks {
                valid = true;
                out.capture(index, nid.as_bytes());
            }
        }
        valid
    }
}

/// Creates a `@validateNid` operator from `KIND REGEX`.
///
/// # Errors
///
/// If KIND is neither `cl` nor `us`, or REGEX isn't a valid regular expression.
pub fn validate_nid(argument: &str) -> Result<ValidateNid, String> {
    let invalid = || format!("invalid @validateNid argument: {argument:?}");
    let (kind, pattern) = argument.split_once(' ').ok_or_else(invalid)?;
    let kind = match kind {
        "cl" => NidKind::Cl,
        "us" => NidKind::Us,
        _ => return Err(invalid()),
    };
    let regex = regex::Regex::new(pattern).map_err(|e| format!("{}: {e}", invalid()))?;
    Ok(ValidateNid { kind, regex })
}

/// Whether `nid` is a Chilean RUT whose last character is its check digit.
fn is_rut(nid: &str) -> bool {
    if nid.len() < 8 {
        return false;
    }
    let nid: String = nid
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == 'k')
        .collect();
    let Some(check) = nid.chars().last() else {
        return false;
    };
    let mut rut: u64 = nid[..nid.len() - 1].parse().unwrap_or(0);
    let mut sum = 0;
    let mut factor = 2;
    while rut != 0 {
        sum += rut % 10 * factor;
        factor = if factor == 7 { 2 } else { factor + 1 };
        rut /= 10;
    }
    let expected = match sum % 11 {
        0 => '0',
        1 => 'k',
        remainder => char::from_digit((11 - remainder) as u32, 10).unwrap_or('?'),
    };
    expected == check
}

/// Whether `nid` is a plausible US social security number.
fn is_ssn(nid: &str) -> bool {
    let digits: Vec<u32> = nid.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 9 {
        return false;
    }
    let number = |range: std::ops::Range<usize>| {
        digits[range]
            .iter()
            .fold(0, |number, digit| number * 10 + digit)
    };
    let (area, group, serial) = (number(0..3), number(3..5), number(5..9));
    if area == 0 || group == 0 || serial == 0 || area >= 740 || area == 666 {
        return false;
    }
    let all_equal = digits.windows(2).all(|pair| pair[0] == pair[1]);
    let consecutive = digits.windows(2).all(|pair| pair[1] == pair[0] + 1);
    !all_equal && !consecutive
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::Matches;

    #[test]
    fn test_rut() {
        // Go Coraza's validate_nid_test.go
        for rut in [
            "11.111.111-1",
            "16100407-3",
            "8.492.655-8",
            "84926558",
            "111111111",
            "5348281-3",
            "10727393-k",
            "10727393-K",
        ] {
            assert!(is_rut(rut), "{rut}");
        }
        for rut in [
            "11.111.111-k",
            "16100407-2",
            "8.492.655-7",
            "84926557",
            "111111112",
            "5348281-4",
            "",
        ] {
            assert!(!is_rut(rut), "{rut}");
        }
    }

    #[test]
    fn test_unconditional_match() {
        let op = unconditional_match();

        assert!(op.matches("test"));
        assert!(op.matches(""));
        assert!(op.matches("anything"));
    }

    #[test]
    fn test_no_match() {
        let op = no_match();

        assert!(!op.matches("test"));
        assert!(!op.matches(""));
        assert!(!op.matches("anything"));
    }

    #[test]
    fn test_validate_byte_range_case4() {
        // Test from Go: TestValidateByteRangeCase4
        let op = validate_byte_range("0-255").unwrap();

        // Cyrillic "А" (U+0410) encoded as UTF-8: 0xD0 0x90
        // Both bytes are within 0-255, so should be valid (no violation)
        assert!(!op.matches("\u{0410}"));
    }

    #[test]
    fn test_validate_byte_range_case5() {
        // Test from Go: TestValidateByteRangeCase5
        let op = validate_byte_range("9,10,13,32-126,128-255").unwrap();

        // Contains \ufffd (U+FFFD) which in UTF-8 is 0xEF 0xBF 0xBD
        // All these bytes are in the allowed range, so should be valid
        assert!(!op.matches("/\u{FFFD}index.html?test=test1"));
    }

    #[test]
    fn test_validate_byte_range_printable_ascii() {
        let op = validate_byte_range("32-126").unwrap();

        // Valid printable ASCII
        assert!(!op.matches("Hello World"));
        assert!(!op.matches("test123!@#"));

        // Invalid: contains null byte
        assert!(op.matches("Hello\x00World"));

        // Invalid: contains control character
        assert!(op.matches("Hello\x01World"));
    }

    #[test]
    fn test_validate_byte_range_with_newline_tab() {
        let op = validate_byte_range("9,10,13,32-126").unwrap();

        // Valid: tab (9), newline (10), carriage return (13)
        assert!(!op.matches("Hello\tWorld"));
        assert!(!op.matches("Hello\nWorld"));
        assert!(!op.matches("Hello\rWorld"));

        // Invalid: null byte
        assert!(op.matches("Hello\x00World"));
    }

    #[test]
    fn test_validate_byte_range_empty_input() {
        let op = validate_byte_range("32-126").unwrap();

        // Empty input is valid (no bytes to violate)
        assert!(!op.matches(""));
    }

    #[test]
    fn test_validate_byte_range_full_range() {
        let op = validate_byte_range("0-255").unwrap();

        // All bytes allowed
        assert!(!op.matches("anything goes"));
        assert!(!op.matches("test\x00null")); // with null byte
    }

    #[test]
    fn test_validate_byte_range_empty_spec() {
        let op = validate_byte_range("").unwrap();

        // Empty spec means all bytes valid
        assert!(!op.matches("anything"));
        assert!(!op.matches("test\x00data"));
    }

    #[test]
    fn test_validate_byte_range_individual_bytes() {
        let op = validate_byte_range("65,66,67").unwrap(); // A, B, C

        assert!(!op.matches("ABC"));
        assert!(op.matches("ABCD")); // D not allowed
    }

    #[test]
    fn test_validate_url_encoding_valid() {
        let op = validate_url_encoding();

        // No percent encoding
        assert!(!op.matches("/path/to/resource"));

        // Valid percent encoding
        assert!(!op.matches("/path%20with%20spaces"));
        assert!(!op.matches("%2Fpath%3Ftest"));
        assert!(!op.matches("/test%20%21%22"));

        // Mixed case hex
        assert!(!op.matches("%2f%2F%aA%Aa"));

        // Empty input
        assert!(!op.matches(""));
    }

    #[test]
    fn test_validate_url_encoding_invalid() {
        let op = validate_url_encoding();

        // Incomplete sequences
        assert!(op.matches("/path%2"));
        assert!(op.matches("/path%"));
        assert!(op.matches("%2"));

        // Non-hex characters
        assert!(op.matches("/path%ZZ"));
        assert!(op.matches("/path%2G"));
        assert!(op.matches("/path%G2"));
        assert!(op.matches("/path% 2"));
    }

    #[test]
    fn test_validate_utf8_encoding() {
        let op = validate_utf8_encoding();

        // Valid UTF-8 (Rust &str is always valid UTF-8)
        assert!(!op.matches("Hello"));
        assert!(!op.matches("Hello 世界"));
        assert!(!op.matches("🦀 Rust"));
        assert!(!op.matches(""));

        // Note: We cannot easily test invalid UTF-8 with &str
        // since Rust guarantees &str is always valid UTF-8
        // In production, invalid UTF-8 would be rejected before reaching this operator
    }
}
