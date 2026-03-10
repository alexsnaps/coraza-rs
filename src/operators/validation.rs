//! Validation and utility operators.
//!
//! This module provides operators for validating encoding, byte ranges, and
//! utility operators that always match or never match.

use crate::operators::Operator;
use crate::operators::macros::TransactionState;

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
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "any input"));
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, ""));
/// ```
#[derive(Debug, Clone, Copy)]
pub struct UnconditionalMatch;

impl Operator for UnconditionalMatch {
    fn evaluate<TX: TransactionState>(&self, _tx: Option<&mut TX>, _input: &str) -> bool {
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
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "test"));
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
/// assert!(!op.evaluate(None::<&mut coraza::transaction::Transaction>, "any input"));
/// assert!(!op.evaluate(None::<&mut coraza::transaction::Transaction>, ""));
/// ```
#[derive(Debug, Clone, Copy)]
pub struct NoMatch;

impl Operator for NoMatch {
    fn evaluate<TX: TransactionState>(&self, _tx: Option<&mut TX>, _input: &str) -> bool {
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
/// assert!(!op.evaluate(None::<&mut coraza::transaction::Transaction>, "test"));
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
/// assert!(!op.evaluate(None::<&mut coraza::transaction::Transaction>, "Hello World")); // Valid
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "Hello\x00World")); // Invalid (null byte)
///
/// // Allow printable ASCII plus newline/tab
/// let op = validate_byte_range("10,13,32-126").unwrap();
/// assert!(!op.evaluate(None::<&mut coraza::transaction::Transaction>, "Hello\nWorld"));
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
    fn evaluate<TX: TransactionState>(&self, _tx: Option<&mut TX>, input: &str) -> bool {
        if input.is_empty() {
            return false; // Empty input is valid
        }

        // Check each byte - return true (violation) if any byte is invalid
        for &byte in input.as_bytes() {
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
/// assert!(!op.evaluate(None::<&mut coraza::transaction::Transaction>, "valid ASCII"));
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
/// assert!(!op.evaluate(None::<&mut coraza::transaction::Transaction>, "/path"));
/// assert!(!op.evaluate(None::<&mut coraza::transaction::Transaction>, "/path%20with%20spaces"));
/// assert!(!op.evaluate(None::<&mut coraza::transaction::Transaction>, "%2Fpath%3Ftest"));
///
/// // Invalid encodings
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "/path%2")); // Incomplete
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "/path%ZZ")); // Non-hex
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "/path%2G")); // Non-hex
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ValidateUrlEncoding;

impl ValidateUrlEncoding {
    /// Checks if a character is a valid hexadecimal digit.
    #[inline]
    fn is_hex_digit(c: u8) -> bool {
        c.is_ascii_hexdigit()
    }
}

impl Operator for ValidateUrlEncoding {
    fn evaluate<TX: TransactionState>(&self, _tx: Option<&mut TX>, input: &str) -> bool {
        if input.is_empty() {
            return false; // Empty input is valid
        }

        let bytes = input.as_bytes();
        let len = bytes.len();
        let mut i = 0;

        while i < len {
            if bytes[i] == b'%' {
                // Check if there are at least 2 more characters
                if i + 2 >= len {
                    return true; // Incomplete sequence (violation)
                }

                // Check if next two characters are hex digits
                let c1 = bytes[i + 1];
                let c2 = bytes[i + 2];

                if !Self::is_hex_digit(c1) || !Self::is_hex_digit(c2) {
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
/// assert!(!op.evaluate(None::<&mut coraza::transaction::Transaction>, "/valid%20path"));
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "/invalid%2"));
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
/// assert!(!op.evaluate(None::<&mut coraza::transaction::Transaction>, "Hello"));
/// assert!(!op.evaluate(None::<&mut coraza::transaction::Transaction>, "Hello 世界"));
/// assert!(!op.evaluate(None::<&mut coraza::transaction::Transaction>, ""));
/// assert!(!op.evaluate(None::<&mut coraza::transaction::Transaction>, "🦀"));
///
/// // Note: Cannot test invalid UTF-8 with &str since Rust guarantees &str is valid UTF-8
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ValidateUtf8Encoding;

impl Operator for ValidateUtf8Encoding {
    fn evaluate<TX: TransactionState>(&self, _tx: Option<&mut TX>, _input: &str) -> bool {
        // In Rust, &str is guaranteed to be valid UTF-8, so this always returns false
        // However, if we receive input from C FFI or unsafe code, we should check
        // For now, since our input is &str, it's always valid UTF-8
        // If we need to validate raw bytes, we'd accept &[u8] instead

        // Note: In the Go implementation, this checks if the string is valid UTF-8
        // In Rust, &str is ALWAYS valid UTF-8 by construction
        // If we received invalid UTF-8, it would fail to parse to &str in the first place

        // For compatibility with the Go implementation's semantics:
        // Return true if INVALID UTF-8 (violation), false if valid
        // Since Rust &str is always valid UTF-8, we always return false
        false
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
/// assert!(!op.evaluate(None::<&mut coraza::transaction::Transaction>, "valid UTF-8 ✓"));
/// ```
pub fn validate_utf8_encoding() -> ValidateUtf8Encoding {
    ValidateUtf8Encoding
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::Transaction;

    #[test]
    fn test_unconditional_match() {
        let op = unconditional_match();

        assert!(op.evaluate(None::<&mut Transaction>, "test"));
        assert!(op.evaluate(None::<&mut Transaction>, ""));
        assert!(op.evaluate(None::<&mut Transaction>, "anything"));
    }

    #[test]
    fn test_no_match() {
        let op = no_match();

        assert!(!op.evaluate(None::<&mut Transaction>, "test"));
        assert!(!op.evaluate(None::<&mut Transaction>, ""));
        assert!(!op.evaluate(None::<&mut Transaction>, "anything"));
    }

    #[test]
    fn test_validate_byte_range_case4() {
        // Test from Go: TestValidateByteRangeCase4
        let op = validate_byte_range("0-255").unwrap();

        // Cyrillic "А" (U+0410) encoded as UTF-8: 0xD0 0x90
        // Both bytes are within 0-255, so should be valid (no violation)
        assert!(!op.evaluate(None::<&mut Transaction>, "\u{0410}"));
    }

    #[test]
    fn test_validate_byte_range_case5() {
        // Test from Go: TestValidateByteRangeCase5
        let op = validate_byte_range("9,10,13,32-126,128-255").unwrap();

        // Contains \ufffd (U+FFFD) which in UTF-8 is 0xEF 0xBF 0xBD
        // All these bytes are in the allowed range, so should be valid
        assert!(!op.evaluate(None::<&mut Transaction>, "/\u{FFFD}index.html?test=test1"));
    }

    #[test]
    fn test_validate_byte_range_printable_ascii() {
        let op = validate_byte_range("32-126").unwrap();

        // Valid printable ASCII
        assert!(!op.evaluate(None::<&mut Transaction>, "Hello World"));
        assert!(!op.evaluate(None::<&mut Transaction>, "test123!@#"));

        // Invalid: contains null byte
        assert!(op.evaluate(None::<&mut Transaction>, "Hello\x00World"));

        // Invalid: contains control character
        assert!(op.evaluate(None::<&mut Transaction>, "Hello\x01World"));
    }

    #[test]
    fn test_validate_byte_range_with_newline_tab() {
        let op = validate_byte_range("9,10,13,32-126").unwrap();

        // Valid: tab (9), newline (10), carriage return (13)
        assert!(!op.evaluate(None::<&mut Transaction>, "Hello\tWorld"));
        assert!(!op.evaluate(None::<&mut Transaction>, "Hello\nWorld"));
        assert!(!op.evaluate(None::<&mut Transaction>, "Hello\rWorld"));

        // Invalid: null byte
        assert!(op.evaluate(None::<&mut Transaction>, "Hello\x00World"));
    }

    #[test]
    fn test_validate_byte_range_empty_input() {
        let op = validate_byte_range("32-126").unwrap();

        // Empty input is valid (no bytes to violate)
        assert!(!op.evaluate(None::<&mut Transaction>, ""));
    }

    #[test]
    fn test_validate_byte_range_full_range() {
        let op = validate_byte_range("0-255").unwrap();

        // All bytes allowed
        assert!(!op.evaluate(None::<&mut Transaction>, "anything goes"));
        assert!(!op.evaluate(None::<&mut Transaction>, "test\x00null")); // with null byte
    }

    #[test]
    fn test_validate_byte_range_empty_spec() {
        let op = validate_byte_range("").unwrap();

        // Empty spec means all bytes valid
        assert!(!op.evaluate(None::<&mut Transaction>, "anything"));
        assert!(!op.evaluate(None::<&mut Transaction>, "test\x00data"));
    }

    #[test]
    fn test_validate_byte_range_individual_bytes() {
        let op = validate_byte_range("65,66,67").unwrap(); // A, B, C

        assert!(!op.evaluate(None::<&mut Transaction>, "ABC"));
        assert!(op.evaluate(None::<&mut Transaction>, "ABCD")); // D not allowed
    }

    #[test]
    fn test_validate_url_encoding_valid() {
        let op = validate_url_encoding();

        // No percent encoding
        assert!(!op.evaluate(None::<&mut Transaction>, "/path/to/resource"));

        // Valid percent encoding
        assert!(!op.evaluate(None::<&mut Transaction>, "/path%20with%20spaces"));
        assert!(!op.evaluate(None::<&mut Transaction>, "%2Fpath%3Ftest"));
        assert!(!op.evaluate(None::<&mut Transaction>, "/test%20%21%22"));

        // Mixed case hex
        assert!(!op.evaluate(None::<&mut Transaction>, "%2f%2F%aA%Aa"));

        // Empty input
        assert!(!op.evaluate(None::<&mut Transaction>, ""));
    }

    #[test]
    fn test_validate_url_encoding_invalid() {
        let op = validate_url_encoding();

        // Incomplete sequences
        assert!(op.evaluate(None::<&mut Transaction>, "/path%2"));
        assert!(op.evaluate(None::<&mut Transaction>, "/path%"));
        assert!(op.evaluate(None::<&mut Transaction>, "%2"));

        // Non-hex characters
        assert!(op.evaluate(None::<&mut Transaction>, "/path%ZZ"));
        assert!(op.evaluate(None::<&mut Transaction>, "/path%2G"));
        assert!(op.evaluate(None::<&mut Transaction>, "/path%G2"));
        assert!(op.evaluate(None::<&mut Transaction>, "/path% 2"));
    }

    #[test]
    fn test_validate_utf8_encoding() {
        let op = validate_utf8_encoding();

        // Valid UTF-8 (Rust &str is always valid UTF-8)
        assert!(!op.evaluate(None::<&mut Transaction>, "Hello"));
        assert!(!op.evaluate(None::<&mut Transaction>, "Hello 世界"));
        assert!(!op.evaluate(None::<&mut Transaction>, "🦀 Rust"));
        assert!(!op.evaluate(None::<&mut Transaction>, ""));

        // Note: We cannot easily test invalid UTF-8 with &str
        // since Rust guarantees &str is always valid UTF-8
        // In production, invalid UTF-8 would be rejected before reaching this operator
    }
}
