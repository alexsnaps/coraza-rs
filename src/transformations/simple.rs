// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Simple string transformations.
//!
//! This module contains basic string manipulation transformations that don't
//! require external dependencies beyond stdlib.

use crate::transformations::TransformationResult;
use crate::utils::strings::{valid_hex, x2c};

/// Whitespace characters to trim (matching C++ isspace).
///
/// From <https://en.cppreference.com/w/cpp/string/byte/isspace>:
/// - space (0x20, ' ')
/// - form feed (0x0c, '\f')
/// - line feed (0x0a, '\n')
/// - carriage return (0x0d, '\r')
/// - horizontal tab (0x09, '\t')
/// - vertical tab (0x0b, '\v')
const TRIM_SPACES: &[char] = &[' ', '\t', '\n', '\r', '\x0c', '\x0b'];

/// Converts input to lowercase.
///
/// # Examples
///
/// ```
/// use coraza_rs::transformations::lowercase;
///
/// let (result, changed, _) = lowercase("TestCase");
/// assert_eq!(result, "testcase");
/// assert!(changed);
///
/// let (result, changed, _) = lowercase("already lowercase");
/// assert_eq!(result, "already lowercase");
/// assert!(!changed);
/// ```
pub fn lowercase(input: &str) -> TransformationResult {
    let transformed = input.to_lowercase();
    let changed = input != transformed;
    (transformed, changed, None)
}

/// Converts input to uppercase.
///
/// # Examples
///
/// ```
/// use coraza_rs::transformations::uppercase;
///
/// let (result, changed, _) = uppercase("TestCase");
/// assert_eq!(result, "TESTCASE");
/// assert!(changed);
///
/// let (result, changed, _) = uppercase("ALREADY UPPERCASE");
/// assert_eq!(result, "ALREADY UPPERCASE");
/// assert!(!changed);
/// ```
pub fn uppercase(input: &str) -> TransformationResult {
    let transformed = input.to_uppercase();
    let changed = input != transformed;
    (transformed, changed, None)
}

/// Removes leading and trailing whitespace.
///
/// Uses the same whitespace characters as ModSecurity (C++ isspace).
///
/// # Examples
///
/// ```
/// use coraza_rs::transformations::trim;
///
/// let (result, changed, _) = trim("  hello  ");
/// assert_eq!(result, "hello");
/// assert!(changed);
///
/// let (result, changed, _) = trim("hello");
/// assert_eq!(result, "hello");
/// assert!(!changed);
/// ```
pub fn trim(input: &str) -> TransformationResult {
    let transformed = input.trim_matches(TRIM_SPACES);
    let changed = input.len() != transformed.len();
    (transformed.to_string(), changed, None)
}

/// Removes leading whitespace.
///
/// Uses the same whitespace characters as ModSecurity (C++ isspace).
///
/// # Examples
///
/// ```
/// use coraza_rs::transformations::trim_left;
///
/// let (result, changed, _) = trim_left("  hello  ");
/// assert_eq!(result, "hello  ");
/// assert!(changed);
/// ```
pub fn trim_left(input: &str) -> TransformationResult {
    let transformed = input.trim_start_matches(TRIM_SPACES);
    let changed = input.len() != transformed.len();
    (transformed.to_string(), changed, None)
}

/// Removes trailing whitespace.
///
/// Uses the same whitespace characters as ModSecurity (C++ isspace).
///
/// # Examples
///
/// ```
/// use coraza_rs::transformations::trim_right;
///
/// let (result, changed, _) = trim_right("  hello  ");
/// assert_eq!(result, "  hello");
/// assert!(changed);
/// ```
pub fn trim_right(input: &str) -> TransformationResult {
    let transformed = input.trim_end_matches(TRIM_SPACES);
    let changed = input.len() != transformed.len();
    (transformed.to_string(), changed, None)
}

/// Removes all whitespace characters from the input.
///
/// # Examples
///
/// ```
/// use coraza_rs::transformations::remove_whitespace;
///
/// let (result, changed, _) = remove_whitespace("t e s t");
/// assert_eq!(result, "test");
/// assert!(changed);
///
/// let (result, changed, _) = remove_whitespace("test");
/// assert_eq!(result, "test");
/// assert!(!changed);
/// ```
pub fn remove_whitespace(input: &str) -> TransformationResult {
    let mut changed = false;
    let transformed: String = input
        .chars()
        .filter(|c| {
            if c.is_whitespace() {
                changed = true;
                false
            } else {
                true
            }
        })
        .collect();

    (transformed, changed, None)
}

/// Compresses consecutive whitespace into single spaces.
///
/// Multiple consecutive whitespace characters (space, tab, newline, etc.) are
/// replaced with a single space character.
///
/// # Examples
///
/// ```
/// use coraza_rs::transformations::compress_whitespace;
///
/// let (result, changed, _) = compress_whitespace("Multiple    spaces");
/// assert_eq!(result, "Multiple spaces");
/// assert!(changed);
///
/// let (result, changed, _) = compress_whitespace("Single space");
/// assert_eq!(result, "Single space");
/// assert!(!changed);
/// ```
pub fn compress_whitespace(input: &str) -> TransformationResult {
    // Fast path: check if there's any whitespace to compress
    let bytes = input.as_bytes();
    if let Some(pos) = bytes.iter().position(|&b| is_latin_space(b)) {
        return do_compress_whitespace(input, pos);
    }
    (input.to_string(), false, None)
}

/// Helper function for compress_whitespace - does the actual compression.
fn do_compress_whitespace(input: &str, start_pos: usize) -> TransformationResult {
    let mut result = String::with_capacity(input.len());
    result.push_str(&input[..start_pos]);

    let bytes = input.as_bytes();
    let mut changed = false;
    let mut in_whitespace = false;

    for &byte in bytes.iter().skip(start_pos) {
        if is_latin_space(byte) {
            if in_whitespace {
                changed = true;
                continue;
            } else {
                in_whitespace = true;
                result.push(' ');
            }
        } else {
            in_whitespace = false;
            result.push(byte as char);
        }
    }

    (result, changed, None)
}

/// Checks if a byte is a latin space character.
///
/// Includes: tab, newline, vertical tab, form feed, carriage return, space, and
/// Latin-1 whitespace characters (0x85, 0xA0).
#[inline]
fn is_latin_space(c: u8) -> bool {
    matches!(
        c,
        b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r' | b' ' | 0x85 | 0xA0
    )
}

/// URL decodes the input (percent-decoding and + to space).
///
/// Decodes percent-encoded sequences (%XX) and converts '+' to space.
/// Invalid percent sequences are left unchanged.
///
/// # Examples
///
/// ```
/// use coraza_rs::transformations::url_decode;
///
/// let (result, changed, _) = url_decode("hello+world");
/// assert_eq!(result, "hello world");
/// assert!(changed);
///
/// let (result, changed, _) = url_decode("test%20case");
/// assert_eq!(result, "test case");
/// assert!(changed);
///
/// let (result, changed, _) = url_decode("no encoding");
/// assert_eq!(result, "no encoding");
/// assert!(!changed);
/// ```
pub fn url_decode(input: &str) -> TransformationResult {
    // Fast path: check if there's anything to decode
    let bytes = input.as_bytes();
    if let Some(pos) = bytes.iter().position(|&b| b == b'%' || b == b'+') {
        return do_url_decode(input, pos);
    }
    (input.to_string(), false, None)
}

/// Helper function for url_decode - does the actual decoding.
///
/// Extracted from <https://github.com/senghoo/modsecurity-go/blob/master/utils/urlencode.go>
fn do_url_decode(input: &str, start_pos: usize) -> TransformationResult {
    let input_bytes = input.as_bytes();
    let input_len = input_bytes.len();

    let mut result = Vec::with_capacity(input_len);
    // Copy the part before the first special character
    result.extend_from_slice(&input_bytes[..start_pos]);

    let mut i = start_pos;

    while i < input_len {
        if input_bytes[i] == b'%' {
            // Character is a percent sign
            // Are there enough bytes available?
            if i + 2 < input_len {
                let c1 = input_bytes[i + 1];
                let c2 = input_bytes[i + 2];

                if valid_hex(c1) && valid_hex(c2) {
                    let decoded = x2c(&input[i + 1..i + 3]);
                    result.push(decoded);
                    i += 3;
                } else {
                    // Not a valid encoding, skip this %
                    result.push(input_bytes[i]);
                    i += 1;
                }
            } else {
                // Not enough bytes available, copy the raw bytes
                result.push(input_bytes[i]);
                i += 1;
            }
        } else if input_bytes[i] == b'+' {
            // Plus sign becomes space
            result.push(b' ');
            i += 1;
        } else {
            // Regular character
            result.push(input_bytes[i]);
            i += 1;
        }
    }

    // SAFETY: We're only decoding percent-encoded bytes and replacing '+' with space.
    // The input was valid UTF-8, and our transformations preserve UTF-8 validity.
    let transformed = unsafe { String::from_utf8_unchecked(result) };
    (transformed, true, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lowercase() {
        let tests = vec![
            ("TestCase", "testcase", true),
            ("test\u{0000}case", "test\u{0000}case", false),
            ("testcase", "testcase", false),
            ("", "", false),
            (
                "ThIs Is A tExT fOr TeStInG lOwErCaSe FuNcTiOnAlItY.",
                "this is a text for testing lowercase functionality.",
                true,
            ),
        ];

        for (input, want, want_changed) in tests {
            let (got, changed, err) = lowercase(input);
            assert!(err.is_none(), "unexpected error: {:?}", err);
            assert_eq!(got, want, "input: {:?}", input);
            assert_eq!(changed, want_changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_uppercase() {
        let tests = vec![
            ("TestCase", "TESTCASE", true),
            ("test\u{0000}case", "TEST\u{0000}CASE", true),
            ("TESTCASE", "TESTCASE", false),
            ("", "", false),
            (
                "ThIs Is A tExT fOr TeStInG uPPerCAse FuNcTiOnAlItY.",
                "THIS IS A TEXT FOR TESTING UPPERCASE FUNCTIONALITY.",
                true,
            ),
        ];

        for (input, want, want_changed) in tests {
            let (got, changed, err) = uppercase(input);
            assert!(err.is_none(), "unexpected error: {:?}", err);
            assert_eq!(got, want, "input: {:?}", input);
            assert_eq!(changed, want_changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_trim() {
        let tests = vec![
            ("  hello  ", "hello", true),
            ("\t\nhello\r\n", "hello", true),
            ("hello", "hello", false),
            ("", "", false),
            (" ", "", true),
            ("  hello world  ", "hello world", true),
        ];

        for (input, want, want_changed) in tests {
            let (got, changed, err) = trim(input);
            assert!(err.is_none(), "unexpected error: {:?}", err);
            assert_eq!(got, want, "input: {:?}", input);
            assert_eq!(changed, want_changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_trim_left() {
        let tests = vec![
            ("  hello  ", "hello  ", true),
            ("\t\nhello\r\n", "hello\r\n", true),
            ("hello", "hello", false),
            ("", "", false),
            (" ", "", true),
        ];

        for (input, want, want_changed) in tests {
            let (got, changed, err) = trim_left(input);
            assert!(err.is_none(), "unexpected error: {:?}", err);
            assert_eq!(got, want, "input: {:?}", input);
            assert_eq!(changed, want_changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_trim_right() {
        let tests = vec![
            ("  hello  ", "  hello", true),
            ("\t\nhello\r\n", "\t\nhello", true),
            ("hello", "hello", false),
            ("", "", false),
            (" ", "", true),
        ];

        for (input, want, want_changed) in tests {
            let (got, changed, err) = trim_right(input);
            assert!(err.is_none(), "unexpected error: {:?}", err);
            assert_eq!(got, want, "input: {:?}", input);
            assert_eq!(changed, want_changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_remove_whitespace() {
        let tests = vec![
            ("", "", false),
            ("test", "test", false),
            ("t e s t", "test", true),
            ("  test  ", "test", true),
            ("\t\ntest\r\n", "test", true),
        ];

        for (input, want, want_changed) in tests {
            let (got, changed, err) = remove_whitespace(input);
            assert!(err.is_none(), "unexpected error: {:?}", err);
            assert_eq!(got, want, "input: {:?}", input);
            assert_eq!(changed, want_changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_compress_whitespace() {
        let tests = vec![
            ("", "", false),
            ("Single space", "Single space", false),
            ("Multiple    spaces", "Multiple spaces", true),
            ("  leading", " leading", true),
            ("trailing  ", "trailing ", true),
            ("\t\ntest  \r\n", " test ", true),
        ];

        for (input, want, want_changed) in tests {
            let (got, changed, err) = compress_whitespace(input);
            assert!(err.is_none(), "unexpected error: {:?}", err);
            assert_eq!(got, want, "input: {:?}", input);
            assert_eq!(changed, want_changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_url_decode() {
        let tests = vec![
            ("hello+world", "hello world", true),
            ("test%20case", "test case", true),
            ("no encoding", "no encoding", false),
            ("", "", false),
            ("test%2Bcase", "test+case", true),
            ("%41%42%43", "ABC", true),
            ("test%", "test%", true),       // Invalid: not enough bytes
            ("test%2", "test%2", true),     // Invalid: not enough bytes
            ("test%GG", "test%GG", true),   // Invalid: not hex
            ("100%25", "100%", true),       // Percent sign itself
            ("mix+%20ed", "mix  ed", true), // Mixed + and %20
        ];

        for (input, want, want_changed) in tests {
            let (got, changed, err) = url_decode(input);
            assert!(err.is_none(), "unexpected error: {:?}", err);
            assert_eq!(got, want, "input: {:?}", input);
            assert_eq!(changed, want_changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_url_decode_utf8() {
        // UTF-8 multi-byte sequences encoded as percent
        let (got, changed, err) = url_decode("hello%C2%A9world"); // © symbol
        assert!(err.is_none());
        assert_eq!(got, "hello©world");
        assert!(changed);
    }

    #[test]
    fn test_is_latin_space() {
        assert!(is_latin_space(b'\t'));
        assert!(is_latin_space(b'\n'));
        assert!(is_latin_space(b'\x0b')); // vertical tab
        assert!(is_latin_space(b'\x0c')); // form feed
        assert!(is_latin_space(b'\r'));
        assert!(is_latin_space(b' '));
        assert!(is_latin_space(0x85));
        assert!(is_latin_space(0xA0));

        assert!(!is_latin_space(b'a'));
        assert!(!is_latin_space(b'Z'));
        assert!(!is_latin_space(b'0'));
    }
}
