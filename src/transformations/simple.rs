// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Simple string transformations.
//!
//! This module contains basic string manipulation transformations that don't
//! require external dependencies beyond stdlib.

use crate::transformations::{TransformationResult, chars_lossy};
use crate::utils::strings::x2c;

/// Whitespace bytes to trim (matching C++ isspace).
///
/// From <https://en.cppreference.com/w/cpp/string/byte/isspace>:
/// - space (0x20, ' ')
/// - form feed (0x0c, '\f')
/// - line feed (0x0a, '\n')
/// - carriage return (0x0d, '\r')
/// - horizontal tab (0x09, '\t')
/// - vertical tab (0x0b, '\v')
const TRIM_SPACES: &[u8] = b" \t\n\r\x0c\x0b";

/// Converts input to lowercase.
///
/// ASCII input is lowercased byte by byte; other input is read as characters, each
/// byte that isn't part of one becoming U+FFFD, as in Go Coraza.
///
/// # Examples
///
/// ```
/// use coraza::transformations::lowercase;
///
/// let (result, changed, _) = lowercase(b"TestCase");
/// assert_eq!(result, b"testcase");
/// assert!(changed);
///
/// let (result, changed, _) = lowercase(b"already lowercase");
/// assert_eq!(result, b"already lowercase");
/// assert!(!changed);
/// ```
pub fn lowercase(input: &[u8]) -> TransformationResult {
    let transformed = if input.is_ascii() {
        input.to_ascii_lowercase()
    } else {
        chars_lossy(input).to_lowercase().into_bytes()
    };
    let changed = input != transformed;
    (transformed, changed, None)
}

/// Converts input to uppercase.
///
/// ASCII input is uppercased byte by byte; other input is read as characters, each
/// byte that isn't part of one becoming U+FFFD, as in Go Coraza.
///
/// # Examples
///
/// ```
/// use coraza::transformations::uppercase;
///
/// let (result, changed, _) = uppercase(b"TestCase");
/// assert_eq!(result, b"TESTCASE");
/// assert!(changed);
///
/// let (result, changed, _) = uppercase(b"ALREADY UPPERCASE");
/// assert_eq!(result, b"ALREADY UPPERCASE");
/// assert!(!changed);
/// ```
pub fn uppercase(input: &[u8]) -> TransformationResult {
    let transformed = if input.is_ascii() {
        input.to_ascii_uppercase()
    } else {
        chars_lossy(input).to_uppercase().into_bytes()
    };
    let changed = input != transformed;
    (transformed, changed, None)
}

/// `input` without its leading whitespace.
fn trim_start(input: &[u8]) -> &[u8] {
    let start = input
        .iter()
        .position(|byte| !TRIM_SPACES.contains(byte))
        .unwrap_or(input.len());
    &input[start..]
}

/// `input` without its trailing whitespace.
fn trim_end(input: &[u8]) -> &[u8] {
    let end = input
        .iter()
        .rposition(|byte| !TRIM_SPACES.contains(byte))
        .map_or(0, |last| last + 1);
    &input[..end]
}

/// Removes leading and trailing whitespace.
///
/// Uses the same whitespace characters as ModSecurity (C++ isspace).
///
/// # Examples
///
/// ```
/// use coraza::transformations::trim;
///
/// let (result, changed, _) = trim(b"  hello  ");
/// assert_eq!(result, b"hello");
/// assert!(changed);
///
/// let (result, changed, _) = trim(b"hello");
/// assert_eq!(result, b"hello");
/// assert!(!changed);
/// ```
pub fn trim(input: &[u8]) -> TransformationResult {
    let transformed = trim_end(trim_start(input));
    let changed = input.len() != transformed.len();
    (transformed.to_vec(), changed, None)
}

/// Removes leading whitespace.
///
/// Uses the same whitespace characters as ModSecurity (C++ isspace).
///
/// # Examples
///
/// ```
/// use coraza::transformations::trim_left;
///
/// let (result, changed, _) = trim_left(b"  hello  ");
/// assert_eq!(result, b"hello  ");
/// assert!(changed);
/// ```
pub fn trim_left(input: &[u8]) -> TransformationResult {
    let transformed = trim_start(input);
    let changed = input.len() != transformed.len();
    (transformed.to_vec(), changed, None)
}

/// Removes trailing whitespace.
///
/// Uses the same whitespace characters as ModSecurity (C++ isspace).
///
/// # Examples
///
/// ```
/// use coraza::transformations::trim_right;
///
/// let (result, changed, _) = trim_right(b"  hello  ");
/// assert_eq!(result, b"  hello");
/// assert!(changed);
/// ```
pub fn trim_right(input: &[u8]) -> TransformationResult {
    let transformed = trim_end(input);
    let changed = input.len() != transformed.len();
    (transformed.to_vec(), changed, None)
}

/// Removes all whitespace characters from the input.
///
/// The input is read as characters, each byte that isn't part of one becoming
/// U+FFFD, as in Go Coraza.
///
/// # Examples
///
/// ```
/// use coraza::transformations::remove_whitespace;
///
/// let (result, changed, _) = remove_whitespace(b"t e s t");
/// assert_eq!(result, b"test");
/// assert!(changed);
///
/// let (result, changed, _) = remove_whitespace(b"test");
/// assert_eq!(result, b"test");
/// assert!(!changed);
/// ```
pub fn remove_whitespace(input: &[u8]) -> TransformationResult {
    let mut changed = false;
    let transformed: String = chars_lossy(input)
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

    (transformed.into_bytes(), changed, None)
}

/// Compresses consecutive whitespace into single spaces.
///
/// Each run of whitespace (ASCII whitespace, U+0085, U+00A0, or a 0xA0 byte that isn't
/// part of a character) becomes one space, as in Go Coraza.
///
/// # Examples
///
/// ```
/// use coraza::transformations::compress_whitespace;
///
/// let (result, changed, _) = compress_whitespace(b"Multiple    spaces");
/// assert_eq!(result, b"Multiple spaces");
/// assert!(changed);
///
/// let (result, changed, _) = compress_whitespace(b"Single space");
/// assert_eq!(result, b"Single space");
/// assert!(!changed);
/// ```
pub fn compress_whitespace(input: &[u8]) -> TransformationResult {
    let mut result = Vec::with_capacity(input.len());
    let mut changed = false;
    let mut in_whitespace = false;

    let mut push = |is_whitespace: bool, is_space: bool, bytes: &[u8]| {
        if !is_whitespace {
            in_whitespace = false;
            result.extend_from_slice(bytes);
        } else if in_whitespace {
            changed = true;
        } else {
            in_whitespace = true;
            changed |= !is_space;
            result.push(b' ');
        }
    };
    for chunk in input.utf8_chunks() {
        for c in chunk.valid().chars() {
            push(
                is_latin_space(c),
                c == ' ',
                c.encode_utf8(&mut [0; 4]).as_bytes(),
            );
        }
        // A Latin-1 NBSP, as ModSecurity matches it
        for &byte in chunk.invalid() {
            push(byte == 0xA0, false, &[byte]);
        }
    }

    (result, changed, None)
}

/// Whether `c` is ASCII whitespace or one of Latin-1's (U+0085, U+00A0), the
/// whitespace `compressWhitespace` matches in ModSecurity.
#[inline]
fn is_latin_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\x0b' | '\x0c' | '\r' | ' ' | '\u{85}' | '\u{a0}'
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
/// use coraza::transformations::url_decode;
///
/// let (result, changed, _) = url_decode(b"hello+world");
/// assert_eq!(result, b"hello world");
/// assert!(changed);
///
/// let (result, changed, _) = url_decode(b"test%20case");
/// assert_eq!(result, b"test case");
/// assert!(changed);
///
/// let (result, changed, _) = url_decode(b"%ff");
/// assert_eq!(result, b"\xff");
///
/// let (result, changed, _) = url_decode(b"no encoding");
/// assert_eq!(result, b"no encoding");
/// assert!(!changed);
/// ```
pub fn url_decode(input: &[u8]) -> TransformationResult {
    // Fast path: check if there's anything to decode
    if let Some(pos) = input.iter().position(|&b| b == b'%' || b == b'+') {
        return do_url_decode(input, pos);
    }
    (input.to_vec(), false, None)
}

/// Helper function for url_decode - does the actual decoding.
///
/// Extracted from <https://github.com/senghoo/modsecurity-go/blob/master/utils/urlencode.go>
fn do_url_decode(input: &[u8], start_pos: usize) -> TransformationResult {
    let input_len = input.len();

    let mut result = Vec::with_capacity(input_len);
    // Copy the part before the first special character
    result.extend_from_slice(&input[..start_pos]);

    let mut i = start_pos;

    while i < input_len {
        if input[i] == b'%' {
            // Character is a percent sign
            // Are there enough bytes available?
            if i + 2 < input_len {
                let c1 = input[i + 1];
                let c2 = input[i + 2];

                if c1.is_ascii_hexdigit() && c2.is_ascii_hexdigit() {
                    result.push(x2c(&input[i + 1..i + 3]));
                    i += 3;
                } else {
                    // Not a valid encoding, skip this %
                    result.push(input[i]);
                    i += 1;
                }
            } else {
                // Not enough bytes available, copy the raw bytes
                result.push(input[i]);
                i += 1;
            }
        } else if input[i] == b'+' {
            // Plus sign becomes space
            result.push(b' ');
            i += 1;
        } else {
            // Regular character
            result.push(input[i]);
            i += 1;
        }
    }

    (result, true, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transformations::on_text;

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
            let (got, changed, err) = on_text(lowercase, input);
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
            let (got, changed, err) = on_text(uppercase, input);
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
            let (got, changed, err) = on_text(trim, input);
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
            let (got, changed, err) = on_text(trim_left, input);
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
            let (got, changed, err) = on_text(trim_right, input);
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
            let (got, changed, err) = on_text(remove_whitespace, input);
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
            let (got, changed, err) = on_text(compress_whitespace, input);
            assert!(err.is_none(), "unexpected error: {:?}", err);
            assert_eq!(got, want, "input: {:?}", input);
            assert_eq!(changed, want_changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_compress_whitespace_non_ascii() {
        // 0x85 and 0xA0, U+0085 and U+00A0 in Latin-1, are also the last byte of
        // characters such as ① (e2 91 a0) and à (c3 a0)
        for (input, want, want_changed) in [
            ("acap://①②⑦.⓪", "acap://①②⑦.⓪", false),
            ("a  é", "a é", true),
            ("à\u{a0}\u{85}b", "à b", true),
            ("a\tb", "a b", true),
        ] {
            let (got, changed, err) = on_text(compress_whitespace, input);
            assert!(err.is_none());
            assert_eq!(got, want, "input: {input:?}");
            assert_eq!(changed, want_changed, "input: {input:?}");
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
            let (got, changed, err) = on_text(url_decode, input);
            assert!(err.is_none(), "unexpected error: {:?}", err);
            assert_eq!(got, want, "input: {:?}", input);
            assert_eq!(changed, want_changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_url_decode_utf8() {
        // UTF-8 multi-byte sequences encoded as percent
        let (got, changed, err) = on_text(url_decode, "hello%C2%A9world"); // © symbol
        assert!(err.is_none());
        assert_eq!(got, "hello©world");
        assert!(changed);
    }

    #[test]
    fn test_bytes_that_are_not_utf8() {
        // Kept by byte-level transformations
        assert_eq!(url_decode(b"%ff%41").0, b"\xffA");
        assert_eq!(trim(b" \xff ").0, b"\xff");
        assert_eq!(compress_whitespace(b"\xc3  \xa0\xa0x").0, b"\xc3 x");
        // Replaced, one U+FFFD per byte, by those that read characters, as in Go
        assert_eq!(lowercase(b"A\xff\xfeB").0, "a\u{FFFD}\u{FFFD}b".as_bytes());
        assert_eq!(uppercase(b"a\xffb").0, "A\u{FFFD}B".as_bytes());
        assert_eq!(remove_whitespace(b"a \xff").0, "a\u{FFFD}".as_bytes());
    }

    #[test]
    fn test_is_latin_space() {
        for c in ['\t', '\n', '\x0b', '\x0c', '\r', ' ', '\u{85}', '\u{a0}'] {
            assert!(is_latin_space(c), "{c:?}");
        }
        for c in ['a', 'Z', '0', '\u{2000}', '\u{3000}'] {
            assert!(!is_latin_space(c), "{c:?}");
        }
    }
}
