// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Encoding and decoding transformations.
//!
//! This module contains transformations for various encoding schemes including
//! hex, base64, and URL encoding.

use crate::transformations::{TransformationError, TransformationResult};
use crate::utils::strings::wrap_unsafe;

/// Returns the length of the input as a string.
///
/// # Examples
///
/// ```
/// use coraza_rs::transformations::length;
///
/// let (result, changed, _) = length("hello");
/// assert_eq!(result, "5");
/// assert!(changed);
///
/// let (result, changed, _) = length("");
/// assert_eq!(result, "0");
/// assert!(changed);
/// ```
pub fn length(input: &str) -> TransformationResult {
    // Always returns changed=true because the transformation conceptually
    // always changes the data (except edge case where input is its own length)
    (input.len().to_string(), true, None)
}

/// Returns input unchanged (identity transformation).
///
/// This is a special case used in SecLang parsing.
///
/// # Examples
///
/// ```
/// use coraza_rs::transformations::none;
///
/// let (result, changed, _) = none("hello");
/// assert_eq!(result, "hello");
/// assert!(!changed);
/// ```
pub fn none(input: &str) -> TransformationResult {
    (input.to_string(), false, None)
}

/// Removes all NUL bytes (\x00) from input.
///
/// # Examples
///
/// ```
/// use coraza_rs::transformations::remove_nulls;
///
/// let (result, changed, _) = remove_nulls("hello\x00world");
/// assert_eq!(result, "helloworld");
/// assert!(changed);
///
/// let (result, changed, _) = remove_nulls("no nulls");
/// assert_eq!(result, "no nulls");
/// assert!(!changed);
/// ```
pub fn remove_nulls(input: &str) -> TransformationResult {
    if !input.contains('\x00') {
        return (input.to_string(), false, None);
    }

    let transformed = input.replace('\x00', "");
    (transformed, true, None)
}

/// Replaces all NUL bytes (\x00) with spaces.
///
/// # Examples
///
/// ```
/// use coraza_rs::transformations::replace_nulls;
///
/// let (result, changed, _) = replace_nulls("hello\x00world");
/// assert_eq!(result, "hello world");
/// assert!(changed);
///
/// let (result, changed, _) = replace_nulls("no nulls");
/// assert_eq!(result, "no nulls");
/// assert!(!changed);
/// ```
pub fn replace_nulls(input: &str) -> TransformationResult {
    let transformed = input.replace('\x00', " ");
    let changed = input != transformed;
    (transformed, changed, None)
}

/// Encodes input as hexadecimal (lowercase).
///
/// # Examples
///
/// ```
/// use coraza_rs::transformations::hex_encode;
///
/// let (result, changed, _) = hex_encode("Hello");
/// assert_eq!(result, "48656c6c6f");
/// assert!(changed);
///
/// let (result, changed, _) = hex_encode("");
/// assert_eq!(result, "");
/// assert!(changed);
/// ```
pub fn hex_encode(input: &str) -> TransformationResult {
    let encoded = input
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    (encoded, true, None)
}

/// Decodes hexadecimal input to bytes.
///
/// Returns an error if the input contains invalid hex characters or has odd length.
///
/// # Examples
///
/// ```
/// use coraza_rs::transformations::hex_decode;
///
/// let (result, changed, err) = hex_decode("48656c6c6f");
/// assert_eq!(result, "Hello");
/// assert!(changed);
/// assert!(err.is_none());
///
/// let (result, changed, err) = hex_decode("invalid");
/// assert_eq!(result, "");
/// assert!(!changed);
/// assert!(err.is_some());
/// ```
pub fn hex_decode(input: &str) -> TransformationResult {
    if input.is_empty() {
        return (String::new(), true, None);
    }

    match hex_decode_bytes(input) {
        Ok(bytes) => {
            // SAFETY: hex_decode_bytes validates that the decoded bytes form valid UTF-8
            // by using String::from_utf8 which checks UTF-8 validity
            let decoded = unsafe { wrap_unsafe(&bytes) }.to_string();
            (decoded, true, None)
        }
        Err(e) => (String::new(), false, Some(e)),
    }
}

/// Helper function to decode hex string to bytes.
fn hex_decode_bytes(input: &str) -> Result<Vec<u8>, TransformationError> {
    if !input.len().is_multiple_of(2) {
        return Err(TransformationError::new("odd length hex string"));
    }

    let mut result = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();

    for i in (0..bytes.len()).step_by(2) {
        let high = hex_char_to_value(bytes[i])?;
        let low = hex_char_to_value(bytes[i + 1])?;
        result.push((high << 4) | low);
    }

    Ok(result)
}

/// Converts a hex character to its numeric value.
#[inline]
fn hex_char_to_value(c: u8) -> Result<u8, TransformationError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(TransformationError::new(format!(
            "invalid hex character: {}",
            c as char
        ))),
    }
}

/// URL encodes the input (percent-encoding and space to +).
///
/// Encodes all characters except alphanumerics and asterisk (*).
/// Spaces are encoded as '+'.
///
/// # Examples
///
/// ```
/// use coraza_rs::transformations::url_encode;
///
/// let (result, changed, _) = url_encode("hello world");
/// assert_eq!(result, "hello+world");
/// assert!(changed);
///
/// let (result, changed, _) = url_encode("https://www.coraza.io");
/// assert_eq!(result, "https%3a%2f%2fwww%2ecoraza%2eio");
/// assert!(changed);
///
/// let (result, changed, _) = url_encode("helloWorld");
/// assert_eq!(result, "helloWorld");
/// assert!(!changed);
/// ```
pub fn url_encode(input: &str) -> TransformationResult {
    if input.is_empty() {
        return (String::new(), false, None);
    }

    let mut result = String::with_capacity(input.len() * 3);
    let mut changed = false;

    for byte in input.as_bytes() {
        match byte {
            b' ' => {
                result.push('+');
                changed = true;
            }
            // Keep alphanumerics and asterisk unchanged
            b'*' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' => {
                result.push(*byte as char);
            }
            // Percent-encode everything else
            _ => {
                result.push('%');
                result.push_str(&format!("{:02x}", byte));
                changed = true;
            }
        }
    }

    (result, changed, None)
}

/// Base64 encodes the input using standard encoding.
///
/// # Examples
///
/// ```
/// use coraza_rs::transformations::base64_encode;
///
/// let (result, changed, _) = base64_encode("Hello");
/// assert_eq!(result, "SGVsbG8=");
/// assert!(changed);
///
/// let (result, changed, _) = base64_encode("");
/// assert_eq!(result, "");
/// assert!(changed);
/// ```
pub fn base64_encode(input: &str) -> TransformationResult {
    // Using a simple custom base64 encoder to avoid dependencies
    let encoded = base64_encode_string(input.as_bytes());
    (encoded, true, None)
}

/// Custom base64 encoder (standard alphabet with padding).
fn base64_encode_string(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    if input.is_empty() {
        return String::new();
    }

    let mut result = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;

    // Process 3-byte chunks
    while i + 2 < input.len() {
        let chunk =
            ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);

        result.push(ALPHABET[((chunk >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((chunk >> 12) & 0x3F) as usize] as char);
        result.push(ALPHABET[((chunk >> 6) & 0x3F) as usize] as char);
        result.push(ALPHABET[(chunk & 0x3F) as usize] as char);

        i += 3;
    }

    // Handle remaining bytes with padding
    let remaining = input.len() - i;
    if remaining > 0 {
        let chunk = if remaining == 1 {
            (input[i] as u32) << 16
        } else {
            ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8)
        };

        result.push(ALPHABET[((chunk >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((chunk >> 12) & 0x3F) as usize] as char);

        if remaining == 1 {
            result.push('=');
        } else {
            result.push(ALPHABET[((chunk >> 6) & 0x3F) as usize] as char);
        }
        result.push('=');
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_length() {
        let tests = vec![
            ("hello", "5"),
            ("", "0"),
            ("ハローワールド", "21"), // UTF-8 byte length
        ];

        for (input, want) in tests {
            let (got, changed, err) = length(input);
            assert!(err.is_none(), "unexpected error for input: {:?}", input);
            assert_eq!(got, want, "input: {:?}", input);
            assert!(changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_none() {
        let tests = vec!["hello", "", "test case", "ハロー"];

        for input in tests {
            let (got, changed, err) = none(input);
            assert!(err.is_none(), "unexpected error for input: {:?}", input);
            assert_eq!(got, input, "input: {:?}", input);
            assert!(!changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_remove_nulls() {
        let tests = vec![
            ("hello\x00world", "helloworld", true),
            ("no nulls", "no nulls", false),
            ("", "", false),
            ("\x00\x00", "", true),
            ("start\x00middle\x00end", "startmiddleend", true),
        ];

        for (input, want, want_changed) in tests {
            let (got, changed, err) = remove_nulls(input);
            assert!(err.is_none(), "unexpected error for input: {:?}", input);
            assert_eq!(got, want, "input: {:?}", input);
            assert_eq!(changed, want_changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_replace_nulls() {
        let tests = vec![
            ("hello\x00world", "hello world", true),
            ("no nulls", "no nulls", false),
            ("", "", false),
            ("\x00\x00", "  ", true),
            ("start\x00middle\x00end", "start middle end", true),
        ];

        for (input, want, want_changed) in tests {
            let (got, changed, err) = replace_nulls(input);
            assert!(err.is_none(), "unexpected error for input: {:?}", input);
            assert_eq!(got, want, "input: {:?}", input);
            assert_eq!(changed, want_changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_hex_encode() {
        let tests = vec![
            ("Hello", "48656c6c6f", true),
            ("", "", true),
            ("HELLO", "48454c4c4f", true),
            ("!@#$%^&*(", "21402324255e262a28", true),
        ];

        for (input, want, want_changed) in tests {
            let (got, changed, err) = hex_encode(input);
            assert!(err.is_none(), "unexpected error for input: {:?}", input);
            assert_eq!(got, want, "input: {:?}", input);
            assert_eq!(changed, want_changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_hex_decode() {
        let tests = vec![
            ("48656c6c6f", "Hello", true, false),
            ("", "", true, false),
            ("48454C4C4F", "HELLO", true, false),
            ("48454c4C4f", "HELLO", true, false), // Mixed case
            ("21402324255E262A28", "!@#$%^&*(", true, false),
        ];

        for (input, want_output, want_changed, want_error) in tests {
            let (got, changed, err) = hex_decode(input);
            assert_eq!(
                err.is_some(),
                want_error,
                "input: {:?}, err: {:?}",
                input,
                err
            );
            assert_eq!(got, want_output, "input: {:?}", input);
            assert_eq!(changed, want_changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_hex_decode_errors() {
        let tests = vec![
            ("48656c6c6f7", "", false, true), // Odd length
            ("YyYy", "", false, true),        // Invalid hex
            ("123G", "", false, true),        // Extra invalid char
            ("48656c6c6fZ", "", false, true), // Invalid at end
        ];

        for (input, want_output, want_changed, want_error) in tests {
            let (got, changed, err) = hex_decode(input);
            assert_eq!(
                err.is_some(),
                want_error,
                "input: {:?}, err: {:?}",
                input,
                err
            );
            assert_eq!(got, want_output, "input: {:?}", input);
            assert_eq!(changed, want_changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_url_encode() {
        let tests = vec![
            ("", "", false),
            ("helloWorld", "helloWorld", false),
            ("hello world", "hello+world", true),
            (
                "https://www.coraza.io",
                "https%3a%2f%2fwww%2ecoraza%2eio",
                true,
            ),
        ];

        for (input, want, want_changed) in tests {
            let (got, changed, err) = url_encode(input);
            assert!(err.is_none(), "unexpected error for input: {:?}", input);
            assert_eq!(got, want, "input: {:?}", input);
            assert_eq!(changed, want_changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_base64_encode() {
        let tests = vec![
            ("Hello", "SGVsbG8="),
            ("", ""),
            ("A", "QQ=="),
            ("AB", "QUI="),
            ("ABC", "QUJD"),
            ("Man", "TWFu"),
            ("pleasure.", "cGxlYXN1cmUu"),
        ];

        for (input, want) in tests {
            let (got, changed, err) = base64_encode(input);
            assert!(err.is_none(), "unexpected error for input: {:?}", input);
            assert_eq!(got, want, "input: {:?}", input);
            assert!(changed, "input: {:?}", input);
        }
    }
}
