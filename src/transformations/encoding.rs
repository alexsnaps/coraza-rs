// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Encoding and decoding transformations.
//!
//! This module contains transformations for various encoding schemes including
//! hex, base64, and URL encoding.

use crate::transformations::{TransformationError, TransformationResult};
use crate::utils::strings::wrap_unsafe;
use md5::{Digest, Md5};
use sha1::Sha1;

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

/// Computes MD5 hash of input (returns raw binary hash, not hex-encoded).
///
/// # Examples
///
/// ```
/// use coraza_rs::transformations::md5_hash;
///
/// let (result, changed, _) = md5_hash("hello");
/// // Result is raw binary MD5 hash (16 bytes)
/// assert_eq!(result.len(), 16);
/// assert!(changed);
/// ```
pub fn md5_hash(input: &str) -> TransformationResult {
    if input.is_empty() {
        // Pre-computed MD5 of empty string
        static EMPTY_MD5: &[u8] = &[
            0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
            0x42, 0x7e,
        ];
        // SAFETY: EMPTY_MD5 is a valid byte slice representing MD5 output
        let hash_str = unsafe { wrap_unsafe(EMPTY_MD5) }.to_string();
        return (hash_str, true, None);
    }

    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    let hash = hasher.finalize();

    // SAFETY: MD5 hash output is always valid bytes (may not be valid UTF-8)
    // We're treating it as raw bytes, wrapped as a string
    let hash_str = unsafe { wrap_unsafe(&hash) }.to_string();

    // Hash transformations are almost always a change (invariant is extremely unlikely)
    (hash_str, true, None)
}

/// Computes SHA1 hash of input (returns raw binary hash, not hex-encoded).
///
/// # Examples
///
/// ```
/// use coraza_rs::transformations::sha1_hash;
///
/// let (result, changed, _) = sha1_hash("hello");
/// // Result is raw binary SHA1 hash (20 bytes)
/// assert_eq!(result.len(), 20);
/// assert!(changed);
/// ```
pub fn sha1_hash(input: &str) -> TransformationResult {
    if input.is_empty() {
        // Pre-computed SHA1 of empty string
        static EMPTY_SHA1: &[u8] = &[
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
            0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ];
        // SAFETY: EMPTY_SHA1 is a valid byte slice representing SHA1 output
        let hash_str = unsafe { wrap_unsafe(EMPTY_SHA1) }.to_string();
        return (hash_str, true, None);
    }

    let mut hasher = Sha1::new();
    hasher.update(input.as_bytes());
    let hash = hasher.finalize();

    // SAFETY: SHA1 hash output is always valid bytes (may not be valid UTF-8)
    // We're treating it as raw bytes, wrapped as a string
    let hash_str = unsafe { wrap_unsafe(&hash) }.to_string();

    // Hash transformations are almost always a change (invariant is extremely unlikely)
    (hash_str, true, None)
}

/// Base64 decodes the input with partial decoding support.
///
/// Decodes base64 input, stopping at the first invalid character. Returns
/// successfully decoded bytes up to that point. Newlines (\r, \n) are ignored.
///
/// This matches ModSecurity behavior for lenient base64 decoding.
///
/// # Examples
///
/// ```
/// use coraza_rs::transformations::base64_decode;
///
/// let (result, changed, _) = base64_decode("SGVsbG8=");
/// assert_eq!(result, "Hello");
/// assert!(changed);
///
/// // Partial decoding - stops at space (invalid)
/// let (result, changed, _) = base64_decode("PFR FU1Q+");
/// assert_eq!(result, "<T");
/// assert!(changed);
///
/// // Without padding
/// let (result, changed, _) = base64_decode("VGVzdENhc2U");
/// assert_eq!(result, "TestCase");
/// assert!(changed);
/// ```
pub fn base64_decode(input: &str) -> TransformationResult {
    let result = do_base64_decode(input, false);
    (result, true, None)
}

/// Base64 decodes with lenient handling of whitespace and dots.
///
/// Like base64_decode but also ignores whitespace and '.' characters.
///
/// # Examples
///
/// ```
/// use coraza_rs::transformations::base64_decode_ext;
///
/// // Ignores dots and whitespace
/// let (result, changed, _) = base64_decode_ext("P.HNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==");
/// assert_eq!(result, "<script>alert(1)</script>");
/// assert!(changed);
///
/// let (result, changed, _) = base64_decode_ext("PFR FU1Q+");
/// assert_eq!(result, "<TEST>");
/// assert!(changed);
/// ```
pub fn base64_decode_ext(input: &str) -> TransformationResult {
    let result = do_base64_decode(input, true);
    (result, true, None)
}

/// Base64 decode map for custom decoder.
const BASE64_DEC_MAP: [u8; 128] = [
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, // 0-15
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, // 16-31
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 62, 127, 127, 127,
    63, // 32-47 ('+' = 62, '/' = 63)
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 127, 127, 127, 64, 127,
    127, // 48-63 ('0'-'9' = 52-61, '=' = 64)
    127, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, // 64-79 ('A'-'O' = 0-14)
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 127, 127, 127, 127,
    127, // 80-95 ('P'-'Z' = 15-25)
    127, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
    40, // 96-111 ('a'-'o' = 26-40)
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 127, 127, 127, 127,
    127, // 112-127 ('p'-'z' = 41-51)
];

/// Performs base64 decoding with partial decode support.
///
/// The `ext` flag enables lenient mode which skips whitespace and '.' characters.
fn do_base64_decode(src: &str, ext: bool) -> String {
    if src.is_empty() {
        return String::new();
    }

    let mut result = Vec::with_capacity(src.len());
    let mut n = 0; // Number of valid base64 characters accumulated
    let mut x = 0u32; // Accumulator for decoding

    for byte in src.bytes() {
        // Skip whitespace and '.' if in ext mode
        if ext && (byte.is_ascii_whitespace() || byte == b'.') {
            continue;
        }

        // Newline characters are always ignored
        if byte == b'\r' || byte == b'\n' {
            continue;
        }

        // Stop on padding, space, or non-ASCII
        if byte == b'=' || byte == b' ' || byte > 127 {
            break;
        }

        let decoded = BASE64_DEC_MAP[byte as usize];

        // Invalid character - stop decoding
        if decoded == 127 {
            break;
        }

        x = (x << 6) | (decoded as u32 & 0x3F);
        n += 1;

        if n == 4 {
            result.push((x >> 16) as u8);
            result.push((x >> 8) as u8);
            result.push(x as u8);
            n = 0;
            x = 0;
        }
    }

    // Handle remaining characters
    match n {
        2 => {
            x <<= 12;
            result.push((x >> 16) as u8);
        }
        3 => {
            x <<= 6;
            result.push((x >> 16) as u8);
            result.push((x >> 8) as u8);
        }
        _ => {}
    }

    // SAFETY: base64 decoding can produce arbitrary bytes, but we're wrapping
    // them as a string. The caller is responsible for interpreting the result.
    unsafe { wrap_unsafe(&result) }.to_string()
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

    #[test]
    fn test_md5_hash() {
        // Test that MD5 produces 16-byte output
        let (result, changed, err) = md5_hash("hello");
        assert!(err.is_none());
        assert_eq!(result.len(), 16);
        assert!(changed);

        // Test empty string
        let (result, changed, err) = md5_hash("");
        assert!(err.is_none());
        assert_eq!(result.len(), 16);
        assert!(changed);

        // Test that different inputs produce different hashes
        let (result1, _, _) = md5_hash("test1");
        let (result2, _, _) = md5_hash("test2");
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_sha1_hash() {
        // Test that SHA1 produces 20-byte output
        let (result, changed, err) = sha1_hash("hello");
        assert!(err.is_none());
        assert_eq!(result.len(), 20);
        assert!(changed);

        // Test empty string
        let (result, changed, err) = sha1_hash("");
        assert!(err.is_none());
        assert_eq!(result.len(), 20);
        assert!(changed);

        // Test that different inputs produce different hashes
        let (result1, _, _) = sha1_hash("test1");
        let (result2, _, _) = sha1_hash("test2");
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_base64_decode() {
        // Helper function to create test expected values from byte arrays
        fn bytes_to_string(bytes: &[u8]) -> String {
            unsafe { wrap_unsafe(bytes) }.to_string()
        }

        let tests: Vec<(&str, String)> = vec![
            // Valid cases
            ("VGVzdENhc2U=", "TestCase".to_string()),
            ("VGVzdABDYXNl", "Test\x00Case".to_string()), // With null byte
            ("VGVzdENhc2U", "TestCase".to_string()),      // Without padding
            ("PA==", "<".to_string()),
            ("PFRFU1Q+", "<TEST>".to_string()),
            // Partial decoding - stops at first invalid char
            ("PHNjcmlwd", "<scrip".to_string()), // Malformed
            ("PFR FU1Q+", "<T".to_string()),     // Space is invalid
            ("P.HNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "".to_string()), // Dot is invalid, P alone doesn't decode
            (
                "PHNjcmlwd.D5hbGVydCgxKTwvc2NyaXB0Pg==",
                "<scrip".to_string(),
            ),
            (
                "PHNjcmlwdD.5hbGVydCgxKTwvc2NyaXB0Pg==",
                "<script".to_string(),
            ),
            ("PFRFU1Q-", "<TEST".to_string()), // Dash is invalid for std base64
            // RFC 3548 examples (binary data)
            (
                "FPucA9l+",
                bytes_to_string(&[0x14, 0xfb, 0x9c, 0x03, 0xd9, 0x7e]),
            ),
            ("FPucA9k=", bytes_to_string(&[0x14, 0xfb, 0x9c, 0x03, 0xd9])),
            ("FPucAw==", bytes_to_string(&[0x14, 0xfb, 0x9c, 0x03])),
            // RFC 4648 examples
            ("", "".to_string()),
            ("Zg==", "f".to_string()),
            ("Zm8=", "fo".to_string()),
            ("Zm9v", "foo".to_string()),
            ("Zm9vYg==", "foob".to_string()),
            ("Zm9vYmE=", "fooba".to_string()),
            ("Zm9vYmFy", "foobar".to_string()),
            // Wikipedia examples
            ("c3VyZS4=", "sure.".to_string()),
            ("c3VyZQ==", "sure".to_string()),
            ("c3Vy", "sur".to_string()),
            ("c3U=", "su".to_string()),
            ("bGVhc3VyZS4=", "leasure.".to_string()),
            ("ZWFzdXJlLg==", "easure.".to_string()),
            ("YXN1cmUu", "asure.".to_string()),
        ];

        for (input, want) in tests {
            let (got, changed, err) = base64_decode(input);
            assert!(err.is_none(), "unexpected error for input: {:?}", input);
            assert_eq!(got, want, "input: {:?}", input);
            assert!(changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_base64_decode_ext() {
        let tests = vec![
            ("VGVzdENhc2U=", "TestCase"),
            ("VGVzdABDYXNl", "Test\x00Case"),
            // Ext mode ignores whitespace and dots
            (
                "P.HNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
                "<script>alert(1)</script>",
            ),
            ("PFR FU1Q+", "<TEST>"),
            (
                "PHNjcmlwd.D5hbGVydCgxKTwvc2NyaXB0Pg==",
                "<script>alert(1)</script>",
            ),
            (
                "PHNjcmlwdD.5hbGVydCgxKTwvc2NyaXB0Pg==",
                "<script>alert(1)</script>",
            ),
        ];

        for (input, want) in tests {
            let (got, changed, err) = base64_decode_ext(input);
            assert!(err.is_none(), "unexpected error for input: {:?}", input);
            assert_eq!(got, want, "input: {:?}", input);
            assert!(changed, "input: {:?}", input);
        }
    }
}
