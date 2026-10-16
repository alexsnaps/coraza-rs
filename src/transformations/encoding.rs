// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Encoding and decoding transformations.
//!
//! This module contains transformations for various encoding schemes including
//! hex, base64, and URL encoding.

use crate::transformations::{TransformationError, TransformationResult};
use crate::utils::strings::hex_value;
use md5::{Digest, Md5};
use sha1::Sha1;

/// Returns the length of the input, in bytes, as a decimal number.
pub fn length(input: &[u8]) -> TransformationResult {
    // Always returns changed=true because the transformation conceptually
    // always changes the data (except edge case where input is its own length)
    (input.len().to_string().into_bytes(), true, None)
}

/// Returns input unchanged (identity transformation).
///
/// This is a special case used in SecLang parsing.
pub fn none(input: &[u8]) -> TransformationResult {
    (input.to_vec(), false, None)
}

/// Removes all NUL bytes (\x00) from input.
pub fn remove_nulls(input: &[u8]) -> TransformationResult {
    // Spares the values without NUL, nearly all, the byte-by-byte copy
    if !input.contains(&0) {
        return (input.to_vec(), false, None);
    }
    let transformed: Vec<u8> = input.iter().copied().filter(|&byte| byte != 0).collect();
    (transformed, true, None)
}

/// Replaces all NUL bytes (\x00) with spaces.
pub fn replace_nulls(input: &[u8]) -> TransformationResult {
    let changed = input.contains(&0);
    let transformed = input
        .iter()
        .map(|&byte| if byte == 0 { b' ' } else { byte })
        .collect();
    (transformed, changed, None)
}

/// Encodes input as hexadecimal (lowercase).
pub fn hex_encode(input: &[u8]) -> TransformationResult {
    let encoded = input
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    (encoded.into_bytes(), true, None)
}

/// Decodes hexadecimal input to bytes.
///
/// Returns an error if the input contains invalid hex characters or has odd length.
pub fn hex_decode(input: &[u8]) -> TransformationResult {
    match hex_decode_bytes(input) {
        Ok(bytes) => (bytes, true, None),
        Err(e) => (Vec::new(), false, Some(e)),
    }
}

/// Helper function to decode hex string to bytes.
fn hex_decode_bytes(bytes: &[u8]) -> Result<Vec<u8>, TransformationError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(TransformationError::new("odd length hex string"));
    }

    let mut result = Vec::with_capacity(bytes.len() / 2);

    let digit = |c: u8| {
        hex_value(c).ok_or_else(|| {
            TransformationError::new(format!("invalid hex character: {}", c as char))
        })
    };
    for &[high, low] in bytes.as_chunks::<2>().0 {
        result.push((digit(high)? << 4) | digit(low)?);
    }

    Ok(result)
}

/// URL encodes the input (percent-encoding and space to +).
///
/// Encodes all characters except alphanumerics and asterisk (*).
/// Spaces are encoded as '+'.
pub fn url_encode(input: &[u8]) -> TransformationResult {
    let mut result = Vec::with_capacity(input.len() * 3);
    let mut changed = false;

    for &byte in input {
        match byte {
            b' ' => {
                result.push(b'+');
                changed = true;
            }
            // Keep alphanumerics and asterisk unchanged
            b'*' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' => {
                result.push(byte);
            }
            // Percent-encode everything else
            _ => {
                result.extend_from_slice(format!("%{:02x}", byte).as_bytes());
                changed = true;
            }
        }
    }

    (result, changed, None)
}

/// Base64 encodes the input using standard encoding.
pub fn base64_encode(input: &[u8]) -> TransformationResult {
    // Using a simple custom base64 encoder to avoid dependencies
    let encoded = base64_encode_string(input);
    (encoded.into_bytes(), true, None)
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

/// Computes the MD5 digest of the input, as raw bytes rather than hex: follow it with
/// `t:hexEncode` for hex.
pub fn md5_hash(input: &[u8]) -> TransformationResult {
    // Hash transformations are almost always a change (invariant is extremely unlikely)
    (Md5::digest(input).to_vec(), true, None)
}

/// Computes the SHA1 digest of the input, as raw bytes rather than hex: follow it with
/// `t:hexEncode` for hex.
pub fn sha1_hash(input: &[u8]) -> TransformationResult {
    // Hash transformations are almost always a change (invariant is extremely unlikely)
    (Sha1::digest(input).to_vec(), true, None)
}

/// Base64 decodes the input with partial decoding support.
///
/// Decodes base64 input, stopping at the first invalid character. Returns
/// successfully decoded bytes up to that point. Newlines (\r, \n) are ignored.
///
/// This matches ModSecurity behavior for lenient base64 decoding.
pub fn base64_decode(input: &[u8]) -> TransformationResult {
    let result = do_base64_decode(input, false);
    (result, true, None)
}

/// Base64 decodes with lenient handling of whitespace and dots.
///
/// Like base64_decode but also ignores whitespace and '.' characters.
pub fn base64_decode_ext(input: &[u8]) -> TransformationResult {
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
fn do_base64_decode(src: &[u8], ext: bool) -> Vec<u8> {
    let mut result = Vec::with_capacity(src.len());
    let mut n = 0; // Number of valid base64 characters accumulated
    let mut x = 0u32; // Accumulator for decoding

    for &byte in src {
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

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transformations::on_text;

    #[test]
    fn test_length() {
        let tests = vec![
            ("hello", "5"),
            ("", "0"),
            ("ハローワールド", "21"), // UTF-8 byte length
        ];

        for (input, want) in tests {
            let (got, changed, err) = on_text(length, input);
            assert!(err.is_none(), "unexpected error for input: {:?}", input);
            assert_eq!(got, want, "input: {:?}", input);
            assert!(changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_none() {
        let tests = vec!["hello", "", "test case", "ハロー"];

        for input in tests {
            let (got, changed, err) = on_text(none, input);
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
            let (got, changed, err) = on_text(remove_nulls, input);
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
            let (got, changed, err) = on_text(replace_nulls, input);
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
            let (got, changed, err) = on_text(hex_encode, input);
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
            let (got, changed, err) = on_text(hex_decode, input);
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
            let (got, changed, err) = on_text(hex_decode, input);
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
            let (got, changed, err) = on_text(url_encode, input);
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
            let (got, changed, err) = on_text(base64_encode, input);
            assert!(err.is_none(), "unexpected error for input: {:?}", input);
            assert_eq!(got, want, "input: {:?}", input);
            assert!(changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_md5_hash() {
        for (input, want) in [
            ("hello", "5d41402abc4b2a76b9719d911017c592"),
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
        ] {
            let (digest, changed, err) = md5_hash(input.as_bytes());
            assert!(err.is_none());
            assert_eq!(hex_encode(&digest).0, want.as_bytes());
            assert!(changed);
        }
    }

    #[test]
    fn test_sha1_hash() {
        for (input, want) in [
            ("hello", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"),
            ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        ] {
            let (digest, changed, err) = sha1_hash(input.as_bytes());
            assert!(err.is_none());
            assert_eq!(hex_encode(&digest).0, want.as_bytes());
            assert!(changed);
        }
    }

    #[test]
    fn test_base64_decode() {
        let tests: Vec<(&str, &[u8])> = vec![
            // Valid cases
            ("VGVzdENhc2U=", b"TestCase"),
            ("VGVzdABDYXNl", b"Test\x00Case"), // With null byte
            ("VGVzdENhc2U", b"TestCase"),      // Without padding
            ("PA==", b"<"),
            ("PFRFU1Q+", b"<TEST>"),
            // Partial decoding - stops at first invalid char
            ("PHNjcmlwd", b"<scrip"),                       // Malformed
            ("PFR FU1Q+", b"<T"),                           // Space is invalid
            ("P.HNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", b""), // Dot is invalid, P alone doesn't decode
            ("PHNjcmlwd.D5hbGVydCgxKTwvc2NyaXB0Pg==", b"<scrip"),
            ("PHNjcmlwdD.5hbGVydCgxKTwvc2NyaXB0Pg==", b"<script"),
            ("PFRFU1Q-", b"<TEST"), // Dash is invalid for std base64
            // RFC 3548 examples (binary data)
            ("FPucA9l+", &[0x14, 0xfb, 0x9c, 0x03, 0xd9, 0x7e]),
            ("FPucA9k=", &[0x14, 0xfb, 0x9c, 0x03, 0xd9]),
            ("FPucAw==", &[0x14, 0xfb, 0x9c, 0x03]),
            // RFC 4648 examples
            ("", b""),
            ("Zg==", b"f"),
            ("Zm8=", b"fo"),
            ("Zm9v", b"foo"),
            ("Zm9vYg==", b"foob"),
            ("Zm9vYmE=", b"fooba"),
            ("Zm9vYmFy", b"foobar"),
            // Wikipedia examples
            ("c3VyZS4=", b"sure."),
            ("c3VyZQ==", b"sure"),
            ("c3Vy", b"sur"),
            ("c3U=", b"su"),
            ("bGVhc3VyZS4=", b"leasure."),
            ("ZWFzdXJlLg==", b"easure."),
            ("YXN1cmUu", b"asure."),
        ];

        for (input, want) in tests {
            let (got, changed, err) = base64_decode(input.as_bytes());
            assert!(err.is_none(), "unexpected error for input: {:?}", input);
            assert_eq!(got, want, "input: {:?}", input);
            assert!(changed, "input: {:?}", input);
        }
    }

    #[test]
    fn test_bytes_that_are_not_utf8() {
        assert_eq!(hex_decode(b"ff00").0, b"\xff\x00");
        assert_eq!(hex_encode(b"\xff\x00").0, b"ff00");
        assert_eq!(url_encode(b"\xff").0, b"%ff");
        assert_eq!(base64_encode(b"\xff").0, b"/w==");
        assert_eq!(length(b"\xff\xfe").0, b"2");
        assert_eq!(remove_nulls(b"\xff\x00").0, b"\xff");
        assert_eq!(replace_nulls(b"\xff\x00").0, b"\xff ");
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
            let (got, changed, err) = on_text(base64_decode_ext, input);
            assert!(err.is_none(), "unexpected error for input: {:?}", input);
            assert_eq!(got, want, "input: {:?}", input);
            assert!(changed, "input: {:?}", input);
        }
    }

    /// The doc example of `transformations::encoding::length`, before it became internal.
    #[test]
    fn doc_length() {
        use crate::transformations::length;

        let (result, changed, _) = length(b"hello");
        assert_eq!(result, b"5");
        assert!(changed);

        let (result, changed, _) = length(b"");
        assert_eq!(result, b"0");
        assert!(changed);
    }

    /// The doc example of `transformations::encoding::none`, before it became internal.
    #[test]
    fn doc_none() {
        use crate::transformations::none;

        let (result, changed, _) = none(b"hello");
        assert_eq!(result, b"hello");
        assert!(!changed);
    }

    /// The doc example of `transformations::encoding::remove_nulls`, before it became internal.
    #[test]
    fn doc_remove_nulls() {
        use crate::transformations::remove_nulls;

        let (result, changed, _) = remove_nulls(b"hello\x00world");
        assert_eq!(result, b"helloworld");
        assert!(changed);

        let (result, changed, _) = remove_nulls(b"no nulls");
        assert_eq!(result, b"no nulls");
        assert!(!changed);
    }

    /// The doc example of `transformations::encoding::replace_nulls`, before it became internal.
    #[test]
    fn doc_replace_nulls() {
        use crate::transformations::replace_nulls;

        let (result, changed, _) = replace_nulls(b"hello\x00world");
        assert_eq!(result, b"hello world");
        assert!(changed);

        let (result, changed, _) = replace_nulls(b"no nulls");
        assert_eq!(result, b"no nulls");
        assert!(!changed);
    }

    /// The doc example of `transformations::encoding::hex_encode`, before it became internal.
    #[test]
    fn doc_hex_encode() {
        use crate::transformations::hex_encode;

        let (result, changed, _) = hex_encode(b"Hello");
        assert_eq!(result, b"48656c6c6f");
        assert!(changed);

        let (result, changed, _) = hex_encode(b"");
        assert_eq!(result, b"");
        assert!(changed);
    }

    /// The doc example of `transformations::encoding::hex_decode`, before it became internal.
    #[test]
    fn doc_hex_decode() {
        use crate::transformations::hex_decode;

        let (result, changed, err) = hex_decode(b"48656c6c6f");
        assert_eq!(result, b"Hello");
        assert!(changed);
        assert!(err.is_none());

        let (result, changed, err) = hex_decode(b"invalid");
        assert_eq!(result, b"");
        assert!(!changed);
        assert!(err.is_some());
    }

    /// The doc example of `transformations::encoding::url_encode`, before it became internal.
    #[test]
    fn doc_url_encode() {
        use crate::transformations::url_encode;

        let (result, changed, _) = url_encode(b"hello world");
        assert_eq!(result, b"hello+world");
        assert!(changed);

        let (result, changed, _) = url_encode(b"https://www.coraza.io");
        assert_eq!(result, b"https%3a%2f%2fwww%2ecoraza%2eio");
        assert!(changed);

        let (result, changed, _) = url_encode(b"helloWorld");
        assert_eq!(result, b"helloWorld");
        assert!(!changed);
    }

    /// The doc example of `transformations::encoding::base64_encode`, before it became internal.
    #[test]
    fn doc_base64_encode() {
        use crate::transformations::base64_encode;

        let (result, changed, _) = base64_encode(b"Hello");
        assert_eq!(result, b"SGVsbG8=");
        assert!(changed);

        let (result, changed, _) = base64_encode(b"");
        assert_eq!(result, b"");
        assert!(changed);
    }

    /// The doc example of `transformations::encoding::md5_hash`, before it became internal.
    #[test]
    fn doc_md5_hash() {
        use crate::transformations::{hex_encode, md5_hash};

        let (digest, changed, _) = md5_hash(b"hello");
        assert_eq!(hex_encode(&digest).0, b"5d41402abc4b2a76b9719d911017c592");
        assert!(changed);
    }

    /// The doc example of `transformations::encoding::sha1_hash`, before it became internal.
    #[test]
    fn doc_sha1_hash() {
        use crate::transformations::{hex_encode, sha1_hash};

        let (digest, changed, _) = sha1_hash(b"hello");
        assert_eq!(
            hex_encode(&digest).0,
            b"aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        );
        assert!(changed);
    }

    /// The doc example of `transformations::encoding::base64_decode`, before it became internal.
    #[test]
    fn doc_base64_decode() {
        use crate::transformations::base64_decode;

        let (result, changed, _) = base64_decode(b"SGVsbG8=");
        assert_eq!(result, b"Hello");
        assert!(changed);

        // Partial decoding - stops at space (invalid)
        let (result, changed, _) = base64_decode(b"PFR FU1Q+");
        assert_eq!(result, b"<T");
        assert!(changed);

        // Without padding
        let (result, changed, _) = base64_decode(b"VGVzdENhc2U");
        assert_eq!(result, b"TestCase");
        assert!(changed);
    }

    /// The doc example of `transformations::encoding::base64_decode_ext`, before it became internal.
    #[test]
    fn doc_base64_decode_ext() {
        use crate::transformations::base64_decode_ext;

        // Ignores dots and whitespace
        let (result, changed, _) = base64_decode_ext(b"P.HNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==");
        assert_eq!(result, b"<script>alert(1)</script>");
        assert!(changed);

        let (result, changed, _) = base64_decode_ext(b"PFR FU1Q+");
        assert_eq!(result, b"<TEST>");
        assert!(changed);
    }
}
