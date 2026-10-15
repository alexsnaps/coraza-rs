// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! String utility functions for WAF processing.
//!
//! This module provides low-level string manipulation utilities used throughout
//! the WAF, particularly in transformations and SecLang parsing.

use std::sync::Mutex;

/// Alphabet for random string generation (a-z, A-Z).
const LETTER_BYTES: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Thread-safe random number generator for random strings.
/// Using Mutex to ensure thread-safety as required by the Go implementation.
static RNG: Mutex<Option<fastrand::Rng>> = Mutex::new(None);

/// Returns a pseudorandom alphanumeric string of length n.
///
/// This function is thread-safe and can be called concurrently.
///
/// # Examples
///
/// ```
/// use coraza::utils::strings::random_string;
///
/// let id = random_string(16);
/// assert_eq!(id.len(), 16);
/// assert!(id.chars().all(|c| c.is_ascii_alphabetic()));
/// ```
pub fn random_string(n: usize) -> String {
    let mut rng = RNG.lock().unwrap();
    let rng = rng.get_or_insert_with(fastrand::Rng::new);

    let mut result = String::with_capacity(n);
    for _ in 0..n {
        let idx = rng.usize(..LETTER_BYTES.len());
        result.push(LETTER_BYTES[idx] as char);
    }
    result
}

/// Value (0-15) of an ASCII hex digit (`0-9`, `a-f`, `A-F`); `None` for any other byte.
///
/// # Examples
///
/// ```
/// use coraza::utils::strings::hex_value;
///
/// assert_eq!(hex_value(b'7'), Some(7));
/// assert_eq!(hex_value(b'b'), Some(11));
/// assert_eq!(hex_value(b'F'), Some(15));
/// assert_eq!(hex_value(b'g'), None);
/// ```
pub fn hex_value(digit: u8) -> Option<u8> {
    char::from(digit).to_digit(16).map(|value| value as u8)
}

/// Converts a two-character hex string to its byte value.
///
/// Assumes the input is exactly 2 characters and both are valid hex digits.
/// Check digits with [`u8::is_ascii_hexdigit`] first.
///
/// # Examples
///
/// ```
/// use coraza::utils::strings::x2c;
///
/// assert_eq!(x2c("41"), b'A');  // 0x41 = 65 = 'A'
/// assert_eq!(x2c("0a"), 10);
/// assert_eq!(x2c("FF"), 255);
/// assert_eq!(x2c("00"), 0);
/// ```
///
/// # Panics
///
/// Panics if the string is not exactly 2 bytes or contains invalid hex characters.
pub fn x2c(what: &str) -> u8 {
    assert_eq!(what.len(), 2, "x2c requires exactly 2 hex characters");

    // Use stdlib's from_str_radix for cleaner, safer code
    u8::from_str_radix(what, 16).expect("x2c requires valid hex characters")
}

/// Removes surrounding quotes from a string if present.
///
/// Removes quotes only if the string both starts and ends with the same quote
/// character (either `"` or `'`). Otherwise returns the string unchanged.
///
/// # Examples
///
/// ```
/// use coraza::utils::strings::maybe_remove_quotes;
///
/// assert_eq!(maybe_remove_quotes(r#""hello""#), "hello");
/// assert_eq!(maybe_remove_quotes("'world'"), "world");
/// assert_eq!(maybe_remove_quotes(r#""mismatched'"#), r#""mismatched'"#);
/// assert_eq!(maybe_remove_quotes(r#""incomplete"#), r#""incomplete"#);
/// assert_eq!(maybe_remove_quotes(""), "");
/// assert_eq!(maybe_remove_quotes(r#"""#), r#"""#);
/// ```
pub fn maybe_remove_quotes(s: &str) -> &str {
    if s.len() < 2 {
        return s;
    }

    // Check if it starts and ends with matching quotes
    let starts_with_quote = s.starts_with('"') || s.starts_with('\'');
    let ends_with_quote = s.ends_with('"') || s.ends_with('\'');

    if starts_with_quote && ends_with_quote && s.as_bytes()[0] == s.as_bytes()[s.len() - 1] {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Unescapes `\"` sequences to `"` in SecLang quoted strings.
///
/// This is the ONLY escape sequence recognized by the SecLang quoted string
/// parser. Backslashes before any other character (including other backslashes)
/// are left as-is so that operator arguments like regex patterns are passed
/// through unchanged.
///
/// # Examples
///
/// ```
/// use coraza::utils::strings::unescape_quoted_string;
///
/// assert_eq!(unescape_quoted_string(r#"hello \"world\""#), r#"hello "world""#);
/// assert_eq!(unescape_quoted_string(r#"\""#), r#"""#);
/// assert_eq!(unescape_quoted_string(r#"\\"#), r#"\\"#);  // Backslash NOT escaped
/// assert_eq!(unescape_quoted_string(r#"\n"#), r#"\n"#);  // Other escapes NOT processed
/// assert_eq!(unescape_quoted_string(r#"@rx C:\\"#), r#"@rx C:\\"#);
/// assert_eq!(unescape_quoted_string("no escapes"), "no escapes");
/// ```
pub fn unescape_quoted_string(s: &str) -> String {
    // Fast path: if no backslashes, return unchanged
    if !s.contains('\\') {
        return s.to_string();
    }

    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() && bytes[i + 1] == b'"' {
            // Unescape \" -> "
            result.push('"');
            i += 2; // Skip both the backslash and quote
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }

    result
}

/// Wraps a byte slice as a string without copying or validation.
///
/// # Safety
///
/// The caller must ensure:
/// - The byte slice contains valid UTF-8
/// - The byte slice will not be mutated after calling this function
///
/// # Examples
///
/// ```
/// use coraza::utils::strings::wrap_unsafe;
///
/// let bytes = b"hello";
/// let s = unsafe { wrap_unsafe(bytes) };
/// assert_eq!(s, "hello");
/// ```
#[inline]
pub unsafe fn wrap_unsafe(buf: &[u8]) -> &str {
    // SAFETY: Caller guarantees buf is valid UTF-8
    unsafe { std::str::from_utf8_unchecked(buf) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_string_length() {
        assert_eq!(random_string(0).len(), 0);
        assert_eq!(random_string(1).len(), 1);
        assert_eq!(random_string(10).len(), 10);
        assert_eq!(random_string(100).len(), 100);
    }

    #[test]
    fn test_random_string_chars() {
        let s = random_string(1000);
        assert!(s.chars().all(|c| c.is_ascii_alphabetic()));
    }

    #[test]
    fn test_random_string_uniqueness() {
        // Random strings should be different (probabilistically)
        let s1 = random_string(20);
        let s2 = random_string(20);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_random_string_concurrent() {
        // Test thread safety - should not panic
        std::thread::scope(|s| {
            for _ in 0..100 {
                s.spawn(|| {
                    random_string(100);
                });
            }
        });
    }

    #[test]
    fn test_hex_value() {
        for (digit, value) in [
            (b'0', 0),
            (b'9', 9),
            (b'a', 10),
            (b'f', 15),
            (b'A', 10),
            (b'F', 15),
        ] {
            assert_eq!(hex_value(digit), Some(value));
        }
        for &digit in b"gGz /:@" {
            assert_eq!(hex_value(digit), None);
        }
    }

    #[test]
    fn test_x2c() {
        assert_eq!(x2c("00"), 0);
        assert_eq!(x2c("09"), 9);
        assert_eq!(x2c("0a"), 10);
        assert_eq!(x2c("0A"), 10);
        assert_eq!(x2c("0f"), 15);
        assert_eq!(x2c("0F"), 15);
        assert_eq!(x2c("10"), 16);
        assert_eq!(x2c("20"), 32);
        assert_eq!(x2c("41"), b'A'); // 0x41 = 65 = 'A'
        assert_eq!(x2c("ff"), 255);
        assert_eq!(x2c("FF"), 255);
        assert_eq!(x2c("Ff"), 255);
    }

    #[test]
    #[should_panic]
    fn test_x2c_invalid_length() {
        x2c("1"); // Too short
    }

    #[test]
    #[should_panic]
    fn test_x2c_invalid_char() {
        x2c("GG"); // Invalid hex
    }

    #[test]
    fn test_maybe_remove_quotes() {
        // Empty and short strings
        assert_eq!(maybe_remove_quotes(""), "");
        assert_eq!(maybe_remove_quotes("\""), "\"");

        // Double quotes
        assert_eq!(maybe_remove_quotes("\"\""), "");
        assert_eq!(maybe_remove_quotes("'value\""), "'value\"");
        assert_eq!(maybe_remove_quotes("\"hello world\""), "hello world");
        assert_eq!(
            maybe_remove_quotes("\"hello \\\"world\""),
            "hello \\\"world"
        );

        // Single quotes
        assert_eq!(maybe_remove_quotes("'hello world'"), "hello world");
        assert_eq!(maybe_remove_quotes("'hello \"world'"), "hello \"world");
        assert_eq!(maybe_remove_quotes("'hello \\'world'"), "hello \\'world");

        // Mixed quotes (no removal)
        assert_eq!(maybe_remove_quotes("\"hello world'"), "\"hello world'");
        assert_eq!(maybe_remove_quotes("'hello world\""), "'hello world\"");

        // Incomplete quotes (no removal)
        assert_eq!(maybe_remove_quotes("\"hello world"), "\"hello world");
        assert_eq!(maybe_remove_quotes("'hello world"), "'hello world");

        // No quotes
        assert_eq!(maybe_remove_quotes("hello world"), "hello world");

        // Unicode content
        assert_eq!(
            maybe_remove_quotes("\"\\x{30cf}\\x{30ed}\\x{30fc} world\""),
            "\\x{30cf}\\x{30ed}\\x{30fc} world"
        );
        assert_eq!(maybe_remove_quotes("\"\\s\\x5c.*\""), "\\s\\x5c.*");
    }

    #[test]
    fn test_unescape_quoted_string() {
        // Empty and simple strings
        assert_eq!(unescape_quoted_string(""), "");
        assert_eq!(unescape_quoted_string("hello"), "hello");

        // Escaped quotes
        assert_eq!(unescape_quoted_string("\\\""), "\"");
        assert_eq!(
            unescape_quoted_string("hello \\\"world\\\""),
            "hello \"world\""
        );
        assert_eq!(unescape_quoted_string("@contains \\\""), "@contains \"");

        // Backslashes NOT escaped
        assert_eq!(unescape_quoted_string("\\\\"), "\\\\");
        assert_eq!(unescape_quoted_string("@rx C:\\\\"), "@rx C:\\\\");

        // Other escapes NOT processed
        assert_eq!(unescape_quoted_string("\\n"), "\\n");
        assert_eq!(unescape_quoted_string("\\t"), "\\t");
        assert_eq!(unescape_quoted_string("\\r"), "\\r");

        // No escapes
        assert_eq!(unescape_quoted_string("no escapes here"), "no escapes here");
    }

    #[test]
    fn test_wrap_unsafe() {
        let bytes = b"hello world";
        let s = unsafe { wrap_unsafe(bytes) };
        assert_eq!(s, "hello world");

        let empty: &[u8] = b"";
        let s = unsafe { wrap_unsafe(empty) };
        assert_eq!(s, "");

        let unicode = "Hello 世界".as_bytes();
        let s = unsafe { wrap_unsafe(unicode) };
        assert_eq!(s, "Hello 世界");
    }
}
