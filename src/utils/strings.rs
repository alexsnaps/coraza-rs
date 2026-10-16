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
pub fn hex_value(digit: u8) -> Option<u8> {
    char::from(digit).to_digit(16).map(|value| value as u8)
}

/// The byte two hex digits encode, e.g. `b"41"` for `A`.
///
/// Check digits with [`u8::is_ascii_hexdigit`] first.
///
/// # Panics
///
/// Panics if `what` isn't exactly two hex digits.
pub fn x2c(what: &[u8]) -> u8 {
    let &[high, low] = what else {
        panic!("x2c requires exactly 2 hex digits");
    };
    let digit = |digit| hex_value(digit).expect("x2c requires valid hex digits");
    (digit(high) << 4) | digit(low)
}

/// Removes surrounding quotes from a string if present.
///
/// Removes quotes only if the string both starts and ends with the same quote
/// character (either `"` or `'`). Otherwise returns the string unchanged.
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
        assert_eq!(x2c(b"00"), 0);
        assert_eq!(x2c(b"09"), 9);
        assert_eq!(x2c(b"0a"), 10);
        assert_eq!(x2c(b"0A"), 10);
        assert_eq!(x2c(b"0f"), 15);
        assert_eq!(x2c(b"0F"), 15);
        assert_eq!(x2c(b"10"), 16);
        assert_eq!(x2c(b"20"), 32);
        assert_eq!(x2c(b"41"), b'A'); // 0x41 = 65 = 'A'
        assert_eq!(x2c(b"ff"), 255);
        assert_eq!(x2c(b"FF"), 255);
        assert_eq!(x2c(b"Ff"), 255);
    }

    #[test]
    #[should_panic]
    fn test_x2c_invalid_length() {
        x2c(b"1"); // Too short
    }

    #[test]
    #[should_panic]
    fn test_x2c_invalid_char() {
        x2c(b"GG"); // Invalid hex
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

    /// The doc example of `utils::strings::random_string`, before it became internal.
    #[test]
    fn doc_random_string() {
        use crate::utils::strings::random_string;

        let id = random_string(16);
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_alphabetic()));
    }

    /// The doc example of `utils::strings::hex_value`, before it became internal.
    #[test]
    fn doc_hex_value() {
        use crate::utils::strings::hex_value;

        assert_eq!(hex_value(b'7'), Some(7));
        assert_eq!(hex_value(b'b'), Some(11));
        assert_eq!(hex_value(b'F'), Some(15));
        assert_eq!(hex_value(b'g'), None);
    }

    /// The doc example of `utils::strings::x2c`, before it became internal.
    #[test]
    fn doc_x2c() {
        use crate::utils::strings::x2c;

        assert_eq!(x2c(b"41"), b'A'); // 0x41 = 65 = 'A'
        assert_eq!(x2c(b"0a"), 10);
        assert_eq!(x2c(b"FF"), 255);
        assert_eq!(x2c(b"00"), 0);
    }

    /// The doc example of `utils::strings::maybe_remove_quotes`, before it became internal.
    #[test]
    fn doc_maybe_remove_quotes() {
        use crate::utils::strings::maybe_remove_quotes;

        assert_eq!(maybe_remove_quotes(r#""hello""#), "hello");
        assert_eq!(maybe_remove_quotes("'world'"), "world");
        assert_eq!(maybe_remove_quotes(r#""mismatched'"#), r#""mismatched'"#);
        assert_eq!(maybe_remove_quotes(r#""incomplete"#), r#""incomplete"#);
        assert_eq!(maybe_remove_quotes(""), "");
        assert_eq!(maybe_remove_quotes(r#"""#), r#"""#);
    }
}
