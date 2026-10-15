//! Escape sequence decoding transformations.
//!
//! This module provides transformations for decoding various escape sequence formats
//! including C-style, JavaScript, CSS, and URL Unicode escapes.

use super::unicode_bestfit::best_fit_ascii;
use super::{TransformationResult, chars_lossy};
use crate::utils::strings::{hex_value, x2c};

/// C-style escape sequence decoding transformation.
///
/// Decodes C-style escape sequences including:
/// - Simple escapes: `\n`, `\t`, `\r`, `\a`, `\b`, `\f`, `\v`, `\\`, `\?`, `\'`, `\"`
/// - Octal escapes: `\OOO` (up to 3 octal digits, max value `\377`)
/// - Hex escapes: `\xHH` (exactly 2 hex digits)
///
/// # Arguments
///
/// * `input` - Input string that may contain C-style escape sequences
///
/// # Returns
///
/// Returns `(output, changed)` where:
/// - `output` is the decoded string
/// - `changed` is `true` if any escapes were decoded, `false` otherwise
///
/// # Examples
///
/// ```
/// # use coraza::transformations::escape::escape_seq_decode;
/// let (result, changed, _) = escape_seq_decode(b"\\n\\t\\r");
/// assert_eq!(result, b"\n\t\r");
/// assert!(changed);
///
/// let (result, changed, _) = escape_seq_decode(b"\\x41\\x42\\x43");
/// assert_eq!(result, b"ABC");
/// assert!(changed);
///
/// let (result, changed, _) = escape_seq_decode(b"\\101\\102\\103");
/// assert_eq!(result, b"ABC");
/// assert!(changed);
/// ```
pub fn escape_seq_decode(input: &[u8]) -> TransformationResult {
    if let Some(pos) = input.iter().position(|&b| b == b'\\') {
        let (output, changed) = do_escape_seq_decode(input, pos);
        (output, changed, None)
    } else {
        (input.to_vec(), false, None)
    }
}

fn do_escape_seq_decode(input: &[u8], pos: usize) -> (Vec<u8>, bool) {
    let input_bytes = input;
    let input_len = input_bytes.len();
    let mut result = Vec::with_capacity(input_len);
    let mut changed = false;

    // Copy bytes before first backslash
    result.extend_from_slice(&input_bytes[..pos]);
    let mut i = pos;

    while i < input_len {
        if input_bytes[i] == b'\\' && i + 1 < input_len {
            let mut matched = true;

            let c = match input_bytes[i + 1] {
                b'a' => b'\x07', // Alert (bell)
                b'b' => b'\x08', // Backspace
                b'f' => b'\x0C', // Form feed
                b'n' => b'\n',   // Newline
                b'r' => b'\r',   // Carriage return
                b't' => b'\t',   // Horizontal tab
                b'v' => b'\x0B', // Vertical tab
                b'\\' => b'\\',  // Backslash
                b'?' => b'?',    // Question mark
                b'\'' => b'\'',  // Single quote
                b'"' => b'"',    // Double quote
                _ => {
                    matched = false;
                    0
                }
            };

            if matched {
                result.push(c);
                i += 2;
                changed = true;
                continue;
            }

            // Check for hexadecimal escape: \xHH
            if input_bytes[i + 1] == b'x' || input_bytes[i + 1] == b'X' {
                if i + 3 < input_len
                    && input_bytes[i + 2].is_ascii_hexdigit()
                    && input_bytes[i + 3].is_ascii_hexdigit()
                {
                    let hex_byte = x2c(&input[i + 2..i + 4]);
                    result.push(hex_byte);
                    i += 4;
                    changed = true;
                    continue;
                } else {
                    // Invalid hex escape: skip \x and continue
                    i += 2;
                    changed = true;
                    continue;
                }
            }

            // Check for octal escape: \OOO
            if is_octal_digit(input_bytes[i + 1]) {
                let mut j = 2;
                while j < 4 && i + j < input_len && is_octal_digit(input_bytes[i + j]) {
                    j += 1;
                }

                // Parse octal value (truncate to u8 if needed)
                result.push((octal_value(&input[i + 1..i + j]) & 0xFF) as u8);
                i += j;
                changed = true;
                continue;
            }

            // Not a recognized escape, copy the character after backslash
            result.push(input_bytes[i + 1]);
            i += 2;
        } else {
            // Regular character
            result.push(input_bytes[i]);
            i += 1;
        }
    }

    (result, changed)
}

fn is_octal_digit(c: u8) -> bool {
    matches!(c, b'0'..=b'7')
}

/// The number octal `digits` (at most five, all checked with [`is_octal_digit`]) write.
fn octal_value(digits: &[u8]) -> u16 {
    digits
        .iter()
        .fold(0, |value, digit| value * 8 + u16::from(digit - b'0'))
}

/// JavaScript escape sequence decoding transformation.
///
/// Decodes JavaScript escape sequences including:
/// - Unicode escapes: `\uHHHH` (uses lower byte only, with full-width ASCII handling)
/// - Hex escapes: `\xHH` (exactly 2 hex digits)
/// - Octal escapes: `\OOO` (up to 3 octal digits, max value `\377`)
/// - Simple escapes: `\a`, `\b`, `\f`, `\n`, `\r`, `\t`, `\v`, `\\`, `\?`, `\'`, `\"`
///
/// Full-width ASCII (U+FF01 to U+FF5E) is converted to regular ASCII by adding 0x20
/// to the lower byte.
///
/// # Arguments
///
/// * `input` - Input string that may contain JavaScript escape sequences
///
/// # Returns
///
/// Returns `(output, changed)` where:
/// - `output` is the decoded string
/// - `changed` is `true` if any escapes were decoded, `false` otherwise
///
/// # Examples
///
/// ```
/// # use coraza::transformations::escape::js_decode;
/// let (result, changed, _) = js_decode(b"\\u0048\\u0065\\u006c\\u006c\\u006f");
/// assert_eq!(result, b"Hello");
/// assert!(changed);
///
/// let (result, changed, _) = js_decode(b"\\x48\\x65\\x6c\\x6c\\x6f");
/// assert_eq!(result, b"Hello");
/// assert!(changed);
///
/// // Full-width ASCII conversion (U+FF41 'ａ' -> 'a')
/// let (result, changed, _) = js_decode(b"\\uff41");
/// assert_eq!(result, b"a");
/// assert!(changed);
/// ```
pub fn js_decode(input: &[u8]) -> TransformationResult {
    if let Some(pos) = input.iter().position(|&b| b == b'\\') {
        let (output, changed) = do_js_decode(input, pos);
        (output, changed, None)
    } else {
        (input.to_vec(), false, None)
    }
}

fn do_js_decode(input: &[u8], pos: usize) -> (Vec<u8>, bool) {
    let input_bytes = input;
    let input_len = input_bytes.len();
    let mut result = Vec::with_capacity(input_len);
    let mut changed = false;

    // Copy bytes before first backslash
    result.extend_from_slice(&input_bytes[..pos]);
    let mut i = pos;

    while i < input_len {
        if input_bytes[i] == b'\\' && i + 1 < input_len {
            let mut matched = false;

            // Check for Unicode escape: \uHHHH
            if i + 5 < input_len
                && input_bytes[i + 1] == b'u'
                && input_bytes[i + 2].is_ascii_hexdigit()
                && input_bytes[i + 3].is_ascii_hexdigit()
                && input_bytes[i + 4].is_ascii_hexdigit()
                && input_bytes[i + 5].is_ascii_hexdigit()
            {
                // Use only the lower byte (last 2 hex digits)
                let mut byte = x2c(&input[i + 4..i + 6]);

                // Full-width ASCII (ff01 - ff5e) needs 0x20 added
                // Check if upper 2 hex digits are 'ff' or 'FF'
                if (input_bytes[i + 2] == b'f' || input_bytes[i + 2] == b'F')
                    && (input_bytes[i + 3] == b'f' || input_bytes[i + 3] == b'F')
                    && byte > 0x00
                    && byte < 0x5f
                {
                    byte = byte.wrapping_add(0x20);
                }

                result.push(byte);
                i += 6;
                changed = true;
                matched = true;
            }

            // Check for hex escape: \xHH
            if !matched
                && i + 3 < input_len
                && input_bytes[i + 1] == b'x'
                && input_bytes[i + 2].is_ascii_hexdigit()
                && input_bytes[i + 3].is_ascii_hexdigit()
            {
                let byte = x2c(&input[i + 2..i + 4]);
                result.push(byte);
                i += 4;
                changed = true;
                matched = true;
            }

            // Check for octal escape: \OOO
            if !matched && is_octal_digit(input_bytes[i + 1]) {
                let mut j = 1;
                while j < 4 && i + j < input_len && is_octal_digit(input_bytes[i + j]) {
                    j += 1;
                }

                // If we have 3 digits and first digit > 3, only use 2 digits to stay ≤ 255
                let octal_len = if j == 4 && input_bytes[i + 1] > b'3' {
                    3 // Use only 2 octal digits (positions i+1 and i+2)
                } else {
                    j
                };

                // At most 0o377
                result.push(octal_value(&input[i + 1..i + octal_len]) as u8);
                i += octal_len;
                changed = true;
                matched = true;
            }

            // Simple C-style escapes
            if !matched {
                let c = match input_bytes[i + 1] {
                    b'a' => b'\x07', // Alert (bell)
                    b'b' => b'\x08', // Backspace
                    b'f' => b'\x0C', // Form feed
                    b'n' => b'\n',   // Newline
                    b'r' => b'\r',   // Carriage return
                    b't' => b'\t',   // Horizontal tab
                    b'v' => b'\x0B', // Vertical tab
                    // For \?, \\, \', \" just remove the backslash
                    other => other,
                };

                result.push(c);
                i += 2;
                changed = true;
            }
        } else {
            // Regular character
            result.push(input_bytes[i]);
            i += 1;
        }
    }

    (result, changed)
}

/// CSS escape sequence decoding transformation.
///
/// Decodes CSS hex escapes in the format `\HHHHHH` where H is a hexadecimal digit.
/// CSS escapes can be 1-6 hex digits long. The transformation, as Go Coraza's:
/// - Decodes the escape to its code point, in UTF-8; U+FFFD for zero, a surrogate or a
///   value past U+10FFFF
/// - Ignores a single whitespace character after the hex escape
/// - Folds full-width ASCII (U+FF01 to U+FF5E) to ASCII
/// - Removes backslash before newline
/// - Removes backslash before non-hex characters
///
/// # Arguments
///
/// * `input` - Input string that may contain CSS escape sequences
///
/// # Returns
///
/// Returns `(output, changed)` where:
/// - `output` is the decoded string
/// - `changed` is `true` if any escapes were decoded, `false` otherwise
///
/// # Examples
///
/// ```
/// # use coraza::transformations::escape::css_decode;
/// let (result, changed, _) = css_decode(b"\\48\\65\\6c\\6c\\6f");
/// assert_eq!(result, b"Hello");
/// assert!(changed);
///
/// let (result, changed, _) = css_decode(b"\\000048");  // 6 hex digits
/// assert_eq!(result, b"H");
/// assert!(changed);
///
/// // Whitespace after hex escape is ignored
/// let (result, changed, _) = css_decode(b"\\48 ello");
/// assert_eq!(result, b"Hello");
/// assert!(changed);
/// ```
pub fn css_decode(input: &[u8]) -> TransformationResult {
    if let Some(pos) = input.iter().position(|&b| b == b'\\') {
        (do_css_decode(input, pos), true, None)
    } else {
        (input.to_vec(), false, None)
    }
}

fn do_css_decode(input: &[u8], pos: usize) -> Vec<u8> {
    let input_bytes = input;
    let input_len = input_bytes.len();
    let mut result = Vec::with_capacity(input_len);

    // Copy bytes before first backslash
    result.extend_from_slice(&input_bytes[..pos]);
    let mut i = pos;

    while i < input_len {
        if input_bytes[i] == b'\\' {
            // Is there at least one more byte?
            if i + 1 < input_len {
                i += 1; // Skip the backslash

                // Count hex digits (1-6)
                let mut j = 0;
                while j < 6 && i + j < input_len && input_bytes[i + j].is_ascii_hexdigit() {
                    j += 1;
                }

                if j > 0 {
                    // The escape is one code point, however many digits write it
                    let code = input[i..i + j].iter().fold(0, |code, &digit| {
                        (code << 4) | u32::from(hex_value(digit).expect("checked hex digit"))
                    });
                    let code = match code {
                        // Zero is invalid, as are surrogates and values past U+10FFFF
                        0 => u32::from(char::REPLACEMENT_CHARACTER),
                        // Full-width ASCII folds to ASCII, as in ModSecurity
                        0xff01..=0xff5e => code - 0xfee0,
                        _ => code,
                    };
                    let c = char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER);
                    result.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());

                    // Ignore a single whitespace after hex escape
                    if i + j < input_len && is_css_whitespace(input_bytes[i + j]) {
                        j += 1;
                    }

                    i += j;
                } else if input_bytes[i] == b'\n' {
                    // Backslash followed by newline: ignore both
                    i += 1;
                } else {
                    // Backslash followed by non-hex: remove backslash, keep character
                    result.push(input_bytes[i]);
                    i += 1;
                }
            } else {
                // Trailing backslash: ignore it
                i += 1;
            }
        } else {
            // Regular character
            result.push(input_bytes[i]);
            i += 1;
        }
    }

    result
}

/// Checks if a byte is CSS whitespace
fn is_css_whitespace(c: u8) -> bool {
    matches!(c, b' ' | b'\x0C' | b'\n' | b'\t' | b'\r' | b'\x0B')
}

/// URL decoding with Unicode support (IIS-specific %uHHHH encoding).
///
/// Decodes both standard URL encoding and IIS-specific Unicode encoding:
/// - Standard URL encoding: `%HH` (2 hex digits)
/// - IIS Unicode encoding: `%uHHHH` (4 hex digits): the code point's best-fit ASCII
///   (`%u201c` is `"`) as ModSecurity's mapping for code page 20127 has it, as in Go
///   Coraza; otherwise its lower byte, with full-width ASCII (U+FF01 to U+FF5E) folded
///   to ASCII
/// - Plus to space conversion: `+` → ` `
///
/// # Arguments
///
/// * `input` - Input string that may contain URL-encoded data
///
/// # Returns
///
/// Returns `(output, changed)` where:
/// - `output` is the decoded string
/// - `changed` is `true` if anything was decoded; invalid escapes are kept as they are
///
/// # Examples
///
/// ```
/// # use coraza::transformations::escape::url_decode_uni;
/// let (result, changed, _) = url_decode_uni(b"Hello%20World");
/// assert_eq!(result, b"Hello World");
/// assert!(changed);
///
/// let (result, changed, _) = url_decode_uni(b"Hello+World");
/// assert_eq!(result, b"Hello World");
/// assert!(changed);
///
/// // IIS Unicode encoding
/// let (result, changed, _) = url_decode_uni(b"%u0048%u0065%u006c%u006c%u006f");
/// assert_eq!(result, b"Hello");
/// assert!(changed);
/// ```
pub fn url_decode_uni(input: &[u8]) -> TransformationResult {
    // Most values have nothing to decode, and `contains` searches a byte much faster
    // than the scan below, which was a tenth of a CRS transaction with a 10 KB argument
    if !input.contains(&b'%') && !input.contains(&b'+') {
        return (input.to_vec(), false, None);
    }
    let pos = input
        .iter()
        .position(|&b| b == b'%' || b == b'+')
        .expect("input holds a % or a +");
    let (output, changed) = do_url_decode_uni(input, pos);
    (output, changed, None)
}

fn do_url_decode_uni(input: &[u8], pos: usize) -> (Vec<u8>, bool) {
    let input_len = input.len();
    let mut result = Vec::with_capacity(input_len);
    // Whether something was decoded: an invalid escape is copied as it is
    let mut changed = false;

    // Copy bytes before first % or +
    result.extend_from_slice(&input[..pos]);
    let mut i = pos;

    while i < input_len {
        if input[i] == b'%' {
            // Check for IIS Unicode encoding: %uHHHH
            if i + 1 < input_len && (input[i + 1] == b'u' || input[i + 1] == b'U') {
                if i + 5 < input_len && input[i + 2..i + 6].iter().all(u8::is_ascii_hexdigit) {
                    let [high, low] = [x2c(&input[i + 2..i + 4]), x2c(&input[i + 4..i + 6])];
                    let byte = best_fit_ascii(u16::from_be_bytes([high, low])).unwrap_or(
                        // Otherwise the lower byte, full-width ASCII (U+FF01 to U+FF5E)
                        // folded to ASCII
                        if high == 0xff && low > 0x00 && low < 0x5f {
                            low + 0x20
                        } else {
                            low
                        },
                    );
                    result.push(byte);
                    i += 6;
                    changed = true;
                } else {
                    // Invalid %u sequence, keep %u as-is
                    result.extend_from_slice(&input[i..i + 2]);
                    i += 2;
                }
            } else if i + 2 < input_len
                && input[i + 1].is_ascii_hexdigit()
                && input[i + 2].is_ascii_hexdigit()
            {
                // Standard URL encoding: %HH
                result.push(x2c(&input[i + 1..i + 3]));
                i += 3;
                changed = true;
            } else {
                // Invalid % sequence, keep % as-is
                result.push(input[i]);
                i += 1;
            }
        } else if input[i] == b'+' {
            // Convert + to space
            result.push(b' ');
            i += 1;
            changed = true;
        } else {
            // Regular character
            result.push(input[i]);
            i += 1;
        }
    }

    (result, changed)
}

/// UTF-8 to Unicode encoding transformation.
///
/// Converts non-ASCII UTF-8 characters to %uHHHH format (IIS-style Unicode encoding).
/// ASCII characters (< 0x80) are left unchanged.
///
/// # Arguments
///
/// * `input` - Input string that may contain non-ASCII UTF-8 characters
///
/// # Returns
///
/// Returns `(output, changed)` where:
/// - `output` is the encoded string with non-ASCII as %uHHHH
/// - `changed` is `true` if any encoding occurred, `false` otherwise
///
/// # Examples
///
/// ```
/// # use coraza::transformations::escape::utf8_to_unicode;
/// let (result, changed, _) = utf8_to_unicode("café".as_bytes());
/// assert_eq!(result, b"caf%u00e9");
/// assert!(changed);
///
/// let (result, changed, _) = utf8_to_unicode(b"Hello");
/// assert_eq!(result, b"Hello");
/// assert!(!changed);
///
/// let (result, changed, _) = utf8_to_unicode("中文".as_bytes());
/// assert!(result.starts_with(b"%u"));
/// assert!(changed);
/// ```
pub fn utf8_to_unicode(input: &[u8]) -> TransformationResult {
    if input.is_ascii() {
        return (input.to_vec(), false, None);
    }

    let mut result = Vec::with_capacity(input.len() * 2);
    for c in chars_lossy(input).chars() {
        if c.is_ascii() {
            result.push(c as u8);
        } else {
            result.extend_from_slice(format!("%u{:04x}", u32::from(c)).as_bytes());
        }
    }
    (result, true, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transformations::on_text;

    // Test cases from escapeSeqDecode.json

    #[test]
    fn test_escape_seq_decode_empty() {
        let (result, changed, _) = on_text(escape_seq_decode, "");
        assert_eq!(result, "");
        assert!(!changed);
    }

    #[test]
    fn test_escape_seq_decode_no_escapes() {
        let (result, changed, _) = on_text(escape_seq_decode, "TestCase");
        assert_eq!(result, "TestCase");
        assert!(!changed);
    }

    #[test]
    fn test_escape_seq_decode_with_null() {
        let (result, changed, _) = on_text(escape_seq_decode, "Test\u{0000}Case");
        assert_eq!(result, "Test\u{0000}Case");
        assert!(!changed);
    }

    #[test]
    fn test_escape_seq_decode_comprehensive() {
        let (result, changed, _) =
            escape_seq_decode(b"\\a\\b\\f\\n\\r\\t\\v\\?\\'\\\"\\0\\12\\123\\x00\\xff");
        let expected: &[u8] = &[
            0x07, 0x08, 0x0C, 0x0A, 0x0D, 0x09, 0x0B, b'?', b'\'', b'"', 0x00, 0x0A, 0x53, 0x00,
            0xFF,
        ];
        assert_eq!(result, expected);
        assert!(changed);
    }

    #[test]
    fn test_escape_seq_decode_invalid_sequences() {
        // Invalid hex and octal sequences
        let (result, changed, _) = escape_seq_decode(b"\\8\\9\\666\\xag\\xga\\0123");
        // \8 -> 8, \9 -> 9, \666 -> \xb6 (0o666 = 182 = 0xb6), \xag -> ag, \xga -> ga, \0123 -> \x0a3 (0o12 = 10 = 0x0a, then '3')
        let expected: &[u8] = &[b'8', b'9', 0xb6, b'a', b'g', b'g', b'a', 0x0a, b'3'];
        assert_eq!(result, expected);
        assert!(changed);
    }

    #[test]
    fn test_escape_seq_decode_octal_single() {
        let (result, changed, _) = on_text(escape_seq_decode, "\\0");
        assert_eq!(result, "\x00");
        assert!(changed);
    }

    #[test]
    fn test_escape_seq_decode_octal_double() {
        let (result, changed, _) = on_text(escape_seq_decode, "\\01");
        assert_eq!(result, "\x01");
        assert!(changed);
    }

    #[test]
    fn test_escape_seq_decode_octal_triple() {
        let (result, changed, _) = on_text(escape_seq_decode, "\\012");
        assert_eq!(result, "\n"); // 0o12 = 10 = '\n'
        assert!(changed);
    }

    #[test]
    fn test_escape_seq_decode_trailing_backslash() {
        let (result, changed, _) = on_text(escape_seq_decode, "\\");
        assert_eq!(result, "\\");
        assert!(!changed);
    }

    #[test]
    fn test_escape_seq_decode_escaped_backslash() {
        let (result, changed, _) = on_text(escape_seq_decode, "\\\\u0000");
        assert_eq!(result, "\\u0000");
        assert!(changed);
    }

    // Test cases from jsDecode.json

    #[test]
    fn test_js_decode_empty() {
        let (result, changed, _) = on_text(js_decode, "");
        assert_eq!(result, "");
        assert!(!changed);
    }

    #[test]
    fn test_js_decode_no_escapes() {
        let (result, changed, _) = on_text(js_decode, "TestCase");
        assert_eq!(result, "TestCase");
        assert!(!changed);
    }

    #[test]
    fn test_js_decode_with_null() {
        let (result, changed, _) = on_text(js_decode, "Test\u{0000}Case");
        assert_eq!(result, "Test\u{0000}Case");
        assert!(!changed);
    }

    #[test]
    fn test_js_decode_unicode_escapes() {
        // \u0048\u0065\u006c\u006c\u006f -> "Hello"
        let (result, changed, _) = on_text(js_decode, "\\u0048\\u0065\\u006c\\u006c\\u006f");
        assert_eq!(result, "Hello");
        assert!(changed);
    }

    #[test]
    fn test_js_decode_hex_escapes() {
        // \x48\x65\x6c\x6c\x6f -> "Hello"
        let (result, changed, _) = on_text(js_decode, "\\x48\\x65\\x6c\\x6c\\x6f");
        assert_eq!(result, "Hello");
        assert!(changed);
    }

    #[test]
    fn test_js_decode_octal_escapes() {
        // \110\145\154\154\157 -> "Hello" (octal)
        let (result, changed, _) = on_text(js_decode, "\\110\\145\\154\\154\\157");
        assert_eq!(result, "Hello");
        assert!(changed);
    }

    #[test]
    fn test_js_decode_simple_escapes() {
        // \n\t\r -> newline, tab, carriage return
        let (result, changed, _) = on_text(js_decode, "\\n\\t\\r");
        assert_eq!(result, "\n\t\r");
        assert!(changed);
    }

    #[test]
    fn test_js_decode_full_width_ascii() {
        // \uff41 is full-width 'ａ' (U+FF41), should become 'a' (0x41 + 0x20 = 0x61)
        let (result, changed, _) = on_text(js_decode, "\\uff41");
        assert_eq!(result, "a");
        assert!(changed);

        // \uff21 is full-width 'Ａ' (U+FF21), should become 'A' (0x21 + 0x20 = 0x41)
        let (result, changed, _) = on_text(js_decode, "\\uff21");
        assert_eq!(result, "A");
        assert!(changed);
    }

    #[test]
    fn test_js_decode_mixed() {
        // Mix of different escape types
        let (result, changed, _) = on_text(js_decode, "\\u0048\\x65\\154\\154\\u006f");
        assert_eq!(result, "Hello");
        assert!(changed);
    }

    #[test]
    fn test_js_decode_incomplete_unicode() {
        // \u123 (incomplete, only 3 hex digits) - should pass through as-is
        let (result, changed, _) = on_text(js_decode, "\\u123x");
        assert_eq!(result, "u123x"); // Backslash removed, rest passed through
        assert!(changed);
    }

    #[test]
    fn test_js_decode_incomplete_hex() {
        // \x4 (incomplete, only 1 hex digit) - should pass through
        let (result, changed, _) = on_text(js_decode, "\\x4z");
        assert_eq!(result, "x4z"); // Backslash removed, rest passed through
        assert!(changed);
    }

    #[test]
    fn test_js_decode_octal_overflow() {
        // \777 would be 511 in octal, which overflows u8
        // Should use only first 2 digits: \77 = 63
        let (result, changed, _) = on_text(js_decode, "\\777");
        assert_eq!(result.as_bytes()[0], 0o77); // 63 in decimal
        assert!(changed);
    }

    // Test cases from cssDecode.json

    #[test]
    fn test_css_decode_empty() {
        let (result, changed, _) = on_text(css_decode, "");
        assert_eq!(result, "");
        assert!(!changed);
    }

    #[test]
    fn test_css_decode_no_escapes() {
        let (result, changed, _) = on_text(css_decode, "TestCase");
        assert_eq!(result, "TestCase");
        assert!(!changed);
    }

    #[test]
    fn test_css_decode_with_null() {
        let (result, changed, _) = on_text(css_decode, "Test\u{0000}Case");
        assert_eq!(result, "Test\u{0000}Case");
        assert!(!changed);
    }

    #[test]
    fn test_css_decode_hex_escapes() {
        // \48\65\6c\6c\6f -> "Hello"
        let (result, changed, _) = on_text(css_decode, "\\48\\65\\6c\\6c\\6f");
        assert_eq!(result, "Hello");
        assert!(changed);

        // \000048 (6 hex digits) -> "H"
        let (result, changed, _) = on_text(css_decode, "\\000048");
        assert_eq!(result, "H");
        assert!(changed);
    }

    #[test]
    fn test_css_decode_whitespace_after_hex() {
        // Whitespace after hex escape should be ignored
        let (result, changed, _) = on_text(css_decode, "\\48 ello");
        assert_eq!(result, "Hello");
        assert!(changed);

        // Tab after hex escape
        let (result, changed, _) = on_text(css_decode, "\\48\tello");
        assert_eq!(result, "Hello");
        assert!(changed);
    }

    #[test]
    fn test_css_decode_full_width_ascii() {
        // \ff41 is full-width 'ａ' (U+FF41), should become 'a' (0x41 + 0x20 = 0x61)
        let (result, changed, _) = on_text(css_decode, "\\00ff41");
        assert_eq!(result, "a");
        assert!(changed);
    }

    #[test]
    fn test_css_decode_backslash_newline() {
        // Backslash before newline should be ignored
        let (result, changed, _) = on_text(css_decode, "Hello\\\nWorld");
        assert_eq!(result, "HelloWorld");
        assert!(changed);
    }

    #[test]
    fn test_css_decode_backslash_non_hex() {
        // Backslash before non-hex character: remove backslash
        let (result, changed, _) = on_text(css_decode, "\\g\\h\\i");
        assert_eq!(result, "ghi");
        assert!(changed);
    }

    #[test]
    fn test_css_decode_trailing_backslash() {
        // Trailing backslash should be removed
        let (result, changed, _) = on_text(css_decode, "Hello\\");
        assert_eq!(result, "Hello");
        assert!(changed);
    }

    // Test cases from urlDecodeUni.json

    #[test]
    fn test_url_decode_uni_empty() {
        let (result, changed, _) = on_text(url_decode_uni, "");
        assert_eq!(result, "");
        assert!(!changed);
    }

    #[test]
    fn test_url_decode_uni_no_encoding() {
        let (result, changed, _) = on_text(url_decode_uni, "TestCase");
        assert_eq!(result, "TestCase");
        assert!(!changed);
    }

    #[test]
    fn test_url_decode_uni_with_null() {
        let (result, changed, _) = on_text(url_decode_uni, "Test\u{0000}Case");
        assert_eq!(result, "Test\u{0000}Case");
        assert!(!changed);
    }

    #[test]
    fn test_url_decode_uni_standard_percent() {
        // %20 -> space
        let (result, changed, _) = on_text(url_decode_uni, "Hello%20World");
        assert_eq!(result, "Hello World");
        assert!(changed);

        // %48%65%6c%6c%6f -> "Hello"
        let (result, changed, _) = on_text(url_decode_uni, "%48%65%6c%6c%6f");
        assert_eq!(result, "Hello");
        assert!(changed);
    }

    #[test]
    fn test_url_decode_uni_plus_to_space() {
        let (result, changed, _) = on_text(url_decode_uni, "Hello+World");
        assert_eq!(result, "Hello World");
        assert!(changed);
    }

    #[test]
    fn test_url_decode_uni_iis_unicode() {
        // %u0048%u0065%u006c%u006c%u006f -> "Hello"
        let (result, changed, _) = on_text(url_decode_uni, "%u0048%u0065%u006c%u006c%u006f");
        assert_eq!(result, "Hello");
        assert!(changed);
    }

    #[test]
    fn test_url_decode_uni_full_width_ascii() {
        // %uff41 is full-width 'ａ' (U+FF41), should become 'a'
        let (result, changed, _) = on_text(url_decode_uni, "%uff41");
        assert_eq!(result, "a");
        assert!(changed);
    }

    #[test]
    fn test_url_decode_uni_invalid_percent() {
        // %G is invalid (G is not hex), should keep %G
        let (result, changed, _) = on_text(url_decode_uni, "%GG");
        assert_eq!(result, "%GG");
        assert!(!changed); // Nothing was decoded, as in Go Coraza

        // %2 (incomplete) should keep %2
        let (result, changed, _) = on_text(url_decode_uni, "%2");
        assert_eq!(result, "%2");
        assert!(!changed);
    }

    #[test]
    fn test_url_decode_uni_invalid_unicode() {
        // %u12 (incomplete, only 2 hex digits) should keep %u12
        let (result, changed, _) = on_text(url_decode_uni, "%u12");
        assert_eq!(result, "%u12");
        assert!(!changed);

        // %uGGGG (invalid hex) should keep %uGGGG
        let (result, changed, _) = on_text(url_decode_uni, "%uGGGG");
        assert_eq!(result, "%uGGGG");
        assert!(!changed);
    }

    #[test]
    fn test_url_decode_uni_mixed() {
        // Mix of standard %, +, and %u encoding
        let (result, changed, _) = on_text(url_decode_uni, "Hello+%20%u0057orld");
        assert_eq!(result, "Hello  World");
        assert!(changed);
    }

    // Test cases from utf8toUnicode.json

    #[test]
    fn test_utf8_to_unicode_empty() {
        let (result, changed, _) = on_text(utf8_to_unicode, "");
        assert_eq!(result, "");
        assert!(!changed);
    }

    #[test]
    fn test_utf8_to_unicode_ascii_only() {
        let (result, changed, _) = on_text(utf8_to_unicode, "TestCase");
        assert_eq!(result, "TestCase");
        assert!(!changed);
    }

    #[test]
    fn test_utf8_to_unicode_with_null() {
        let (result, changed, _) = on_text(utf8_to_unicode, "Test\u{0000}Case");
        assert_eq!(result, "Test\u{0000}Case");
        assert!(!changed);
    }

    #[test]
    fn test_utf8_to_unicode_latin_chars() {
        // café -> caf%u00e9
        let (result, changed, _) = on_text(utf8_to_unicode, "café");
        assert_eq!(result, "caf%u00e9");
        assert!(changed);

        // naïve -> na%u00efve
        let (result, changed, _) = on_text(utf8_to_unicode, "naïve");
        assert_eq!(result, "na%u00efve");
        assert!(changed);
    }

    #[test]
    fn test_utf8_to_unicode_chinese() {
        // 中文 (Chinese characters)
        let (result, changed, _) = on_text(utf8_to_unicode, "中文");
        assert_eq!(result, "%u4e2d%u6587");
        assert!(changed);
    }

    #[test]
    fn test_utf8_to_unicode_mixed() {
        // Hello世界 -> Hello%u4e16%u754c
        let (result, changed, _) = on_text(utf8_to_unicode, "Hello世界");
        assert_eq!(result, "Hello%u4e16%u754c");
        assert!(changed);
    }

    #[test]
    fn test_bytes_that_are_not_utf8() {
        assert_eq!(escape_seq_decode(b"\\377\xfe").0, b"\xff\xfe");
        assert_eq!(js_decode(b"\\x80\\200").0, b"\x80\x80");
        // The escape is U+00FF, in UTF-8
        assert_eq!(css_decode(b"\\ff\xfe").0, b"\xc3\xbf\xfe");
        assert_eq!(url_decode_uni(b"%uff80%ff").0, b"\x80\xff");
        // As in Go, a byte that isn't part of a character is U+FFFD
        assert_eq!(utf8_to_unicode(b"a\xff").0, b"a%ufffd");
    }

    #[test]
    fn test_url_decode_uni_best_fit() {
        // Go Coraza's urlDecodeUni test data
        assert_eq!(
            on_text(url_decode_uni, "%u201dQuoted%u2019s%u2018 word%u2014dash").0,
            "\"Quoted's' word-dash"
        );
        assert_eq!(on_text(url_decode_uni, "%u0041%u00e9%u00e8").0, "Aee");
        // Unmapped: the lower byte
        assert_eq!(url_decode_uni(b"%u4e2d").0, b"\x2d");
        assert_eq!(url_decode_uni(b"%uff80").0, b"\x80");
    }

    #[test]
    fn test_css_decode_code_points() {
        // Go Coraza's cssDecode test data
        assert_eq!(
            on_text(css_decode, "\\123\\1234\\12345\\123456\\0").0,
            "\u{123}\u{1234}\u{12345}\u{FFFD}\u{FFFD}"
        );
        // Full-width ASCII folds to ASCII
        assert_eq!(on_text(css_decode, "\\ff01\\00ff5e").0, "!~");
        // A surrogate is U+FFFD
        assert_eq!(on_text(css_decode, "\\d800").0, "\u{FFFD}");
    }
}
