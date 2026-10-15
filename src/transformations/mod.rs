// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Transformation functions for WAF data processing.
//!
//! Transformations are functions that modify input data before it's passed to
//! rule operators. They work on bytes, as in Go Coraza, so that a digest or a decoded
//! escape such as `%ff` keeps its bytes for the next transformation. They return:
//! - The transformed bytes
//! - A boolean indicating if the data was changed
//! - An optional error (for logging only, doesn't stop execution)

pub mod complex;
mod encoding;
pub mod escape;
mod simple;

pub use complex::{
    cmd_line, html_entity_decode, normalise_path, normalise_path_win, remove_comments,
    remove_comments_char, replace_comments,
};
pub use encoding::{
    base64_decode, base64_decode_ext, base64_encode, hex_decode, hex_encode, length, md5_hash,
    none, remove_nulls, replace_nulls, sha1_hash, url_encode,
};
pub use escape::{css_decode, escape_seq_decode, js_decode, url_decode_uni, utf8_to_unicode};
pub use simple::{
    compress_whitespace, lowercase, remove_whitespace, trim, trim_left, trim_right, uppercase,
    url_decode,
};

/// Result type for transformation functions.
///
/// The tuple contains:
/// - `Vec<u8>`: The transformed data, which need not be UTF-8
/// - `bool`: Whether the data was changed
/// - `Option<TransformationError>`: Optional error (for logging only)
pub type TransformationResult = (Vec<u8>, bool, Option<TransformationError>);

/// A transformation function, as used in a [`crate::rules::TransformationChain`].
pub type Transformation = fn(&[u8]) -> TransformationResult;

/// `bytes` as text: as they are if they are UTF-8, or with each invalid sequence
/// replaced by U+FFFD.
///
/// Collection values and operators work on text, so the bytes a transformation chain
/// produces become text here, once, for the operator.
pub(crate) fn text_from_bytes(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes)
        .unwrap_or_else(|invalid| String::from_utf8_lossy(invalid.as_bytes()).into_owned())
}

/// `text` with each byte that isn't part of a UTF-8 sequence replaced by U+FFFD, as Go
/// does when it reads a string as characters (`for range`, `strings.Map`).
fn chars_lossy(text: &[u8]) -> String {
    let mut chars = String::with_capacity(text.len());
    for chunk in text.utf8_chunks() {
        chars.push_str(chunk.valid());
        chars.extend(std::iter::repeat_n(
            char::REPLACEMENT_CHARACTER,
            chunk.invalid().len(),
        ));
    }
    chars
}

/// Error type for transformation operations.
///
/// Transformation errors are for logging only and don't stop rule execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformationError {
    message: String,
}

impl TransformationError {
    /// Creates a new transformation error.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for TransformationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "transformation error: {}", self.message)
    }
}

impl std::error::Error for TransformationError {}

/// Looks up a transformation by its SecLang name (case-insensitive), e.g. `urlDecode`.
///
/// Returns `None` for unknown names. `none` is a real (identity) transformation here;
/// clearing a rule's transformations with `t:none` is up to the caller.
pub fn by_name(name: &str) -> Option<Transformation> {
    let function: Transformation = match name.to_ascii_lowercase().as_str() {
        "base64decode" => base64_decode,
        "base64decodeext" => base64_decode_ext,
        "base64encode" => base64_encode,
        "cmdline" => cmd_line,
        "compresswhitespace" => compress_whitespace,
        "cssdecode" => css_decode,
        "escapeseqdecode" => escape_seq_decode,
        "hexdecode" => hex_decode,
        "hexencode" => hex_encode,
        "htmlentitydecode" => html_entity_decode,
        "jsdecode" => js_decode,
        "length" => length,
        "lowercase" => lowercase,
        "md5" => md5_hash,
        "none" => none,
        "normalisepath" | "normalizepath" => normalise_path,
        "normalisepathwin" | "normalizepathwin" => normalise_path_win,
        "removecomments" => remove_comments,
        "removecommentschar" => remove_comments_char,
        "removenulls" => remove_nulls,
        "removewhitespace" => remove_whitespace,
        "replacecomments" => replace_comments,
        "replacenulls" => replace_nulls,
        "sha1" => sha1_hash,
        "trim" => trim,
        "trimleft" => trim_left,
        "trimright" => trim_right,
        "uppercase" => uppercase,
        "urldecode" => url_decode,
        "urldecodeuni" => url_decode_uni,
        "urlencode" => url_encode,
        "utf8tounicode" => utf8_to_unicode,
        _ => return None,
    };
    Some(function)
}

/// `transformation` applied to `text`, its result as text, for tests of transformations
/// whose output is UTF-8.
///
/// # Panics
///
/// If the output isn't UTF-8.
#[cfg(test)]
pub(crate) fn on_text(
    transformation: Transformation,
    text: &str,
) -> (String, bool, Option<TransformationError>) {
    let (output, changed, error) = transformation(text.as_bytes());
    let output = String::from_utf8(output).expect("the transformation's output is UTF-8");
    (output, changed, error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn by_name_is_case_insensitive() {
        let f = by_name("urlDecode").unwrap();
        assert_eq!(f(b"a%20b").0, b"a b");
        assert!(by_name("URLDECODE").is_some());
    }

    #[test]
    fn chars_lossy_replaces_each_invalid_byte() {
        assert_eq!(chars_lossy("é".as_bytes()), "é");
        assert_eq!(chars_lossy(b"a\xffb"), "a\u{FFFD}b");
        // A truncated sequence is one replacement per byte, as in Go, not one per sequence
        assert_eq!(chars_lossy(b"\xf0\x9f\x98!"), "\u{FFFD}\u{FFFD}\u{FFFD}!");
    }

    #[test]
    fn by_name_rejects_unknown() {
        assert!(by_name("noSuchThing").is_none());
    }
}
