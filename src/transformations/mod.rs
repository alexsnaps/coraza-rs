// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Transformation functions for WAF data processing.
//!
//! Transformations are functions that modify input data before it's passed to
//! rule operators. They return:
//! - The transformed string
//! - A boolean indicating if the data was changed
//! - An optional error (for logging only, doesn't stop execution)

pub mod complex;
mod encoding;
pub mod escape;
mod simple;

pub use complex::{
    cmd_line, html_entity_decode, normalise_path, normalise_path_win, remove_comments,
    replace_comments,
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
/// - `String`: The transformed data
/// - `bool`: Whether the data was changed
/// - `Option<TransformationError>`: Optional error (for logging only)
pub type TransformationResult = (String, bool, Option<TransformationError>);

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
pub fn by_name(name: &str) -> Option<crate::rules::transformation::Transformation> {
    use crate::rules::transformation::Transformation;

    // Adapters for transformations that don't report errors.
    macro_rules! infallible {
        ($f:path) => {
            (|input| {
                let (output, changed) = $f(input);
                (output, changed, None)
            }) as Transformation
        };
    }

    let function: Transformation = match name.to_ascii_lowercase().as_str() {
        "base64decode" => base64_decode,
        "base64decodeext" => base64_decode_ext,
        "base64encode" => base64_encode,
        "cmdline" => infallible!(cmd_line),
        "compresswhitespace" => compress_whitespace,
        "cssdecode" => infallible!(css_decode),
        "escapeseqdecode" => infallible!(escape_seq_decode),
        "hexdecode" => hex_decode,
        "hexencode" => hex_encode,
        "htmlentitydecode" => infallible!(html_entity_decode),
        "jsdecode" => infallible!(js_decode),
        "length" => length,
        "lowercase" => lowercase,
        "md5" => md5_hash,
        "none" => none,
        "normalisepath" | "normalizepath" => infallible!(normalise_path),
        "normalisepathwin" | "normalizepathwin" => infallible!(normalise_path_win),
        "removecomments" => infallible!(remove_comments),
        "removenulls" => remove_nulls,
        "removewhitespace" => remove_whitespace,
        "replacecomments" => infallible!(replace_comments),
        "replacenulls" => replace_nulls,
        "sha1" => sha1_hash,
        "trim" => trim,
        "trimleft" => trim_left,
        "trimright" => trim_right,
        "uppercase" => uppercase,
        "urldecode" => url_decode,
        "urldecodeuni" => infallible!(url_decode_uni),
        "urlencode" => url_encode,
        "utf8tounicode" => infallible!(utf8_to_unicode),
        _ => return None,
    };
    Some(function)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn by_name_is_case_insensitive() {
        let f = by_name("urlDecode").unwrap();
        assert_eq!(f("a%20b").0, "a b");
        assert!(by_name("URLDECODE").is_some());
    }

    #[test]
    fn by_name_adapts_infallible_transformations() {
        let f = by_name("cmdLine").unwrap();
        assert_eq!(f("C^AT").0, cmd_line("C^AT").0);
    }

    #[test]
    fn by_name_rejects_unknown() {
        assert!(by_name("noSuchThing").is_none());
    }
}
