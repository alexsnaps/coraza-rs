// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Transformation functions for WAF data processing.
//!
//! Transformations are functions that modify input data before it's passed to
//! rule operators. They return:
//! - The transformed string
//! - A boolean indicating if the data was changed
//! - An optional error (for logging only, doesn't stop execution)

mod simple;

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
