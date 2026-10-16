// Copyright 2024 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

//! Collection types for storing and retrieving variable data.
//!
//! Collections are used to store transaction data such as request headers,
//! query parameters, cookies, etc. They support:
//! - Case-sensitive and case-insensitive key lookups
//! - Multiple values per key
//! - Regex-based key matching
//! - Finding all values in the collection
//!
//! # Collection types
//!
//! - [`Single`] - a variable with one value
//! - [`Map`] - a variable with values selected by key

use crate::RuleVariable;

mod map;
mod single;

pub use map::Map;
pub use single::Single;

/// Metadata about a matched variable during rule evaluation.
///
/// Contains information about which variable matched (e.g., ARGS, HEADERS),
/// the specific key (e.g., "id" in ARGS:id), and the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchData {
    /// The variable that matched (e.g., ARGS, REQUEST_HEADERS)
    pub variable: RuleVariable,
    /// The specific key (e.g., "id" for ARGS:id), empty if no key
    pub key: String,
    /// The value of the variable, as bytes
    pub value: Vec<u8>,
    /// The rule's `msg`, as expanded for this match; empty when not expanded or unset
    pub message: String,
    /// The rule's `logdata`, as expanded for this match; empty when not expanded or unset
    pub data: String,
}

impl MatchData {
    /// Create a new MatchData instance.
    pub(crate) fn new(
        variable: RuleVariable,
        key: impl Into<String>,
        value: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            variable,
            key: key.into(),
            value: value.into(),
            message: String::new(),
            data: String::new(),
        }
    }

    /// Create a MatchData instance without a key.
    pub(crate) fn without_key(variable: RuleVariable, value: impl Into<Vec<u8>>) -> Self {
        Self::new(variable, String::new(), value)
    }

    /// The value as text, invalid UTF-8 replaced with U+FFFD.
    pub fn value_text(&self) -> std::borrow::Cow<'_, str> {
        crate::transformations::text_of(&self.value)
    }

    /// Create an empty MatchData instance for operator-less rules.
    ///
    /// Used for rules without operators (SecAction, SecMarker) that always match.
    pub(crate) fn new_empty() -> Self {
        Self::new(RuleVariable::Unknown, String::new(), String::new())
    }
}
