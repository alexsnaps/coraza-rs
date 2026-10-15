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

pub mod map;
pub mod single;

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
    /// The value of the variable
    pub value: String,
}

impl MatchData {
    /// Create a new MatchData instance.
    pub fn new(variable: RuleVariable, key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            variable,
            key: key.into(),
            value: value.into(),
        }
    }

    /// Create a MatchData instance without a key.
    pub fn without_key(variable: RuleVariable, value: impl Into<String>) -> Self {
        Self {
            variable,
            key: String::new(),
            value: value.into(),
        }
    }

    /// Create an empty MatchData instance for operator-less rules.
    ///
    /// Used for rules without operators (SecAction, SecMarker) that always match.
    pub fn new_empty() -> Self {
        Self {
            variable: RuleVariable::Unknown,
            key: String::new(),
            value: String::new(),
        }
    }
}
