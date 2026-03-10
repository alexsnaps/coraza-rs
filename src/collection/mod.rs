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
//! # Collection Hierarchy
//!
//! - `Collection` - Base trait with `find_all()` and `name()`
//! - `Single` - Collection with a single value
//! - `Keyed` - Collection with key-value pairs
//! - `Map` - Keyed collection with mutation methods

use crate::RuleVariable;
use regex::Regex;

pub mod concat;
pub mod map;
pub mod noop;
pub mod single;

pub use concat::{ConcatCollection, ConcatKeyed};
pub use map::Map;
pub use noop::Noop;
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
}

/// Base trait for all collections.
///
/// Collections are used to store variable data for transactions.
/// They are NOT concurrent-safe.
pub trait Collection {
    /// Find all matches in this collection.
    fn find_all(&self) -> Vec<MatchData>;

    /// Get the name of this collection (e.g., "REQUEST_HEADERS").
    fn name(&self) -> &str;
}

/// A collection with a single element.
pub trait SingleCollection: Collection {
    /// Get the value of this single-value collection.
    fn get(&self) -> &str;
}

/// A collection with elements that can be selected by key.
pub trait Keyed: Collection {
    /// Get all values for a given key.
    ///
    /// Returns an empty Vec if the key doesn't exist.
    fn get(&self, key: &str) -> Vec<String>;

    /// Find all key-value pairs where the key matches the regex.
    fn find_regex(&self, key: &Regex) -> Vec<MatchData>;

    /// Find all key-value pairs for a specific key.
    ///
    /// If key is empty, returns all values (same as `find_all()`).
    fn find_string(&self, key: &str) -> Vec<MatchData>;
}

/// A mutable collection that supports adding, setting, and removing key-value pairs.
pub trait MapCollection: Keyed {
    /// Add a value to a key.
    ///
    /// If the key already exists, the value is appended to the list of values.
    fn add(&mut self, key: &str, value: &str);

    /// Set the values for a key, replacing any existing values.
    fn set(&mut self, key: &str, values: Vec<String>);

    /// Set the value at a specific index for a key.
    ///
    /// If the index is beyond the current size, the value is appended.
    fn set_index(&mut self, key: &str, index: usize, value: &str);

    /// Remove all values for a key.
    fn remove(&mut self, key: &str);

    /// Remove all key-value pairs from the collection.
    fn reset(&mut self);

    /// Get the number of distinct keys in the collection.
    fn len(&self) -> usize;

    /// Check if the collection is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
