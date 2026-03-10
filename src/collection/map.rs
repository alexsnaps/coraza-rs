// Copyright 2024 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

//! Map collection implementation.
//!
//! Provides key-value storage with optional case-insensitive keys.
//! Multiple values per key are supported.

use super::{Collection, Keyed, MapCollection, MatchData};
use crate::RuleVariable;
use regex::Regex;
use std::collections::HashMap;

/// A key-value collection that supports multiple values per key.
///
/// # Case Sensitivity
///
/// By default, keys are case-insensitive (useful for HTTP headers).
/// Use `new_case_sensitive()` for case-sensitive keys (useful for query parameters).
///
/// # Original Key Preservation
///
/// Even when using case-insensitive mode, the original key casing is preserved
/// and returned in `MatchData` results.
///
/// # Examples
///
/// ```
/// use coraza::collection::{Map, MapCollection, Keyed};
/// use coraza::RuleVariable;
///
/// let mut map = Map::new(RuleVariable::RequestHeaders);
/// map.add("Content-Type", "application/json");
/// map.add("content-type", "text/html");  // Same key, different case
///
/// // Case-insensitive lookup returns both values
/// let values = map.get("CONTENT-TYPE");
/// assert_eq!(values.len(), 2);
/// ```
pub struct Map {
    /// Whether keys are case-sensitive
    case_sensitive: bool,
    /// Internal storage: lookup_key -> Vec<KeyValue>
    /// The lookup_key is lowercase for case-insensitive maps
    data: HashMap<String, Vec<KeyValue>>,
    /// The variable this collection represents
    variable: RuleVariable,
}

/// Internal storage for a key-value pair.
///
/// Preserves the original key casing even when the map is case-insensitive.
#[derive(Debug, Clone)]
struct KeyValue {
    /// Original key (with original casing)
    key: String,
    /// Value
    value: String,
}

impl Map {
    /// Create a new map with case-insensitive keys.
    ///
    /// This is the default for collections like REQUEST_HEADERS.
    pub fn new(variable: RuleVariable) -> Self {
        Self {
            case_sensitive: false,
            data: HashMap::new(),
            variable,
        }
    }

    /// Create a new map with case-sensitive keys.
    ///
    /// This is used for collections like ARGS, ARGS_GET, ARGS_POST.
    pub fn new_case_sensitive(variable: RuleVariable) -> Self {
        Self {
            case_sensitive: true,
            data: HashMap::new(),
            variable,
        }
    }

    /// Get the lookup key (lowercase if case-insensitive).
    fn lookup_key(&self, key: &str) -> String {
        if self.case_sensitive {
            key.to_string()
        } else {
            key.to_lowercase()
        }
    }
}

impl Collection for Map {
    fn find_all(&self) -> Vec<MatchData> {
        let mut result = Vec::new();
        for values in self.data.values() {
            for kv in values {
                result.push(MatchData::new(
                    self.variable,
                    kv.key.clone(),
                    kv.value.clone(),
                ));
            }
        }
        result
    }

    fn name(&self) -> &str {
        self.variable.name()
    }

    fn as_keyed(&self) -> Option<&dyn Keyed> {
        Some(self)
    }
}

impl Keyed for Map {
    fn get(&self, key: &str) -> Vec<String> {
        let lookup = self.lookup_key(key);
        self.data
            .get(&lookup)
            .map(|values| values.iter().map(|kv| kv.value.clone()).collect())
            .unwrap_or_default()
    }

    fn find_regex(&self, regex: &Regex) -> Vec<MatchData> {
        let mut result = Vec::new();
        for (lookup_key, values) in &self.data {
            if regex.is_match(lookup_key) {
                for kv in values {
                    result.push(MatchData::new(
                        self.variable,
                        kv.key.clone(),
                        kv.value.clone(),
                    ));
                }
            }
        }
        result
    }

    fn find_string(&self, key: &str) -> Vec<MatchData> {
        if key.is_empty() {
            return self.find_all();
        }

        let lookup = self.lookup_key(key);
        self.data
            .get(&lookup)
            .map(|values| {
                values
                    .iter()
                    .map(|kv| MatchData::new(self.variable, kv.key.clone(), kv.value.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl MapCollection for Map {
    fn add(&mut self, key: &str, value: &str) {
        let lookup = self.lookup_key(key);
        let kv = KeyValue {
            key: key.to_string(),
            value: value.to_string(),
        };
        self.data.entry(lookup).or_default().push(kv);
    }

    fn set(&mut self, key: &str, values: Vec<String>) {
        let lookup = self.lookup_key(key);
        let key_values: Vec<KeyValue> = values
            .into_iter()
            .map(|value| KeyValue {
                key: key.to_string(),
                value,
            })
            .collect();
        self.data.insert(lookup, key_values);
    }

    fn set_index(&mut self, key: &str, index: usize, value: &str) {
        let lookup = self.lookup_key(key);
        let kv = KeyValue {
            key: key.to_string(),
            value: value.to_string(),
        };

        match self.data.get_mut(&lookup) {
            Some(values) if index < values.len() => {
                values[index] = kv;
            }
            Some(values) => {
                values.push(kv);
            }
            None => {
                self.data.insert(lookup, vec![kv]);
            }
        }
    }

    fn remove(&mut self, key: &str) {
        let lookup = self.lookup_key(key);
        self.data.remove(&lookup);
    }

    fn reset(&mut self) {
        self.data.clear();
    }

    fn len(&self) -> usize {
        self.data.len()
    }
}

impl std::fmt::Display for Map {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}:", self.name())?;
        for values in self.data.values() {
            if let Some(first) = values.first() {
                write!(f, "    {}: ", first.key)?;
                for (i, kv) in values.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{}", kv.value)?;
                }
                writeln!(f)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_case_insensitive() {
        let mut map = Map::new(RuleVariable::RequestHeaders);

        map.set_index("user", 1, "value");
        map.set("user-agent", vec!["value2".to_string()]);

        assert_eq!(map.get("user"), vec!["value"]);
        assert_eq!(map.get("USER"), vec!["value"]); // Case-insensitive
        assert!(!map.find_all().is_empty());
        assert!(map.find_string("a").is_empty());

        let regex = Regex::new("user.*").unwrap();
        assert_eq!(map.find_regex(&regex).len(), 2);

        map.add("user-agent", "value3");
        assert_eq!(map.get("user-agent").len(), 2);

        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_map_case_sensitive() {
        let mut map = Map::new_case_sensitive(RuleVariable::ArgsPost);

        map.set_index("key", 1, "value");
        map.set("key2", vec!["value2".to_string()]);

        assert_eq!(map.get("key"), vec!["value"]);
        assert!(map.get("KEY").is_empty()); // Case-sensitive
        assert!(!map.find_all().is_empty());
        assert!(map.find_string("a").is_empty());

        let regex = Regex::new("k.*").unwrap();
        assert_eq!(map.find_regex(&regex).len(), 2);

        map.add("key2", "value3");
        assert_eq!(map.get("key2").len(), 2);

        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_map_reset() {
        let mut map = Map::new(RuleVariable::RequestHeaders);
        map.add("key1", "value1");
        map.add("key2", "value2");
        assert_eq!(map.len(), 2);

        map.reset();
        assert_eq!(map.len(), 0);
        assert!(map.find_all().is_empty());
    }

    #[test]
    fn test_map_remove() {
        let mut map = Map::new(RuleVariable::RequestHeaders);
        map.add("key1", "value1");
        map.add("key2", "value2");
        assert_eq!(map.len(), 2);

        map.remove("key1");
        assert_eq!(map.len(), 1);
        assert!(map.get("key1").is_empty());
        assert_eq!(map.get("key2"), vec!["value2"]);
    }

    #[test]
    fn test_map_set_index_beyond_size() {
        let mut map = Map::new_case_sensitive(RuleVariable::Args);
        map.set_index("key", 0, "value0");
        map.set_index("key", 5, "value5"); // Index beyond size, should append

        let values = map.get("key");
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], "value0");
        assert_eq!(values[1], "value5");
    }

    #[test]
    fn test_map_multiple_values_same_key() {
        let mut map = Map::new_case_sensitive(RuleVariable::Args);
        map.add("id", "123");
        map.add("id", "456");
        map.add("id", "789");

        let values = map.get("id");
        assert_eq!(values.len(), 3);
        assert_eq!(values, vec!["123", "456", "789"]);
    }

    #[test]
    fn test_find_string_empty_key() {
        let mut map = Map::new(RuleVariable::RequestHeaders);
        map.add("key1", "value1");
        map.add("key2", "value2");

        // Empty key should return all values
        let results = map.find_string("");
        assert_eq!(results.len(), 2);
    }
}
