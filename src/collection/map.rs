// Copyright 2024 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

//! Map collection implementation.
//!
//! Provides key-value storage with optional case-insensitive keys.
//! Multiple values per key are supported.

use super::MatchData;
use crate::RuleVariable;
use regex::Regex;
use std::borrow::Cow;
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
/// use coraza::collection::Map;
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

    /// The key `key` is stored under: as it is in a case-sensitive map, lowercase otherwise.
    /// Borrowed when that is `key` itself, which spares lookups an allocation.
    fn lookup_key<'k>(&self, key: &'k str) -> Cow<'k, str> {
        if self.case_sensitive || !key.bytes().any(|b| b.is_ascii_uppercase() || !b.is_ascii()) {
            Cow::Borrowed(key)
        } else {
            Cow::Owned(key.to_lowercase())
        }
    }
}

impl Map {
    /// All key-value pairs, in no particular order.
    pub fn find_all(&self) -> Vec<MatchData> {
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

    /// Name of the variable this map holds (e.g. `ARGS`).
    pub fn name(&self) -> &str {
        self.variable.name()
    }

    /// All values for `key`; empty if the key is absent.
    pub fn get(&self, key: &str) -> Vec<String> {
        let lookup = self.lookup_key(key);
        self.data
            .get(lookup.as_ref())
            .map(|values| values.iter().map(|kv| kv.value.clone()).collect())
            .unwrap_or_default()
    }

    /// The first value of `key`; `None` if the key is absent.
    pub fn first(&self, key: &str) -> Option<&str> {
        let lookup = self.lookup_key(key);
        let values = self.data.get(lookup.as_ref())?;
        values.first().map(|kv| kv.value.as_str())
    }

    /// All key-value pairs whose (lookup) key matches `regex`.
    pub fn find_regex(&self, regex: &Regex) -> Vec<MatchData> {
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

    /// All key-value pairs for `key`; every pair if `key` is empty.
    pub fn find_string(&self, key: &str) -> Vec<MatchData> {
        if key.is_empty() {
            return self.find_all();
        }

        let lookup = self.lookup_key(key);
        self.data
            .get(lookup.as_ref())
            .map(|values| {
                values
                    .iter()
                    .map(|kv| MatchData::new(self.variable, kv.key.clone(), kv.value.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Appends `value` to the values of `key`.
    pub fn add(&mut self, key: &str, value: &str) {
        let lookup = self.lookup_key(key);
        let kv = KeyValue {
            key: key.to_string(),
            value: value.to_string(),
        };
        match self.data.get_mut(lookup.as_ref()) {
            Some(values) => values.push(kv),
            None => {
                self.data.insert(lookup.into_owned(), vec![kv]);
            }
        }
    }

    /// Replaces the values of `key`.
    pub fn set(&mut self, key: &str, values: Vec<String>) {
        let lookup = self.lookup_key(key);
        let key_values: Vec<KeyValue> = values
            .into_iter()
            .map(|value| KeyValue {
                key: key.to_string(),
                value,
            })
            .collect();
        self.data.insert(lookup.into_owned(), key_values);
    }

    /// Replaces the value at `index` of `key`, or appends it if `index` is past the end.
    pub fn set_index(&mut self, key: &str, index: usize, value: &str) {
        let lookup = self.lookup_key(key);
        let new = || KeyValue {
            key: key.to_string(),
            value: value.to_string(),
        };

        match self.data.get_mut(lookup.as_ref()) {
            // Rewritten in its buffers: RULE's values are set this way for every rule evaluated
            Some(values) if index < values.len() => {
                let kv = &mut values[index];
                kv.key.clear();
                kv.key.push_str(key);
                kv.value.clear();
                kv.value.push_str(value);
            }
            Some(values) => values.push(new()),
            None => {
                self.data.insert(lookup.into_owned(), vec![new()]);
            }
        }
    }

    /// Removes `key` and all its values.
    pub fn remove(&mut self, key: &str) {
        let lookup = self.lookup_key(key);
        self.data.remove(lookup.as_ref());
    }

    /// Removes every key.
    pub fn reset(&mut self) {
        self.data.clear();
    }

    /// Number of distinct keys.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Every key, lowercase in a case-insensitive map, with its values, sorted by key.
    pub fn entries(&self) -> std::collections::BTreeMap<String, Vec<String>> {
        self.data
            .iter()
            .map(|(key, values)| {
                let values = values.iter().map(|kv| kv.value.clone()).collect();
                (key.clone(), values)
            })
            .collect()
    }

    /// Number of values, counting each value of a repeated key.
    pub fn value_count(&self) -> usize {
        self.data.values().map(Vec::len).sum()
    }

    /// Whether the map has no keys.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
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
    fn test_map_lookup_lowercases_non_ascii_keys() {
        // Keys whose only uppercase letters aren't ASCII
        let mut map = Map::new(RuleVariable::RequestHeaders);
        map.add("Über", "value");

        assert_eq!(map.first("über"), Some("value"));
        assert_eq!(map.first("Über"), Some("value"));
        assert_eq!(map.find_string("über")[0].key, "Über");
        map.remove("Über");
        assert!(map.is_empty());
    }

    #[test]
    fn test_map_first() {
        let mut map = Map::new(RuleVariable::RequestHeaders);
        assert_eq!(map.first("key"), None);

        map.add("Key", "value1");
        map.add("KEY", "value2");
        assert_eq!(map.first("key"), Some("value1"));
    }

    #[test]
    fn test_map_set_index_rewrites_in_place() {
        let mut map = Map::new(RuleVariable::Rule);
        map.add("msg", "first");
        map.add("msg", "second");

        map.set_index("MSG", 0, "a longer message than before");
        assert_eq!(
            map.get("msg"),
            vec!["a longer message than before", "second"]
        );
        assert_eq!(map.find_string("msg")[0].key, "MSG");
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
