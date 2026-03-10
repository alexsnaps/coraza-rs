// Copyright 2024 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

//! Concatenated collection implementations.
//!
//! Provides views over multiple collections that combine their results.

use super::{Collection, Keyed, MatchData};
use crate::RuleVariable;
use regex::Regex;

/// A collection view over multiple collections.
///
/// Combines results from all underlying collections when queried.
///
/// # Examples
///
/// ```
/// use coraza::collection::{ConcatCollection, Collection, Map, MapCollection};
/// use coraza::RuleVariable;
///
/// let mut map1 = Map::new(RuleVariable::Args);
/// map1.add("key1", "value1");
///
/// let mut map2 = Map::new(RuleVariable::ArgsGet);
/// map2.add("key2", "value2");
///
/// let concat = ConcatCollection::new(
///     RuleVariable::Args,
///     vec![&map1, &map2],
/// );
///
/// // find_all() returns results from both collections
/// assert_eq!(concat.find_all().len(), 2);
/// ```
pub struct ConcatCollection<'a> {
    data: Vec<&'a dyn Collection>,
    variable: RuleVariable,
}

impl<'a> ConcatCollection<'a> {
    /// Create a new concatenated collection.
    pub fn new(variable: RuleVariable, data: Vec<&'a dyn Collection>) -> Self {
        Self { data, variable }
    }
}

impl<'a> Collection for ConcatCollection<'a> {
    fn find_all(&self) -> Vec<MatchData> {
        let mut result = Vec::new();
        for collection in &self.data {
            for mut match_data in collection.find_all() {
                // Replace the variable with our own
                match_data.variable = self.variable;
                result.push(match_data);
            }
        }
        result
    }

    fn name(&self) -> &str {
        self.variable.name()
    }
}

/// A keyed collection view over multiple keyed collections.
///
/// Combines results from all underlying keyed collections.
pub struct ConcatKeyed<'a> {
    data: Vec<&'a dyn Keyed>,
    variable: RuleVariable,
}

impl<'a> ConcatKeyed<'a> {
    /// Create a new concatenated keyed collection.
    pub fn new(variable: RuleVariable, data: Vec<&'a dyn Keyed>) -> Self {
        Self { data, variable }
    }
}

impl<'a> Collection for ConcatKeyed<'a> {
    fn find_all(&self) -> Vec<MatchData> {
        let mut result = Vec::new();
        for collection in &self.data {
            for mut match_data in collection.find_all() {
                match_data.variable = self.variable;
                result.push(match_data);
            }
        }
        result
    }

    fn name(&self) -> &str {
        self.variable.name()
    }
}

impl<'a> Keyed for ConcatKeyed<'a> {
    fn get(&self, key: &str) -> Vec<String> {
        let mut result = Vec::new();
        let key_lower = key.to_lowercase();
        for collection in &self.data {
            result.extend(collection.get(&key_lower));
        }
        result
    }

    fn find_regex(&self, regex: &Regex) -> Vec<MatchData> {
        let mut result = Vec::new();
        for collection in &self.data {
            for mut match_data in collection.find_regex(regex) {
                match_data.variable = self.variable;
                result.push(match_data);
            }
        }
        result
    }

    fn find_string(&self, key: &str) -> Vec<MatchData> {
        let mut result = Vec::new();
        for collection in &self.data {
            for mut match_data in collection.find_string(key) {
                match_data.variable = self.variable;
                result.push(match_data);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collection::{Map, MapCollection};

    #[test]
    fn test_concat_collection() {
        let mut map1 = Map::new(RuleVariable::Args);
        map1.add("key1", "value1");

        let mut map2 = Map::new(RuleVariable::ArgsGet);
        map2.add("key2", "value2");

        let concat = ConcatCollection::new(
            RuleVariable::Args,
            vec![&map1 as &dyn Collection, &map2 as &dyn Collection],
        );

        let matches = concat.find_all();
        assert_eq!(matches.len(), 2);
        // All matches should have the concat variable, not the original
        assert!(matches.iter().all(|m| m.variable == RuleVariable::Args));
    }

    #[test]
    fn test_concat_keyed() {
        let mut map1 = Map::new_case_sensitive(RuleVariable::Args);
        map1.add("key1", "value1");
        map1.add("key2", "value2");

        let mut map2 = Map::new_case_sensitive(RuleVariable::ArgsGet);
        map2.add("key2", "value3");
        map2.add("key3", "value4");

        let concat = ConcatKeyed::new(
            RuleVariable::Args,
            vec![&map1 as &dyn Keyed, &map2 as &dyn Keyed],
        );

        // Get key2 from both collections
        let values = concat.get("key2");
        assert_eq!(values.len(), 2);
        assert!(values.contains(&"value2".to_string()));
        assert!(values.contains(&"value3".to_string()));

        // find_all returns all values
        let matches = concat.find_all();
        assert_eq!(matches.len(), 4);
    }

    #[test]
    fn test_concat_keyed_regex() {
        let mut map1 = Map::new_case_sensitive(RuleVariable::Args);
        map1.add("key1", "value1");
        map1.add("other", "value2");

        let mut map2 = Map::new_case_sensitive(RuleVariable::ArgsGet);
        map2.add("key2", "value3");

        let concat = ConcatKeyed::new(
            RuleVariable::Args,
            vec![&map1 as &dyn Keyed, &map2 as &dyn Keyed],
        );

        let regex = Regex::new("key.*").unwrap();
        let matches = concat.find_regex(&regex);
        assert_eq!(matches.len(), 2);
    }
}
