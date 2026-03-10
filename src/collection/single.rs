// Copyright 2024 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

//! Single-value collection implementation.

use super::{Collection, MatchData, SingleCollection};
use crate::RuleVariable;

/// A collection that holds a single string value.
///
/// Used for variables like REQUEST_URI, REQUEST_METHOD, etc.
///
/// # Examples
///
/// ```
/// use coraza::collection::{Single, SingleCollection};
/// use coraza::RuleVariable;
///
/// let mut single = Single::new(RuleVariable::RequestURI);
/// single.set("/api/users");
/// assert_eq!(single.get(), "/api/users");
/// ```
pub struct Single {
    data: String,
    variable: RuleVariable,
}

impl Single {
    /// Create a new single-value collection.
    pub fn new(variable: RuleVariable) -> Self {
        Self {
            data: String::new(),
            variable,
        }
    }

    /// Set the value.
    pub fn set(&mut self, value: impl Into<String>) {
        self.data = value.into();
    }

    /// Clear the value.
    pub fn reset(&mut self) {
        self.data.clear();
    }
}

impl Collection for Single {
    fn find_all(&self) -> Vec<MatchData> {
        vec![MatchData::without_key(self.variable, self.data.clone())]
    }

    fn name(&self) -> &str {
        self.variable.name()
    }
}

impl SingleCollection for Single {
    fn get(&self) -> &str {
        &self.data
    }
}

impl std::fmt::Display for Single {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.name(), self.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_new() {
        let single = Single::new(RuleVariable::RequestURI);
        assert_eq!(single.get(), "");
        assert_eq!(single.name(), "REQUEST_URI");
    }

    #[test]
    fn test_single_set() {
        let mut single = Single::new(RuleVariable::RequestMethod);
        single.set("GET");
        assert_eq!(single.get(), "GET");
    }

    #[test]
    fn test_single_reset() {
        let mut single = Single::new(RuleVariable::RequestMethod);
        single.set("POST");
        single.reset();
        assert_eq!(single.get(), "");
    }

    #[test]
    fn test_single_find_all() {
        let mut single = Single::new(RuleVariable::RequestURI);
        single.set("/api/users");

        let matches = single.find_all();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].variable, RuleVariable::RequestURI);
        assert_eq!(matches[0].key, "");
        assert_eq!(matches[0].value, "/api/users");
    }

    #[test]
    fn test_single_display() {
        let mut single = Single::new(RuleVariable::RequestURI);
        single.set("/test");
        assert_eq!(single.to_string(), "REQUEST_URI: /test");
    }
}
