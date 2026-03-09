// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Simple comparison operators.
//!
//! This module implements basic comparison and string matching operators
//! without macro expansion support.

use crate::operators::Operator;

/// Numeric equality operator.
///
/// Performs numerical comparison and returns true if the input value equals
/// the parameter. Both values are converted to integers before comparison.
/// Invalid integers are treated as 0.
///
/// # Examples
///
/// ```
/// use coraza::operators::{Operator, eq};
///
/// let op = eq("15");
/// assert!(op.evaluate("15"));
/// assert!(op.evaluate("015")); // Leading zeros ignored
/// assert!(!op.evaluate("16"));
/// ```
#[derive(Debug, Clone)]
pub struct Eq {
    value: i32,
}

impl Operator for Eq {
    fn evaluate(&self, input: &str) -> bool {
        let input_val = input.parse::<i32>().unwrap_or(0);
        input_val == self.value
    }
}

/// Creates a new `eq` operator.
pub fn eq(parameter: &str) -> Eq {
    Eq {
        value: parameter.parse::<i32>().unwrap_or(0),
    }
}

/// Greater than operator.
///
/// Returns true if the input value is greater than the parameter.
/// Both values are converted to integers before comparison.
///
/// # Examples
///
/// ```
/// use coraza::operators::{Operator, gt};
///
/// let op = gt("10");
/// assert!(op.evaluate("15"));
/// assert!(!op.evaluate("10"));
/// assert!(!op.evaluate("5"));
/// ```
#[derive(Debug, Clone)]
pub struct Gt {
    value: i32,
}

impl Operator for Gt {
    fn evaluate(&self, input: &str) -> bool {
        let input_val = input.parse::<i32>().unwrap_or(0);
        input_val > self.value
    }
}

/// Creates a new `gt` operator.
pub fn gt(parameter: &str) -> Gt {
    Gt {
        value: parameter.parse::<i32>().unwrap_or(0),
    }
}

/// Greater than or equal operator.
///
/// Returns true if the input value is greater than or equal to the parameter.
///
/// # Examples
///
/// ```
/// use coraza::operators::{Operator, ge};
///
/// let op = ge("10");
/// assert!(op.evaluate("15"));
/// assert!(op.evaluate("10"));
/// assert!(!op.evaluate("5"));
/// ```
#[derive(Debug, Clone)]
pub struct Ge {
    value: i32,
}

impl Operator for Ge {
    fn evaluate(&self, input: &str) -> bool {
        let input_val = input.parse::<i32>().unwrap_or(0);
        input_val >= self.value
    }
}

/// Creates a new `ge` operator.
pub fn ge(parameter: &str) -> Ge {
    Ge {
        value: parameter.parse::<i32>().unwrap_or(0),
    }
}

/// Less than operator.
///
/// Returns true if the input value is less than the parameter.
///
/// # Examples
///
/// ```
/// use coraza::operators::{Operator, lt};
///
/// let op = lt("10");
/// assert!(op.evaluate("5"));
/// assert!(!op.evaluate("10"));
/// assert!(!op.evaluate("15"));
/// ```
#[derive(Debug, Clone)]
pub struct Lt {
    value: i32,
}

impl Operator for Lt {
    fn evaluate(&self, input: &str) -> bool {
        let input_val = input.parse::<i32>().unwrap_or(0);
        input_val < self.value
    }
}

/// Creates a new `lt` operator.
pub fn lt(parameter: &str) -> Lt {
    Lt {
        value: parameter.parse::<i32>().unwrap_or(0),
    }
}

/// Less than or equal operator.
///
/// Returns true if the input value is less than or equal to the parameter.
///
/// # Examples
///
/// ```
/// use coraza::operators::{Operator, le};
///
/// let op = le("10");
/// assert!(op.evaluate("5"));
/// assert!(op.evaluate("10"));
/// assert!(!op.evaluate("15"));
/// ```
#[derive(Debug, Clone)]
pub struct Le {
    value: i32,
}

impl Operator for Le {
    fn evaluate(&self, input: &str) -> bool {
        let input_val = input.parse::<i32>().unwrap_or(0);
        input_val <= self.value
    }
}

/// Creates a new `le` operator.
pub fn le(parameter: &str) -> Le {
    Le {
        value: parameter.parse::<i32>().unwrap_or(0),
    }
}

/// String equality operator.
///
/// Performs case-sensitive string comparison and returns true if the input
/// equals the parameter exactly.
///
/// # Examples
///
/// ```
/// use coraza::operators::{Operator, streq};
///
/// let op = streq("POST");
/// assert!(op.evaluate("POST"));
/// assert!(!op.evaluate("post"));
/// assert!(!op.evaluate("GET"));
/// ```
#[derive(Debug, Clone)]
pub struct StrEq {
    value: String,
}

impl Operator for StrEq {
    fn evaluate(&self, input: &str) -> bool {
        input == self.value
    }
}

/// Creates a new `streq` operator.
pub fn streq(parameter: &str) -> StrEq {
    StrEq {
        value: parameter.to_string(),
    }
}

/// Contains operator.
///
/// Returns true if the parameter string is found anywhere in the input.
///
/// # Examples
///
/// ```
/// use coraza::operators::{Operator, contains};
///
/// let op = contains(".php");
/// assert!(op.evaluate("/index.php"));
/// assert!(op.evaluate("test.php?id=1"));
/// assert!(!op.evaluate("/index.html"));
/// ```
#[derive(Debug, Clone)]
pub struct Contains {
    needle: String,
}

impl Operator for Contains {
    fn evaluate(&self, input: &str) -> bool {
        input.contains(&self.needle)
    }
}

/// Creates a new `contains` operator.
pub fn contains(parameter: &str) -> Contains {
    Contains {
        needle: parameter.to_string(),
    }
}

/// Begins with operator.
///
/// Returns true if the input starts with the parameter string.
///
/// # Examples
///
/// ```
/// use coraza::operators::{Operator, begins_with};
///
/// let op = begins_with("GET");
/// assert!(op.evaluate("GET /index.html HTTP/1.1"));
/// assert!(!op.evaluate("POST /index.html HTTP/1.1"));
/// ```
#[derive(Debug, Clone)]
pub struct BeginsWith {
    prefix: String,
}

impl Operator for BeginsWith {
    fn evaluate(&self, input: &str) -> bool {
        input.starts_with(&self.prefix)
    }
}

/// Creates a new `begins_with` operator.
pub fn begins_with(parameter: &str) -> BeginsWith {
    BeginsWith {
        prefix: parameter.to_string(),
    }
}

/// Ends with operator.
///
/// Returns true if the input ends with the parameter string.
///
/// # Examples
///
/// ```
/// use coraza::operators::{Operator, ends_with};
///
/// let op = ends_with(".exe");
/// assert!(op.evaluate("malware.exe"));
/// assert!(op.evaluate("C:\\Windows\\system32\\cmd.exe"));
/// assert!(!op.evaluate("document.pdf"));
/// ```
#[derive(Debug, Clone)]
pub struct EndsWith {
    suffix: String,
}

impl Operator for EndsWith {
    fn evaluate(&self, input: &str) -> bool {
        input.ends_with(&self.suffix)
    }
}

/// Creates a new `ends_with` operator.
pub fn ends_with(parameter: &str) -> EndsWith {
    EndsWith {
        suffix: parameter.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eq_valid_values() {
        let op = eq("1");

        assert!(op.evaluate("1"));
        assert!(op.evaluate("01")); // Leading zeros
        assert!(!op.evaluate("1.0")); // Float parsing fails, becomes 0
        assert!(!op.evaluate("2"));
        assert!(!op.evaluate("0"));
    }

    #[test]
    fn test_eq_invalid_values_return_zero() {
        let op = eq("a"); // Invalid, becomes 0

        assert!(op.evaluate("a")); // Also becomes 0
        assert!(op.evaluate("b")); // Also becomes 0
        assert!(op.evaluate("0")); // Explicitly 0
        assert!(!op.evaluate("1"));
    }

    #[test]
    fn test_eq_edge_cases() {
        assert!(eq("0").evaluate(""));
        assert!(eq("0").evaluate("invalid"));
        assert!(eq("123").evaluate("123"));
        assert!(eq("-5").evaluate("-5"));
    }

    #[test]
    fn test_gt() {
        let op = gt("10");

        assert!(op.evaluate("15"));
        assert!(op.evaluate("11"));
        assert!(!op.evaluate("10"));
        assert!(!op.evaluate("9"));
        assert!(!op.evaluate("0"));
    }

    #[test]
    fn test_ge() {
        let op = ge("10");

        assert!(op.evaluate("15"));
        assert!(op.evaluate("11"));
        assert!(op.evaluate("10"));
        assert!(!op.evaluate("9"));
        assert!(!op.evaluate("0"));
    }

    #[test]
    fn test_lt() {
        let op = lt("10");

        assert!(op.evaluate("9"));
        assert!(op.evaluate("0"));
        assert!(op.evaluate("-5"));
        assert!(!op.evaluate("10"));
        assert!(!op.evaluate("11"));
    }

    #[test]
    fn test_le() {
        let op = le("10");

        assert!(op.evaluate("9"));
        assert!(op.evaluate("10"));
        assert!(op.evaluate("0"));
        assert!(!op.evaluate("11"));
        assert!(!op.evaluate("15"));
    }

    #[test]
    fn test_streq() {
        let op = streq("POST");

        assert!(op.evaluate("POST"));
        assert!(!op.evaluate("post")); // Case sensitive
        assert!(!op.evaluate("GET"));
        assert!(!op.evaluate(""));
    }

    #[test]
    fn test_streq_empty() {
        let op = streq("");

        assert!(op.evaluate(""));
        assert!(!op.evaluate("anything"));
    }

    #[test]
    fn test_contains() {
        let op = contains(".php");

        assert!(op.evaluate("/index.php"));
        assert!(op.evaluate("test.php?id=1"));
        assert!(op.evaluate(".php"));
        assert!(!op.evaluate("/index.html"));
        assert!(!op.evaluate(""));
    }

    #[test]
    fn test_contains_empty() {
        let op = contains("");

        // Empty string is contained in everything
        assert!(op.evaluate("anything"));
        assert!(op.evaluate(""));
    }

    #[test]
    fn test_begins_with() {
        let op = begins_with("GET");

        assert!(op.evaluate("GET /index.html HTTP/1.1"));
        assert!(op.evaluate("GET"));
        assert!(!op.evaluate("POST /index.html HTTP/1.1"));
        assert!(!op.evaluate(" GET"));
        assert!(!op.evaluate(""));
    }

    #[test]
    fn test_begins_with_empty() {
        let op = begins_with("");

        // Everything starts with empty string
        assert!(op.evaluate("anything"));
        assert!(op.evaluate(""));
    }

    #[test]
    fn test_ends_with() {
        let op = ends_with(".exe");

        assert!(op.evaluate("malware.exe"));
        assert!(op.evaluate(".exe"));
        assert!(!op.evaluate("document.pdf"));
        assert!(!op.evaluate(".exe.txt"));
        assert!(!op.evaluate(""));
    }

    #[test]
    fn test_ends_with_empty() {
        let op = ends_with("");

        // Everything ends with empty string
        assert!(op.evaluate("anything"));
        assert!(op.evaluate(""));
    }

    #[test]
    fn test_numeric_operators_with_negatives() {
        assert!(gt("-5").evaluate("0"));
        assert!(gt("-10").evaluate("-5"));
        assert!(!gt("5").evaluate("-10"));

        assert!(ge("-5").evaluate("-5"));
        assert!(lt("0").evaluate("-1"));
        assert!(le("0").evaluate("0"));
    }

    #[test]
    fn test_numeric_operators_with_invalid_input() {
        // Invalid input becomes 0
        assert!(eq("0").evaluate("invalid"));
        assert!(gt("-1").evaluate("abc")); // abc becomes 0, 0 > -1
        assert!(!gt("1").evaluate("xyz")); // xyz becomes 0, 0 > 1 is false
    }
}
