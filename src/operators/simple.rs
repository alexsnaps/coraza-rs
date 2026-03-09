// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Simple comparison operators.
//!
//! This module implements basic comparison and string matching operators
//! with macro expansion support.

use crate::operators::{Macro, MacroError, Operator, TransactionState};

/// Numeric equality operator.
///
/// Performs numerical comparison and returns true if the input value equals
/// the parameter. Both values are converted to integers before comparison.
/// Invalid integers are treated as 0.
///
/// Supports macro expansion for parameter values.
///
/// # Examples
///
/// ```
/// use coraza::operators::{NoTx, Operator, eq};
///
/// let op = eq("15").unwrap();
/// assert!(op.evaluate(None::<&NoTx>, "15"));
/// assert!(op.evaluate(None::<&NoTx>, "015")); // Leading zeros ignored
/// assert!(!op.evaluate(None::<&NoTx>, "16"));
/// ```
#[derive(Debug, Clone)]
pub struct Eq {
    macro_param: Macro,
}

impl Operator for Eq {
    fn evaluate<TX: TransactionState>(&self, tx: Option<&TX>, input: &str) -> bool {
        let param_value = self.macro_param.expand(tx);
        let param_int = param_value.parse::<i32>().unwrap_or(0);
        let input_int = input.parse::<i32>().unwrap_or(0);
        param_int == input_int
    }
}

/// Creates a new `eq` operator.
///
/// # Errors
///
/// Returns an error if the parameter contains invalid macro syntax.
pub fn eq(parameter: &str) -> Result<Eq, MacroError> {
    Ok(Eq {
        macro_param: Macro::new(parameter)?,
    })
}

/// Greater than operator.
///
/// Returns true if the input value is greater than the parameter.
/// Both values are converted to integers before comparison.
///
/// Supports macro expansion for parameter values.
///
/// # Examples
///
/// ```
/// use coraza::operators::{NoTx, Operator, gt};
///
/// let op = gt("10").unwrap();
/// assert!(op.evaluate(None::<&NoTx>, "15"));
/// assert!(!op.evaluate(None::<&NoTx>, "10"));
/// assert!(!op.evaluate(None::<&NoTx>, "5"));
/// ```
#[derive(Debug, Clone)]
pub struct Gt {
    macro_param: Macro,
}

impl Operator for Gt {
    fn evaluate<TX: TransactionState>(&self, tx: Option<&TX>, input: &str) -> bool {
        let param_value = self.macro_param.expand(tx);
        let param_int = param_value.parse::<i32>().unwrap_or(0);
        let input_int = input.parse::<i32>().unwrap_or(0);
        input_int > param_int
    }
}

/// Creates a new `gt` operator.
///
/// # Errors
///
/// Returns an error if the parameter contains invalid macro syntax.
pub fn gt(parameter: &str) -> Result<Gt, MacroError> {
    Ok(Gt {
        macro_param: Macro::new(parameter)?,
    })
}

/// Greater than or equal operator.
///
/// Returns true if the input value is greater than or equal to the parameter.
///
/// Supports macro expansion for parameter values.
///
/// # Examples
///
/// ```
/// use coraza::operators::{NoTx, Operator, ge};
///
/// let op = ge("10").unwrap();
/// assert!(op.evaluate(None::<&NoTx>, "15"));
/// assert!(op.evaluate(None::<&NoTx>, "10"));
/// assert!(!op.evaluate(None::<&NoTx>, "5"));
/// ```
#[derive(Debug, Clone)]
pub struct Ge {
    macro_param: Macro,
}

impl Operator for Ge {
    fn evaluate<TX: TransactionState>(&self, tx: Option<&TX>, input: &str) -> bool {
        let param_value = self.macro_param.expand(tx);
        let param_int = param_value.parse::<i32>().unwrap_or(0);
        let input_int = input.parse::<i32>().unwrap_or(0);
        input_int >= param_int
    }
}

/// Creates a new `ge` operator.
///
/// # Errors
///
/// Returns an error if the parameter contains invalid macro syntax.
pub fn ge(parameter: &str) -> Result<Ge, MacroError> {
    Ok(Ge {
        macro_param: Macro::new(parameter)?,
    })
}

/// Less than operator.
///
/// Returns true if the input value is less than the parameter.
///
/// Supports macro expansion for parameter values.
///
/// # Examples
///
/// ```
/// use coraza::operators::{NoTx, Operator, lt};
///
/// let op = lt("10").unwrap();
/// assert!(op.evaluate(None::<&NoTx>, "5"));
/// assert!(!op.evaluate(None::<&NoTx>, "10"));
/// assert!(!op.evaluate(None::<&NoTx>, "15"));
/// ```
#[derive(Debug, Clone)]
pub struct Lt {
    macro_param: Macro,
}

impl Operator for Lt {
    fn evaluate<TX: TransactionState>(&self, tx: Option<&TX>, input: &str) -> bool {
        let param_value = self.macro_param.expand(tx);
        let param_int = param_value.parse::<i32>().unwrap_or(0);
        let input_int = input.parse::<i32>().unwrap_or(0);
        input_int < param_int
    }
}

/// Creates a new `lt` operator.
///
/// # Errors
///
/// Returns an error if the parameter contains invalid macro syntax.
pub fn lt(parameter: &str) -> Result<Lt, MacroError> {
    Ok(Lt {
        macro_param: Macro::new(parameter)?,
    })
}

/// Less than or equal operator.
///
/// Returns true if the input value is less than or equal to the parameter.
///
/// Supports macro expansion for parameter values.
///
/// # Examples
///
/// ```
/// use coraza::operators::{NoTx, Operator, le};
///
/// let op = le("10").unwrap();
/// assert!(op.evaluate(None::<&NoTx>, "5"));
/// assert!(op.evaluate(None::<&NoTx>, "10"));
/// assert!(!op.evaluate(None::<&NoTx>, "15"));
/// ```
#[derive(Debug, Clone)]
pub struct Le {
    macro_param: Macro,
}

impl Operator for Le {
    fn evaluate<TX: TransactionState>(&self, tx: Option<&TX>, input: &str) -> bool {
        let param_value = self.macro_param.expand(tx);
        let param_int = param_value.parse::<i32>().unwrap_or(0);
        let input_int = input.parse::<i32>().unwrap_or(0);
        input_int <= param_int
    }
}

/// Creates a new `le` operator.
///
/// # Errors
///
/// Returns an error if the parameter contains invalid macro syntax.
pub fn le(parameter: &str) -> Result<Le, MacroError> {
    Ok(Le {
        macro_param: Macro::new(parameter)?,
    })
}

/// String equality operator.
///
/// Performs case-sensitive string comparison and returns true if the input
/// equals the parameter exactly.
///
/// Supports macro expansion for parameter values.
///
/// # Examples
///
/// ```
/// use coraza::operators::{NoTx, Operator, streq};
///
/// let op = streq("POST").unwrap();
/// assert!(op.evaluate(None::<&NoTx>, "POST"));
/// assert!(!op.evaluate(None::<&NoTx>, "post"));
/// assert!(!op.evaluate(None::<&NoTx>, "GET"));
/// ```
#[derive(Debug, Clone)]
pub struct StrEq {
    macro_param: Macro,
}

impl Operator for StrEq {
    fn evaluate<TX: TransactionState>(&self, tx: Option<&TX>, input: &str) -> bool {
        let param_value = self.macro_param.expand(tx);
        input == param_value
    }
}

/// Creates a new `streq` operator.
///
/// # Errors
///
/// Returns an error if the parameter contains invalid macro syntax.
pub fn streq(parameter: &str) -> Result<StrEq, MacroError> {
    Ok(StrEq {
        macro_param: Macro::new(parameter)?,
    })
}

/// Contains operator.
///
/// Returns true if the parameter string is found anywhere in the input.
///
/// Supports macro expansion for parameter values.
///
/// # Examples
///
/// ```
/// use coraza::operators::{NoTx, Operator, contains};
///
/// let op = contains(".php").unwrap();
/// assert!(op.evaluate(None::<&NoTx>, "/index.php"));
/// assert!(op.evaluate(None::<&NoTx>, "test.php?id=1"));
/// assert!(!op.evaluate(None::<&NoTx>, "/index.html"));
/// ```
#[derive(Debug, Clone)]
pub struct Contains {
    macro_param: Macro,
}

impl Operator for Contains {
    fn evaluate<TX: TransactionState>(&self, tx: Option<&TX>, input: &str) -> bool {
        let param_value = self.macro_param.expand(tx);
        input.contains(&param_value)
    }
}

/// Creates a new `contains` operator.
///
/// # Errors
///
/// Returns an error if the parameter contains invalid macro syntax.
pub fn contains(parameter: &str) -> Result<Contains, MacroError> {
    Ok(Contains {
        macro_param: Macro::new(parameter)?,
    })
}

/// Begins with operator.
///
/// Returns true if the input starts with the parameter string.
///
/// Supports macro expansion for parameter values.
///
/// # Examples
///
/// ```
/// use coraza::operators::{NoTx, Operator, begins_with};
///
/// let op = begins_with("GET").unwrap();
/// assert!(op.evaluate(None::<&NoTx>, "GET /index.html HTTP/1.1"));
/// assert!(!op.evaluate(None::<&NoTx>, "POST /index.html HTTP/1.1"));
/// ```
#[derive(Debug, Clone)]
pub struct BeginsWith {
    macro_param: Macro,
}

impl Operator for BeginsWith {
    fn evaluate<TX: TransactionState>(&self, tx: Option<&TX>, input: &str) -> bool {
        let param_value = self.macro_param.expand(tx);
        input.starts_with(&param_value)
    }
}

/// Creates a new `begins_with` operator.
///
/// # Errors
///
/// Returns an error if the parameter contains invalid macro syntax.
pub fn begins_with(parameter: &str) -> Result<BeginsWith, MacroError> {
    Ok(BeginsWith {
        macro_param: Macro::new(parameter)?,
    })
}

/// Ends with operator.
///
/// Returns true if the input ends with the parameter string.
///
/// Supports macro expansion for parameter values.
///
/// # Examples
///
/// ```
/// use coraza::operators::{NoTx, Operator, ends_with};
///
/// let op = ends_with(".exe").unwrap();
/// assert!(op.evaluate(None::<&NoTx>, "malware.exe"));
/// assert!(op.evaluate(None::<&NoTx>, "C:\\Windows\\system32\\cmd.exe"));
/// assert!(!op.evaluate(None::<&NoTx>, "document.pdf"));
/// ```
#[derive(Debug, Clone)]
pub struct EndsWith {
    macro_param: Macro,
}

impl Operator for EndsWith {
    fn evaluate<TX: TransactionState>(&self, tx: Option<&TX>, input: &str) -> bool {
        let param_value = self.macro_param.expand(tx);
        input.ends_with(&param_value)
    }
}

/// Creates a new `ends_with` operator.
///
/// # Errors
///
/// Returns an error if the parameter contains invalid macro syntax.
pub fn ends_with(parameter: &str) -> Result<EndsWith, MacroError> {
    Ok(EndsWith {
        macro_param: Macro::new(parameter)?,
    })
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::operators::NoTx;
    use crate::types::RuleVariable;

    // Mock transaction state for testing macro expansion
    struct MockTx;

    impl TransactionState for MockTx {
        fn get_variable(&self, variable: RuleVariable, key: Option<&str>) -> Option<String> {
            match (variable, key) {
                (RuleVariable::TX, Some("threshold")) => Some("10".to_string()),
                (RuleVariable::TX, Some("method")) => Some("POST".to_string()),
                (RuleVariable::TX, Some("extension")) => Some(".php".to_string()),
                _ => None,
            }
        }
    }

    #[test]
    fn test_eq_valid_values() {
        let op = eq("1").unwrap();

        assert!(op.evaluate(None::<&NoTx>, "1"));
        assert!(op.evaluate(None::<&NoTx>, "01")); // Leading zeros
        assert!(!op.evaluate(None::<&NoTx>, "1.0")); // Float parsing fails, becomes 0
        assert!(!op.evaluate(None::<&NoTx>, "2"));
        assert!(!op.evaluate(None::<&NoTx>, "0"));
    }

    #[test]
    fn test_eq_invalid_values_return_zero() {
        let op = eq("a").unwrap(); // Invalid, becomes 0

        assert!(op.evaluate(None::<&NoTx>, "a")); // Also becomes 0
        assert!(op.evaluate(None::<&NoTx>, "b")); // Also becomes 0
        assert!(op.evaluate(None::<&NoTx>, "0")); // Explicitly 0
        assert!(!op.evaluate(None::<&NoTx>, "1"));
    }

    #[test]
    fn test_eq_edge_cases() {
        assert!(eq("0").unwrap().evaluate(None::<&NoTx>, ""));
        assert!(eq("0").unwrap().evaluate(None::<&NoTx>, "invalid"));
        assert!(eq("123").unwrap().evaluate(None::<&NoTx>, "123"));
        assert!(eq("-5").unwrap().evaluate(None::<&NoTx>, "-5"));
    }

    #[test]
    fn test_eq_with_macro() {
        let op = eq("%{TX.threshold}").unwrap();
        let tx = MockTx;

        assert!(op.evaluate(Some(&tx), "10"));
        assert!(!op.evaluate(Some(&tx), "5"));
        assert!(!op.evaluate(Some(&tx), "15"));
    }

    #[test]
    fn test_gt() {
        let op = gt("10").unwrap();

        assert!(op.evaluate(None::<&NoTx>, "15"));
        assert!(op.evaluate(None::<&NoTx>, "11"));
        assert!(!op.evaluate(None::<&NoTx>, "10"));
        assert!(!op.evaluate(None::<&NoTx>, "9"));
        assert!(!op.evaluate(None::<&NoTx>, "0"));
    }

    #[test]
    fn test_gt_with_macro() {
        let op = gt("%{TX.threshold}").unwrap();
        let tx = MockTx;

        assert!(op.evaluate(Some(&tx), "15"));
        assert!(op.evaluate(Some(&tx), "11"));
        assert!(!op.evaluate(Some(&tx), "10"));
        assert!(!op.evaluate(Some(&tx), "5"));
    }

    #[test]
    fn test_ge() {
        let op = ge("10").unwrap();

        assert!(op.evaluate(None::<&NoTx>, "15"));
        assert!(op.evaluate(None::<&NoTx>, "11"));
        assert!(op.evaluate(None::<&NoTx>, "10"));
        assert!(!op.evaluate(None::<&NoTx>, "9"));
        assert!(!op.evaluate(None::<&NoTx>, "0"));
    }

    #[test]
    fn test_lt() {
        let op = lt("10").unwrap();

        assert!(op.evaluate(None::<&NoTx>, "9"));
        assert!(op.evaluate(None::<&NoTx>, "0"));
        assert!(op.evaluate(None::<&NoTx>, "-5"));
        assert!(!op.evaluate(None::<&NoTx>, "10"));
        assert!(!op.evaluate(None::<&NoTx>, "11"));
    }

    #[test]
    fn test_le() {
        let op = le("10").unwrap();

        assert!(op.evaluate(None::<&NoTx>, "9"));
        assert!(op.evaluate(None::<&NoTx>, "10"));
        assert!(op.evaluate(None::<&NoTx>, "0"));
        assert!(!op.evaluate(None::<&NoTx>, "11"));
        assert!(!op.evaluate(None::<&NoTx>, "15"));
    }

    #[test]
    fn test_streq() {
        let op = streq("POST").unwrap();

        assert!(op.evaluate(None::<&NoTx>, "POST"));
        assert!(!op.evaluate(None::<&NoTx>, "post")); // Case sensitive
        assert!(!op.evaluate(None::<&NoTx>, "GET"));
        assert!(!op.evaluate(None::<&NoTx>, ""));
    }

    #[test]
    fn test_streq_empty() {
        let op = streq("").unwrap();

        assert!(op.evaluate(None::<&NoTx>, ""));
        assert!(!op.evaluate(None::<&NoTx>, "anything"));
    }

    #[test]
    fn test_streq_with_macro() {
        let op = streq("%{TX.method}").unwrap();
        let tx = MockTx;

        assert!(op.evaluate(Some(&tx), "POST"));
        assert!(!op.evaluate(Some(&tx), "GET"));
        assert!(!op.evaluate(Some(&tx), "post"));
    }

    #[test]
    fn test_contains() {
        let op = contains(".php").unwrap();

        assert!(op.evaluate(None::<&NoTx>, "/index.php"));
        assert!(op.evaluate(None::<&NoTx>, "test.php?id=1"));
        assert!(op.evaluate(None::<&NoTx>, ".php"));
        assert!(!op.evaluate(None::<&NoTx>, "/index.html"));
        assert!(!op.evaluate(None::<&NoTx>, ""));
    }

    #[test]
    fn test_contains_empty() {
        let op = contains("").unwrap();

        // Empty string is contained in everything
        assert!(op.evaluate(None::<&NoTx>, "anything"));
        assert!(op.evaluate(None::<&NoTx>, ""));
    }

    #[test]
    fn test_contains_with_macro() {
        let op = contains("%{TX.extension}").unwrap();
        let tx = MockTx;

        assert!(op.evaluate(Some(&tx), "/index.php"));
        assert!(op.evaluate(Some(&tx), "test.php?id=1"));
        assert!(!op.evaluate(Some(&tx), "/index.html"));
    }

    #[test]
    fn test_begins_with() {
        let op = begins_with("GET").unwrap();

        assert!(op.evaluate(None::<&NoTx>, "GET /index.html HTTP/1.1"));
        assert!(op.evaluate(None::<&NoTx>, "GET"));
        assert!(!op.evaluate(None::<&NoTx>, "POST /index.html HTTP/1.1"));
        assert!(!op.evaluate(None::<&NoTx>, " GET"));
        assert!(!op.evaluate(None::<&NoTx>, ""));
    }

    #[test]
    fn test_begins_with_empty() {
        let op = begins_with("").unwrap();

        // Everything starts with empty string
        assert!(op.evaluate(None::<&NoTx>, "anything"));
        assert!(op.evaluate(None::<&NoTx>, ""));
    }

    #[test]
    fn test_ends_with() {
        let op = ends_with(".exe").unwrap();

        assert!(op.evaluate(None::<&NoTx>, "malware.exe"));
        assert!(op.evaluate(None::<&NoTx>, ".exe"));
        assert!(!op.evaluate(None::<&NoTx>, "document.pdf"));
        assert!(!op.evaluate(None::<&NoTx>, ".exe.txt"));
        assert!(!op.evaluate(None::<&NoTx>, ""));
    }

    #[test]
    fn test_ends_with_empty() {
        let op = ends_with("").unwrap();

        // Everything ends with empty string
        assert!(op.evaluate(None::<&NoTx>, "anything"));
        assert!(op.evaluate(None::<&NoTx>, ""));
    }

    #[test]
    fn test_numeric_operators_with_negatives() {
        assert!(gt("-5").unwrap().evaluate(None::<&NoTx>, "0"));
        assert!(gt("-10").unwrap().evaluate(None::<&NoTx>, "-5"));
        assert!(!gt("5").unwrap().evaluate(None::<&NoTx>, "-10"));

        assert!(ge("-5").unwrap().evaluate(None::<&NoTx>, "-5"));
        assert!(lt("0").unwrap().evaluate(None::<&NoTx>, "-1"));
        assert!(le("0").unwrap().evaluate(None::<&NoTx>, "0"));
    }

    #[test]
    fn test_numeric_operators_with_invalid_input() {
        // Invalid input becomes 0
        assert!(eq("0").unwrap().evaluate(None::<&NoTx>, "invalid"));
        assert!(gt("-1").unwrap().evaluate(None::<&NoTx>, "abc")); // abc becomes 0, 0 > -1
        assert!(!gt("1").unwrap().evaluate(None::<&NoTx>, "xyz")); // xyz becomes 0, 0 > 1 is false
    }

    #[test]
    fn test_operator_constructor_with_invalid_macro() {
        // Empty parameter is allowed
        assert!(eq("").is_ok());

        // Malformed macro
        assert!(eq("%{TX.").is_err());
        assert!(eq("%{").is_err());
        assert!(streq("%{unknown_var}").is_err());
    }
}
