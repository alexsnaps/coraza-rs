// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Simple comparison operators.
//!
//! This module implements basic comparison and string matching operators
//! with macro expansion support.

use crate::operators::{Macro, MacroError, Operator, Outputs, contains_bytes};
use crate::transaction::Transaction;

/// `input` as an integer; 0 if it isn't one, as Go's `strconv.Atoi` failing gives.
fn as_int(input: &[u8]) -> i32 {
    std::str::from_utf8(input)
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(0)
}

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
/// use coraza::{transaction::Transaction, Operator, eq};
///
/// let op = eq("15").unwrap();
/// let tx = coraza::waf::Waf::default().new_transaction();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(op.evaluate(&tx, "15".as_bytes(), &mut out));
/// assert!(op.evaluate(&tx, "015".as_bytes(), &mut out)); // Leading zeros ignored
/// assert!(!op.evaluate(&tx, "16".as_bytes(), &mut out));
/// ```
#[derive(Debug, Clone)]
pub struct Eq {
    macro_param: Macro,
}

impl Operator for Eq {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        let param_value = self.macro_param.expand(tx);
        let param_int = param_value.parse::<i32>().unwrap_or(0);
        let input_int = as_int(input);
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
/// use coraza::{transaction::Transaction, Operator, gt};
///
/// let op = gt("10").unwrap();
/// let tx = coraza::waf::Waf::default().new_transaction();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(op.evaluate(&tx, "15".as_bytes(), &mut out));
/// assert!(!op.evaluate(&tx, "10".as_bytes(), &mut out));
/// assert!(!op.evaluate(&tx, "5".as_bytes(), &mut out));
/// ```
#[derive(Debug, Clone)]
pub struct Gt {
    macro_param: Macro,
}

impl Operator for Gt {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        let param_value = self.macro_param.expand(tx);
        let param_int = param_value.parse::<i32>().unwrap_or(0);
        let input_int = as_int(input);
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
/// use coraza::{transaction::Transaction, Operator, ge};
///
/// let op = ge("10").unwrap();
/// let tx = coraza::waf::Waf::default().new_transaction();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(op.evaluate(&tx, "15".as_bytes(), &mut out));
/// assert!(op.evaluate(&tx, "10".as_bytes(), &mut out));
/// assert!(!op.evaluate(&tx, "5".as_bytes(), &mut out));
/// ```
#[derive(Debug, Clone)]
pub struct Ge {
    macro_param: Macro,
}

impl Operator for Ge {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        let param_value = self.macro_param.expand(tx);
        let param_int = param_value.parse::<i32>().unwrap_or(0);
        let input_int = as_int(input);
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
/// use coraza::{transaction::Transaction, Operator, lt};
///
/// let op = lt("10").unwrap();
/// let tx = coraza::waf::Waf::default().new_transaction();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(op.evaluate(&tx, "5".as_bytes(), &mut out));
/// assert!(!op.evaluate(&tx, "10".as_bytes(), &mut out));
/// assert!(!op.evaluate(&tx, "15".as_bytes(), &mut out));
/// ```
#[derive(Debug, Clone)]
pub struct Lt {
    macro_param: Macro,
}

impl Operator for Lt {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        let param_value = self.macro_param.expand(tx);
        let param_int = param_value.parse::<i32>().unwrap_or(0);
        let input_int = as_int(input);
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
/// use coraza::{transaction::Transaction, Operator, le};
///
/// let op = le("10").unwrap();
/// let tx = coraza::waf::Waf::default().new_transaction();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(op.evaluate(&tx, "5".as_bytes(), &mut out));
/// assert!(op.evaluate(&tx, "10".as_bytes(), &mut out));
/// assert!(!op.evaluate(&tx, "15".as_bytes(), &mut out));
/// ```
#[derive(Debug, Clone)]
pub struct Le {
    macro_param: Macro,
}

impl Operator for Le {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        let param_value = self.macro_param.expand(tx);
        let param_int = param_value.parse::<i32>().unwrap_or(0);
        let input_int = as_int(input);
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
/// use coraza::{transaction::Transaction, Operator, streq};
///
/// let op = streq("POST").unwrap();
/// let tx = coraza::waf::Waf::default().new_transaction();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(op.evaluate(&tx, "POST".as_bytes(), &mut out));
/// assert!(!op.evaluate(&tx, "post".as_bytes(), &mut out));
/// assert!(!op.evaluate(&tx, "GET".as_bytes(), &mut out));
/// ```
#[derive(Debug, Clone)]
pub struct StrEq {
    macro_param: Macro,
}

impl Operator for StrEq {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        let param_value = self.macro_param.expand(tx);
        input == param_value.as_bytes()
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
/// use coraza::{transaction::Transaction, Operator, contains};
///
/// let op = contains(".php").unwrap();
/// let tx = coraza::waf::Waf::default().new_transaction();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(op.evaluate(&tx, "/index.php".as_bytes(), &mut out));
/// assert!(op.evaluate(&tx, "test.php?id=1".as_bytes(), &mut out));
/// assert!(!op.evaluate(&tx, "/index.html".as_bytes(), &mut out));
/// ```
#[derive(Debug, Clone)]
pub struct Contains {
    macro_param: Macro,
}

impl Operator for Contains {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        let param_value = self.macro_param.expand(tx);
        contains_bytes(input, param_value.as_bytes())
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
/// use coraza::{transaction::Transaction, Operator, begins_with};
///
/// let op = begins_with("GET").unwrap();
/// let tx = coraza::waf::Waf::default().new_transaction();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(op.evaluate(&tx, "GET /index.html HTTP/1.1".as_bytes(), &mut out));
/// assert!(!op.evaluate(&tx, "POST /index.html HTTP/1.1".as_bytes(), &mut out));
/// ```
#[derive(Debug, Clone)]
pub struct BeginsWith {
    macro_param: Macro,
}

impl Operator for BeginsWith {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        let param_value = self.macro_param.expand(tx);
        input.starts_with(param_value.as_bytes())
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
/// use coraza::{transaction::Transaction, Operator, ends_with};
///
/// let op = ends_with(".exe").unwrap();
/// let tx = coraza::waf::Waf::default().new_transaction();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(op.evaluate(&tx, "malware.exe".as_bytes(), &mut out));
/// assert!(op.evaluate(&tx, "C:\\Windows\\system32\\cmd.exe".as_bytes(), &mut out));
/// assert!(!op.evaluate(&tx, "document.pdf".as_bytes(), &mut out));
/// ```
#[derive(Debug, Clone)]
pub struct EndsWith {
    macro_param: Macro,
}

impl Operator for EndsWith {
    fn evaluate(&self, tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        let param_value = self.macro_param.expand(tx);
        input.ends_with(param_value.as_bytes())
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
mod tests {
    use super::*;
    use crate::operators::{Matches, evaluate_in};
    use crate::transaction::Transaction;
    use crate::types::RuleVariable;

    // Mock transaction state for testing macro expansion
    fn mock_tx() -> Transaction {
        let mut tx = Transaction::new("operator-test");
        let Some(crate::transaction::VariableCollection::Map(vars)) =
            tx.collection_mut(RuleVariable::TX)
        else {
            unreachable!("TX is a map");
        };
        vars.add("threshold", "10");
        vars.add("method", "POST");
        vars.add("extension", ".php");
        tx
    }

    #[test]
    fn test_eq_valid_values() {
        let op = eq("1").unwrap();

        assert!(op.matches("1"));
        assert!(op.matches("01")); // Leading zeros
        assert!(!op.matches("1.0")); // Float parsing fails, becomes 0
        assert!(!op.matches("2"));
        assert!(!op.matches("0"));
    }

    #[test]
    fn test_eq_invalid_values_return_zero() {
        let op = eq("a").unwrap(); // Invalid, becomes 0

        assert!(op.matches("a")); // Also becomes 0
        assert!(op.matches("b")); // Also becomes 0
        assert!(op.matches("0")); // Explicitly 0
        assert!(!op.matches("1"));
    }

    #[test]
    fn test_eq_edge_cases() {
        assert!(eq("0").unwrap().matches(""));
        assert!(eq("0").unwrap().matches("invalid"));
        assert!(eq("123").unwrap().matches("123"));
        assert!(eq("-5").unwrap().matches("-5"));
    }

    #[test]
    fn test_eq_with_macro() {
        let op = eq("%{TX.threshold}").unwrap();
        let mut tx = mock_tx();

        assert!(evaluate_in(&op, &mut tx, "10", false));
        assert!(!evaluate_in(&op, &mut tx, "5", false));
        assert!(!evaluate_in(&op, &mut tx, "15", false));
    }

    #[test]
    fn test_gt() {
        let op = gt("10").unwrap();

        assert!(op.matches("15"));
        assert!(op.matches("11"));
        assert!(!op.matches("10"));
        assert!(!op.matches("9"));
        assert!(!op.matches("0"));
    }

    #[test]
    fn test_gt_with_macro() {
        let op = gt("%{TX.threshold}").unwrap();
        let mut tx = mock_tx();

        assert!(evaluate_in(&op, &mut tx, "15", false));
        assert!(evaluate_in(&op, &mut tx, "11", false));
        assert!(!evaluate_in(&op, &mut tx, "10", false));
        assert!(!evaluate_in(&op, &mut tx, "5", false));
    }

    #[test]
    fn test_ge() {
        let op = ge("10").unwrap();

        assert!(op.matches("15"));
        assert!(op.matches("11"));
        assert!(op.matches("10"));
        assert!(!op.matches("9"));
        assert!(!op.matches("0"));
    }

    #[test]
    fn test_lt() {
        let op = lt("10").unwrap();

        assert!(op.matches("9"));
        assert!(op.matches("0"));
        assert!(op.matches("-5"));
        assert!(!op.matches("10"));
        assert!(!op.matches("11"));
    }

    #[test]
    fn test_le() {
        let op = le("10").unwrap();

        assert!(op.matches("9"));
        assert!(op.matches("10"));
        assert!(op.matches("0"));
        assert!(!op.matches("11"));
        assert!(!op.matches("15"));
    }

    #[test]
    fn test_streq() {
        let op = streq("POST").unwrap();

        assert!(op.matches("POST"));
        assert!(!op.matches("post")); // Case sensitive
        assert!(!op.matches("GET"));
        assert!(!op.matches(""));
    }

    #[test]
    fn test_streq_empty() {
        let op = streq("").unwrap();

        assert!(op.matches(""));
        assert!(!op.matches("anything"));
    }

    #[test]
    fn test_streq_with_macro() {
        let op = streq("%{TX.method}").unwrap();
        let mut tx = mock_tx();

        assert!(evaluate_in(&op, &mut tx, "POST", false));
        assert!(!evaluate_in(&op, &mut tx, "GET", false));
        assert!(!evaluate_in(&op, &mut tx, "post", false));
    }

    #[test]
    fn test_contains() {
        let op = contains(".php").unwrap();

        assert!(op.matches("/index.php"));
        assert!(op.matches("test.php?id=1"));
        assert!(op.matches(".php"));
        assert!(!op.matches("/index.html"));
        assert!(!op.matches(""));
    }

    #[test]
    fn test_contains_empty() {
        let op = contains("").unwrap();

        // Empty string is contained in everything
        assert!(op.matches("anything"));
        assert!(op.matches(""));
    }

    #[test]
    fn test_contains_with_macro() {
        let op = contains("%{TX.extension}").unwrap();
        let mut tx = mock_tx();

        assert!(evaluate_in(&op, &mut tx, "/index.php", false));
        assert!(evaluate_in(&op, &mut tx, "test.php?id=1", false));
        assert!(!evaluate_in(&op, &mut tx, "/index.html", false));
    }

    #[test]
    fn test_begins_with() {
        let op = begins_with("GET").unwrap();

        assert!(op.matches("GET /index.html HTTP/1.1"));
        assert!(op.matches("GET"));
        assert!(!op.matches("POST /index.html HTTP/1.1"));
        assert!(!op.matches(" GET"));
        assert!(!op.matches(""));
    }

    #[test]
    fn test_begins_with_empty() {
        let op = begins_with("").unwrap();

        // Everything starts with empty string
        assert!(op.matches("anything"));
        assert!(op.matches(""));
    }

    #[test]
    fn test_ends_with() {
        let op = ends_with(".exe").unwrap();

        assert!(op.matches("malware.exe"));
        assert!(op.matches(".exe"));
        assert!(!op.matches("document.pdf"));
        assert!(!op.matches(".exe.txt"));
        assert!(!op.matches(""));
    }

    #[test]
    fn test_ends_with_empty() {
        let op = ends_with("").unwrap();

        // Everything ends with empty string
        assert!(op.matches("anything"));
        assert!(op.matches(""));
    }

    #[test]
    fn test_numeric_operators_with_negatives() {
        assert!(gt("-5").unwrap().matches("0"));
        assert!(gt("-10").unwrap().matches("-5"));
        assert!(!gt("5").unwrap().matches("-10"));

        assert!(ge("-5").unwrap().matches("-5"));
        assert!(lt("0").unwrap().matches("-1"));
        assert!(le("0").unwrap().matches("0"));
    }

    #[test]
    fn test_numeric_operators_with_invalid_input() {
        // Invalid input becomes 0
        assert!(eq("0").unwrap().matches("invalid"));
        assert!(gt("-1").unwrap().matches("abc")); // abc becomes 0, 0 > -1
        assert!(!gt("1").unwrap().matches("xyz")); // xyz becomes 0, 0 > 1 is false
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
