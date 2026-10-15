// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Operator integration for rule evaluation.
//!
//! This module wraps operators with metadata (function name, parameters, negation)
//! and provides evaluation logic.

use crate::operators::OperatorEnum;
use crate::transaction::Transaction;

/// Rule operator specification with metadata and negation support.
///
/// This wrapper contains the operator along with its function name, initialization
/// data, and negation flag. Negation is detected from the function name prefix (e.g.,
/// "!@rx" for negated regex matching).
///
/// # Examples
///
/// ```
/// use coraza::rules::RuleOperator;
/// use coraza::operators::{Rx, rx};
///
/// // Normal operator
/// let op = RuleOperator::new(
///     rx("attack").unwrap().into(),
///     "@rx",
///     "attack"
/// );
///
/// // Negated operator (matches when operator returns false)
/// let neg_op = RuleOperator::new(
///     rx("safe").unwrap().into(),
///     "!@rx",
///     "safe"
/// );
/// ```
#[derive(Debug, Clone)]
pub struct RuleOperator {
    /// The operator to evaluate
    operator: OperatorEnum,

    /// Function name (e.g., "@rx", "!@eq")
    function: String,

    /// Initialization data/parameter for the operator
    data: String,

    /// If true, negate the operator result
    negation: bool,
}

impl RuleOperator {
    /// Create a new rule operator.
    ///
    /// The `function` parameter is used to detect negation: if it starts with '!',
    /// the operator result will be inverted.
    ///
    /// # Arguments
    ///
    /// * `operator` - The operator to evaluate
    /// * `function` - Function name (e.g., "@rx", "!@eq") - used for negation detection
    /// * `data` - Initialization data/parameter
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::rules::RuleOperator;
    /// use coraza::operators::{StrEq, streq};
    ///
    /// let op = RuleOperator::new(
    ///     streq("admin").unwrap().into(),
    ///     "@streq",
    ///     "admin"
    /// );
    /// ```
    pub fn new(
        operator: OperatorEnum,
        function: impl Into<String>,
        data: impl Into<String>,
    ) -> Self {
        let function = function.into();
        let negation = !function.is_empty() && function.starts_with('!');

        Self {
            operator,
            function,
            data: data.into(),
            negation,
        }
    }

    /// Get the function name.
    pub fn function(&self) -> &str {
        &self.function
    }

    /// Get the initialization data.
    pub fn data(&self) -> &str {
        &self.data
    }

    /// Check if this operator is negated.
    pub fn is_negated(&self) -> bool {
        self.negation
    }

    /// Evaluate the operator against an input value.
    ///
    /// If negation is enabled, the result is inverted before returning.
    ///
    /// # Arguments
    ///
    /// * `tx` - Transaction state for macro expansion and capturing
    /// * `input` - The input value to evaluate
    ///
    /// # Returns
    ///
    /// True if the operator matches (after applying negation if set).
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::rules::RuleOperator;
    /// use coraza::operators::{StrEq, streq};
    /// use coraza::transaction::Transaction;
    ///
    /// let op = RuleOperator::new(
    ///     streq("test").unwrap().into(),
    ///     "@streq",
    ///     "test"
    /// );
    ///
    /// let mut tx = Transaction::new("test");
    /// assert!(op.evaluate(Some(&mut tx), "test"));
    /// assert!(!op.evaluate(Some(&mut tx), "other"));
    /// ```
    pub fn evaluate(&self, tx: Option<&mut Transaction>, input: &str) -> bool {
        let result = self.operator.evaluate(tx, input);

        if self.negation { !result } else { result }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::{contains, eq, rx, streq};
    use crate::transaction::Transaction;

    // Ported from: coraza/internal/corazawaf/rule.go - SetOperator logic
    #[test]
    fn test_operator_creation() {
        let op = RuleOperator::new(streq("test").unwrap().into(), "@streq", "test");

        assert_eq!(op.function(), "@streq");
        assert_eq!(op.data(), "test");
        assert!(!op.is_negated());
    }

    #[test]
    fn test_operator_negation_detection() {
        // Normal operator (no negation)
        let op_normal = RuleOperator::new(streq("test").unwrap().into(), "@streq", "test");
        assert!(!op_normal.is_negated());

        // Negated operator (starts with '!')
        let op_negated = RuleOperator::new(streq("test").unwrap().into(), "!@streq", "test");
        assert!(op_negated.is_negated());
    }

    // Ported from: coraza/internal/corazawaf/rule.go::executeOperator
    #[test]
    fn test_operator_evaluate_normal() {
        let op = RuleOperator::new(streq("test").unwrap().into(), "@streq", "test");

        let mut tx = Transaction::new("test");
        assert!(op.evaluate(Some(&mut tx), "test"));
        assert!(!op.evaluate(Some(&mut tx), "other"));
    }

    #[test]
    fn test_operator_evaluate_negated() {
        let op = RuleOperator::new(streq("test").unwrap().into(), "!@streq", "test");

        let mut tx = Transaction::new("test");
        // Negated: returns opposite of operator result
        assert!(!op.evaluate(Some(&mut tx), "test")); // streq matches, but negated
        assert!(op.evaluate(Some(&mut tx), "other")); // streq doesn't match, negated = true
    }

    #[test]
    fn test_operator_enum_dispatch() {
        let mut tx = Transaction::new("test");

        // Test that OperatorEnum correctly dispatches to each operator type
        let rx_op = rx("test").unwrap();
        let enum_op = OperatorEnum::from(rx_op);
        assert!(enum_op.evaluate(Some(&mut tx), "test123"));
        assert!(!enum_op.evaluate(Some(&mut tx), "other"));

        let contains_op = contains("hello").unwrap();
        let enum_op = OperatorEnum::from(contains_op);
        assert!(enum_op.evaluate(Some(&mut tx), "hello world"));
        assert!(!enum_op.evaluate(Some(&mut tx), "goodbye"));

        let eq_op = eq("42").unwrap();
        let enum_op = OperatorEnum::from(eq_op);
        assert!(enum_op.evaluate(Some(&mut tx), "42"));
        assert!(!enum_op.evaluate(Some(&mut tx), "43"));
    }

    #[test]
    fn test_multiple_operator_types() {
        // Test all operator conversions
        let operators = vec![
            rx("test").unwrap().into(),
            streq("test").unwrap().into(),
            contains("test").unwrap().into(),
            eq("123").unwrap().into(),
        ];

        for op in operators {
            // Just verify they convert correctly
            let _enum_op: OperatorEnum = op;
        }
    }

    #[test]
    fn test_negation_with_different_operators() {
        let mut tx = Transaction::new("test");

        // Test negation with regex
        let rx_op = RuleOperator::new(rx("^test").unwrap().into(), "!@rx", "^test");
        assert!(!rx_op.evaluate(Some(&mut tx), "test123")); // matches but negated
        assert!(rx_op.evaluate(Some(&mut tx), "other")); // doesn't match, negated = true

        // Test negation with contains
        let contains_op =
            RuleOperator::new(contains("admin").unwrap().into(), "!@contains", "admin");
        assert!(!contains_op.evaluate(Some(&mut tx), "admin user")); // matches but negated
        assert!(contains_op.evaluate(Some(&mut tx), "regular user")); // doesn't match, negated = true

        // Test negation with eq
        let eq_op = RuleOperator::new(eq("0").unwrap().into(), "!@eq", "0");
        assert!(!eq_op.evaluate(Some(&mut tx), "0")); // matches but negated
        assert!(eq_op.evaluate(Some(&mut tx), "1")); // doesn't match, negated = true
    }

    #[test]
    fn test_empty_function_name() {
        // Edge case: empty function name should not be considered negated
        let op = RuleOperator::new(streq("test").unwrap().into(), "", "test");
        assert!(!op.is_negated());
    }

    #[test]
    fn test_function_name_metadata() {
        // Verify function name is stored for logging/debugging
        let op1 = RuleOperator::new(streq("test").unwrap().into(), "@streq", "test");
        assert_eq!(op1.function(), "@streq");

        let op2 = RuleOperator::new(rx(".*").unwrap().into(), "@rx", ".*");
        assert_eq!(op2.function(), "@rx");

        let op3 = RuleOperator::new(eq("42").unwrap().into(), "!@eq", "42");
        assert_eq!(op3.function(), "!@eq");
    }

    #[test]
    fn test_data_metadata() {
        // Verify data is stored for logging/debugging
        let op = RuleOperator::new(streq("admin").unwrap().into(), "@streq", "admin");
        assert_eq!(op.data(), "admin");

        let op2 = RuleOperator::new(rx("test.*").unwrap().into(), "@rx", "test.*");
        assert_eq!(op2.data(), "test.*");
    }
}
