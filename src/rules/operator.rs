// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Operator integration for rule evaluation.
//!
//! This module wraps operators with metadata (function name, parameters, negation)
//! and provides evaluation logic. Operators are stored as an enum for zero-cost
//! abstraction without dynamic dispatch.

use crate::operators::{
    BeginsWith, Contains, EndsWith, Eq, Ge, Gt, IpMatch, Le, Lt, NoMatch, Operator, Pm, Rx, StrEq,
    StrMatch, TransactionState, UnconditionalMatch, ValidateByteRange, ValidateUrlEncoding,
    ValidateUtf8Encoding, Within,
};

/// Enum containing all available operators.
///
/// This enum provides static dispatch instead of `Box<dyn Operator>` for
/// zero-cost abstraction. All operator evaluation is inlined at compile time.
#[derive(Debug, Clone)]
pub enum OperatorEnum {
    // Pattern matching operators
    Rx(Rx),
    Pm(Pm),
    StrMatch(StrMatch),
    Within(Within),

    // String comparison operators
    StrEq(StrEq),
    Contains(Contains),
    BeginsWith(BeginsWith),
    EndsWith(EndsWith),

    // Numeric comparison operators
    Eq(Eq),
    Lt(Lt),
    Le(Le),
    Gt(Gt),
    Ge(Ge),

    // IP and network operators
    IpMatch(IpMatch),

    // Validation operators
    ValidateByteRange(ValidateByteRange),
    ValidateUrlEncoding(ValidateUrlEncoding),
    ValidateUtf8Encoding(ValidateUtf8Encoding),

    // Control operators
    UnconditionalMatch(UnconditionalMatch),
    NoMatch(NoMatch),
}

impl OperatorEnum {
    /// Evaluate the operator against an input value.
    ///
    /// This method dispatches to the appropriate operator implementation
    /// using pattern matching, which the compiler optimizes into a jump table.
    pub fn evaluate<TX: TransactionState>(&self, tx: Option<&mut TX>, input: &str) -> bool {
        match self {
            // Pattern matching
            Self::Rx(op) => op.evaluate(tx, input),
            Self::Pm(op) => op.evaluate(tx, input),
            Self::StrMatch(op) => op.evaluate(tx, input),
            Self::Within(op) => op.evaluate(tx, input),

            // String comparison
            Self::StrEq(op) => op.evaluate(tx, input),
            Self::Contains(op) => op.evaluate(tx, input),
            Self::BeginsWith(op) => op.evaluate(tx, input),
            Self::EndsWith(op) => op.evaluate(tx, input),

            // Numeric comparison
            Self::Eq(op) => op.evaluate(tx, input),
            Self::Lt(op) => op.evaluate(tx, input),
            Self::Le(op) => op.evaluate(tx, input),
            Self::Gt(op) => op.evaluate(tx, input),
            Self::Ge(op) => op.evaluate(tx, input),

            // IP and network
            Self::IpMatch(op) => op.evaluate(tx, input),

            // Validation
            Self::ValidateByteRange(op) => op.evaluate(tx, input),
            Self::ValidateUrlEncoding(op) => op.evaluate(tx, input),
            Self::ValidateUtf8Encoding(op) => op.evaluate(tx, input),

            // Control
            Self::UnconditionalMatch(op) => op.evaluate(tx, input),
            Self::NoMatch(op) => op.evaluate(tx, input),
        }
    }
}

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
    pub fn evaluate<TX: TransactionState>(&self, tx: Option<&mut TX>, input: &str) -> bool {
        let result = self.operator.evaluate(tx, input);

        if self.negation { !result } else { result }
    }
}

// Implement From for each operator type to easily convert to OperatorEnum
impl From<Rx> for OperatorEnum {
    fn from(op: Rx) -> Self {
        Self::Rx(op)
    }
}

impl From<Pm> for OperatorEnum {
    fn from(op: Pm) -> Self {
        Self::Pm(op)
    }
}

impl From<StrMatch> for OperatorEnum {
    fn from(op: StrMatch) -> Self {
        Self::StrMatch(op)
    }
}

impl From<Within> for OperatorEnum {
    fn from(op: Within) -> Self {
        Self::Within(op)
    }
}

impl From<StrEq> for OperatorEnum {
    fn from(op: StrEq) -> Self {
        Self::StrEq(op)
    }
}

impl From<Contains> for OperatorEnum {
    fn from(op: Contains) -> Self {
        Self::Contains(op)
    }
}

impl From<BeginsWith> for OperatorEnum {
    fn from(op: BeginsWith) -> Self {
        Self::BeginsWith(op)
    }
}

impl From<EndsWith> for OperatorEnum {
    fn from(op: EndsWith) -> Self {
        Self::EndsWith(op)
    }
}

impl From<Eq> for OperatorEnum {
    fn from(op: Eq) -> Self {
        Self::Eq(op)
    }
}

impl From<Lt> for OperatorEnum {
    fn from(op: Lt) -> Self {
        Self::Lt(op)
    }
}

impl From<Le> for OperatorEnum {
    fn from(op: Le) -> Self {
        Self::Le(op)
    }
}

impl From<Gt> for OperatorEnum {
    fn from(op: Gt) -> Self {
        Self::Gt(op)
    }
}

impl From<Ge> for OperatorEnum {
    fn from(op: Ge) -> Self {
        Self::Ge(op)
    }
}

impl From<IpMatch> for OperatorEnum {
    fn from(op: IpMatch) -> Self {
        Self::IpMatch(op)
    }
}

impl From<ValidateByteRange> for OperatorEnum {
    fn from(op: ValidateByteRange) -> Self {
        Self::ValidateByteRange(op)
    }
}

impl From<ValidateUrlEncoding> for OperatorEnum {
    fn from(op: ValidateUrlEncoding) -> Self {
        Self::ValidateUrlEncoding(op)
    }
}

impl From<ValidateUtf8Encoding> for OperatorEnum {
    fn from(op: ValidateUtf8Encoding) -> Self {
        Self::ValidateUtf8Encoding(op)
    }
}

impl From<UnconditionalMatch> for OperatorEnum {
    fn from(op: UnconditionalMatch) -> Self {
        Self::UnconditionalMatch(op)
    }
}

impl From<NoMatch> for OperatorEnum {
    fn from(op: NoMatch) -> Self {
        Self::NoMatch(op)
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
