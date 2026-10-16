// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Operator integration for rule evaluation.
//!
//! This module wraps a rule's operator with its negation and provides evaluation logic.

use crate::operators::{OperatorEnum, Outputs};
use crate::transaction::Transaction;

/// A rule's operator, as SecLang's `[!]@NAME ARGUMENT` gives it: the test it applies to
/// each value, and whether the rule matches when that test fails (`!`).
#[derive(Debug, Clone)]
pub(crate) struct RuleOperator {
    operator: OperatorEnum,

    /// Whether a value matches when `operator` rejects it (`!@NAME`)
    negated: bool,
}

impl RuleOperator {
    /// `operator`, inverted if `negated`.
    pub(crate) fn new(operator: OperatorEnum, negated: bool) -> Self {
        Self { operator, negated }
    }

    /// Whether `input` matches: what the operator says of it, inverted if negated.
    pub(crate) fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        let result = self.operator.evaluate(tx, input, out);

        if self.negated { !result } else { result }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::{contains, eq, rx, streq};
    use crate::transaction::Transaction;

    // Ported from: coraza/internal/corazawaf/rule.go::executeOperator
    #[test]
    fn test_operator_evaluate_normal() {
        let op = RuleOperator::new(streq("test").unwrap().into(), false);

        let tx = Transaction::new("test");
        assert!(op.evaluate(&tx, b"test", &mut Outputs::default()));
        assert!(!op.evaluate(&tx, b"other", &mut Outputs::default()));
    }

    #[test]
    fn test_operator_evaluate_negated() {
        let op = RuleOperator::new(streq("test").unwrap().into(), true);

        let tx = Transaction::new("test");
        // Negated: returns opposite of operator result
        assert!(!op.evaluate(&tx, b"test", &mut Outputs::default())); // streq matches, but negated
        assert!(op.evaluate(&tx, b"other", &mut Outputs::default())); // streq doesn't match, negated = true
    }

    #[test]
    fn test_operator_enum_dispatch() {
        let tx = Transaction::new("test");

        // Test that OperatorEnum correctly dispatches to each operator type
        let rx_op = rx("test").unwrap();
        let enum_op = OperatorEnum::from(rx_op);
        assert!(enum_op.evaluate(&tx, b"test123", &mut Outputs::default()));
        assert!(!enum_op.evaluate(&tx, b"other", &mut Outputs::default()));

        let contains_op = contains("hello").unwrap();
        let enum_op = OperatorEnum::from(contains_op);
        assert!(enum_op.evaluate(&tx, b"hello world", &mut Outputs::default()));
        assert!(!enum_op.evaluate(&tx, b"goodbye", &mut Outputs::default()));

        let eq_op = eq("42").unwrap();
        let enum_op = OperatorEnum::from(eq_op);
        assert!(enum_op.evaluate(&tx, b"42", &mut Outputs::default()));
        assert!(!enum_op.evaluate(&tx, b"43", &mut Outputs::default()));
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
        let tx = Transaction::new("test");

        // Test negation with regex
        let rx_op = RuleOperator::new(rx("^test").unwrap().into(), true);
        assert!(!rx_op.evaluate(&tx, b"test123", &mut Outputs::default())); // matches but negated
        assert!(rx_op.evaluate(&tx, b"other", &mut Outputs::default())); // doesn't match, negated = true

        // Test negation with contains
        let contains_op = RuleOperator::new(contains("admin").unwrap().into(), true);
        assert!(!contains_op.evaluate(&tx, b"admin user", &mut Outputs::default())); // matches but negated
        assert!(contains_op.evaluate(&tx, b"regular user", &mut Outputs::default())); // doesn't match, negated = true

        // Test negation with eq
        let eq_op = RuleOperator::new(eq("0").unwrap().into(), true);
        assert!(!eq_op.evaluate(&tx, b"0", &mut Outputs::default())); // matches but negated
        assert!(eq_op.evaluate(&tx, b"1", &mut Outputs::default())); // doesn't match, negated = true
    }
}
