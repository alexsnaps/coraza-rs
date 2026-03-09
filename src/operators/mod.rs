// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Rule operators for WAF matching.
//!
//! Operators are used to evaluate input values against configured parameters.
//! They return boolean results indicating whether the match succeeded.

mod simple;

pub use simple::{
    BeginsWith, Contains, EndsWith, Eq, Ge, Gt, Le, Lt, StrEq, begins_with, contains, ends_with,
    eq, ge, gt, le, lt, streq,
};

/// Trait for rule operators.
///
/// Operators evaluate input values and return whether they match the configured
/// criteria. This is a simplified version without transaction state or macro
/// expansion support.
pub trait Operator {
    /// Evaluates the operator against an input value.
    ///
    /// Returns true if the operator matches the input value according to its
    /// configured parameter.
    fn evaluate(&self, input: &str) -> bool;
}
