// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Rule operators for WAF matching.
//!
//! Operators are used to evaluate input values against configured parameters.
//! They return boolean results indicating whether the match succeeded.

pub mod macros;
mod pattern;
mod simple;

#[allow(deprecated)]
pub use macros::{Macro, MacroError, NoTx, TransactionState};
pub use pattern::{Pm, Rx, StrMatch, Within, pm, rx, strmatch, within};
pub use simple::{
    BeginsWith, Contains, EndsWith, Eq, Ge, Gt, Le, Lt, StrEq, begins_with, contains, ends_with,
    eq, ge, gt, le, lt, streq,
};

/// Trait for rule operators.
///
/// Operators evaluate input values and return whether they match the configured
/// criteria. Operators support macro expansion, allowing parameter values to
/// reference transaction variables like `%{TX.score}`.
pub trait Operator {
    /// Evaluates the operator against an input value.
    ///
    /// The optional `tx` parameter provides access to transaction state for
    /// macro expansion. If `None`, macros are not expanded.
    ///
    /// Returns true if the operator matches the input value according to its
    /// configured parameter (after macro expansion).
    fn evaluate<TX: TransactionState>(&self, tx: Option<&TX>, input: &str) -> bool;
}
