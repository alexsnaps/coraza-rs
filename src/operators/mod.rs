// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Rule operators for WAF matching.
//!
//! Operators are used to evaluate input values against configured parameters.
//! They return boolean results indicating whether the match succeeded.

pub mod detection;
pub mod ip;
pub mod macros;
mod pattern;
mod simple;
pub mod validation;

pub use detection::{DetectSQLi, DetectXSS, detect_sqli, detect_xss};
pub use ip::{IpMatch, IpMatchFromFile, ip_match, ip_match_from_file};
pub use macros::{Macro, MacroError};

use crate::transaction::Transaction;
pub use pattern::{Pm, PmFromFile, Rx, StrMatch, Within, pm, pm_from_file, rx, strmatch, within};
pub use simple::{
    BeginsWith, Contains, EndsWith, Eq, Ge, Gt, Le, Lt, StrEq, begins_with, contains, ends_with,
    eq, ge, gt, le, lt, streq,
};
pub use validation::{
    NoMatch, UnconditionalMatch, ValidateByteRange, ValidateUrlEncoding, ValidateUtf8Encoding,
    no_match, unconditional_match, validate_byte_range, validate_url_encoding,
    validate_utf8_encoding,
};

/// Trait for rule operators.
///
/// Operators evaluate input values and return whether they match the configured
/// criteria. Operators support macro expansion and capturing groups (for regex).
pub trait Operator {
    /// Evaluates the operator against an input value.
    ///
    /// The optional `tx` parameter provides mutable access to transaction state for:
    /// - Macro expansion (reading variables like `%{TX.score}`)
    /// - Capturing regex groups (writing matched values)
    ///
    /// If `None`, macros are not expanded and capturing is disabled.
    ///
    /// Returns true if the operator matches the input value according to its
    /// configured parameter (after macro expansion).
    fn evaluate(&self, tx: Option<&mut Transaction>, input: &str) -> bool;
}

/// Declares [`OperatorEnum`] from one table of operators: each row names the variant
/// (and the type it wraps), its SecLang names (lowercase, without `@`), and a
/// constructor from the operator's argument string.
macro_rules! operators {
    ($($variant:ident: $($name:literal)|+ => $new:expr,)+) => {
        /// Any operator, for static dispatch.
        ///
        /// Built from a SecLang name with [`OperatorEnum::new`], or from an operator value
        /// with `into()`.
        #[derive(Debug, Clone)]
        pub enum OperatorEnum {
            $(
                #[allow(missing_docs)]
                $variant($variant),
            )+
        }

        impl OperatorEnum {
            /// Creates the operator with SecLang name `name` (case-insensitive, without `@`),
            /// e.g. `OperatorEnum::new("rx", "^admin")`.
            ///
            /// # Errors
            ///
            /// Returns a message if the name is unknown or the argument is invalid for
            /// that operator.
            pub fn new(name: &str, argument: &str) -> Result<Self, String> {
                match name.to_ascii_lowercase().as_str() {
                    $($($name)|+ => {
                        let new: fn(&str) -> Result<$variant, String> = $new;
                        new(argument).map(Self::$variant)
                    })+
                    _ => Err(format!("unknown operator: {}", name)),
                }
            }

            /// Evaluates the wrapped operator; see [`Operator::evaluate`].
            pub fn evaluate(&self, tx: Option<&mut Transaction>, input: &str) -> bool {
                match self {
                    $(Self::$variant(op) => op.evaluate(tx, input),)+
                }
            }
        }

        $(
            impl From<$variant> for OperatorEnum {
                fn from(op: $variant) -> Self {
                    Self::$variant(op)
                }
            }
        )+
    };
}

operators! {
    Rx: "rx" => |arg| rx(arg).map_err(|e| e.to_string()),
    Pm: "pm" => |arg| pm(arg).map_err(|e| e.to_string()),
    PmFromFile: "pmfromfile" | "pmf" => pm_from_file,
    StrMatch: "strmatch" => |arg| strmatch(arg).map_err(|e| e.to_string()),
    Within: "within" => |arg| within(arg).map_err(|e| e.to_string()),
    StrEq: "streq" => |arg| streq(arg).map_err(|e| e.to_string()),
    Contains: "contains" => |arg| contains(arg).map_err(|e| e.to_string()),
    BeginsWith: "beginswith" => |arg| begins_with(arg).map_err(|e| e.to_string()),
    EndsWith: "endswith" => |arg| ends_with(arg).map_err(|e| e.to_string()),
    Eq: "eq" => |arg| eq(arg).map_err(|e| e.to_string()),
    Lt: "lt" => |arg| lt(arg).map_err(|e| e.to_string()),
    Le: "le" => |arg| le(arg).map_err(|e| e.to_string()),
    Gt: "gt" => |arg| gt(arg).map_err(|e| e.to_string()),
    Ge: "ge" => |arg| ge(arg).map_err(|e| e.to_string()),
    IpMatch: "ipmatch" => ip_match,
    IpMatchFromFile: "ipmatchfromfile" | "ipmatchf" => ip_match_from_file,
    ValidateByteRange: "validatebyterange" => validate_byte_range,
    ValidateUrlEncoding: "validateurlencoding" => |_| Ok(validate_url_encoding()),
    ValidateUtf8Encoding: "validateutf8encoding" => |_| Ok(validate_utf8_encoding()),
    DetectSQLi: "detectsqli" => |_| Ok(detect_sqli()),
    DetectXSS: "detectxss" => |_| Ok(detect_xss()),
    UnconditionalMatch: "unconditionalmatch" => |_| Ok(unconditional_match()),
    NoMatch: "nomatch" => |_| Ok(no_match()),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_case_insensitive_and_accepts_aliases() {
        assert!(matches!(
            OperatorEnum::new("BeginsWith", "a"),
            Ok(OperatorEnum::BeginsWith(_))
        ));
        assert!(OperatorEnum::new("pmf", "/nonexistent").is_err());
    }

    #[test]
    fn new_reaches_every_operator_in_the_table() {
        let op = OperatorEnum::new("noMatch", "").unwrap();
        assert!(!op.evaluate(None, "anything"));

        let err = OperatorEnum::new("ipMatchFromFile", "/nonexistent").unwrap_err();
        assert!(!err.contains("unknown operator"), "{}", err);
    }

    #[test]
    fn new_rejects_unknown_names() {
        let err = OperatorEnum::new("noSuchOp", "").unwrap_err();
        assert_eq!(err, "unknown operator: noSuchOp");
    }
}
