// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Rule operators for WAF matching.
//!
//! Operators are used to evaluate input values against configured parameters.
//! They return boolean results indicating whether the match succeeded.

pub mod detection;
pub mod external;
pub mod ip;
pub mod macros;
mod pattern;
mod simple;
pub mod validation;

pub use detection::{DetectSQLi, DetectXSS, detect_sqli, detect_xss};
pub use external::{InspectFile, Rbl, inspect_file, rbl};
pub use ip::{
    IpMatch, IpMatchFromDataset, IpMatchFromFile, ip_match, ip_match_from_dataset,
    ip_match_from_file,
};
pub use macros::{Macro, MacroError};

use std::collections::BTreeMap;
use std::path::Path;

use crate::transaction::Transaction;
pub use pattern::{
    Pm, PmFromDataset, PmFromFile, RestPath, Rx, StrMatch, Within, pm, pm_from_dataset,
    pm_from_file, rest_path, rx, strmatch, within,
};
pub use simple::{
    BeginsWith, Contains, EndsWith, Eq, Ge, Gt, Le, Lt, StrEq, begins_with, contains, ends_with,
    eq, ge, gt, le, lt, streq,
};
pub use validation::{
    NoMatch, UnconditionalMatch, ValidateByteRange, ValidateNid, ValidateUrlEncoding,
    ValidateUtf8Encoding, no_match, unconditional_match, validate_byte_range, validate_nid,
    validate_url_encoding, validate_utf8_encoding,
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

/// Named lists of items (`SecDataset`), for `@pmFromDataset` and `@ipMatchFromDataset`.
pub type Datasets = BTreeMap<String, Vec<String>>;

/// What creating an operator may need besides its name and argument.
#[derive(Debug, Clone, Copy)]
pub struct OperatorContext<'a> {
    /// Directory a relative file argument (of `@pmFromFile` and `@ipMatchFromFile`) is
    /// relative to; empty for the working directory. SecLang rules use the directory of
    /// the file they are in.
    pub base_dir: &'a Path,

    /// Datasets the `…FromDataset` operators can name
    pub datasets: &'a Datasets,
}

impl Default for OperatorContext<'_> {
    fn default() -> Self {
        static NO_DATASETS: Datasets = BTreeMap::new();
        Self {
            base_dir: Path::new(""),
            datasets: &NO_DATASETS,
        }
    }
}

/// Declares [`OperatorEnum`] from one table of operators: each row names the variant
/// (and the type it wraps), its SecLang names (lowercase, without `@`), and a
/// constructor from the operator's argument string and [`OperatorContext`].
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
            /// e.g. `OperatorEnum::new("rx", "^admin")`, in the default [`OperatorContext`].
            ///
            /// # Errors
            ///
            /// Returns a message if the name is unknown or the argument is invalid for
            /// that operator.
            pub fn new(name: &str, argument: &str) -> Result<Self, String> {
                Self::with_context(name, argument, &OperatorContext::default())
            }

            /// Like [`OperatorEnum::new`], in `context`.
            ///
            /// # Errors
            ///
            /// As [`OperatorEnum::new`].
            pub fn with_context(
                name: &str,
                argument: &str,
                context: &OperatorContext<'_>,
            ) -> Result<Self, String> {
                match name.to_ascii_lowercase().as_str() {
                    $($($name)|+ => {
                        let new: fn(&str, &OperatorContext<'_>) -> Result<$variant, String> = $new;
                        new(argument, context).map(Self::$variant)
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
    Rx: "rx" => |arg, _| rx(arg).map_err(|e| e.to_string()),
    Pm: "pm" => |arg, _| pm(arg).map_err(|e| e.to_string()),
    PmFromFile: "pmfromfile" | "pmf" => |arg, ctx| pm_from_file(ctx.base_dir.join(arg)),
    PmFromDataset: "pmfromdataset" => |arg, ctx| pm_from_dataset(arg, ctx.datasets),
    StrMatch: "strmatch" => |arg, _| strmatch(arg).map_err(|e| e.to_string()),
    Within: "within" => |arg, _| within(arg).map_err(|e| e.to_string()),
    StrEq: "streq" => |arg, _| streq(arg).map_err(|e| e.to_string()),
    Contains: "contains" => |arg, _| contains(arg).map_err(|e| e.to_string()),
    BeginsWith: "beginswith" => |arg, _| begins_with(arg).map_err(|e| e.to_string()),
    EndsWith: "endswith" => |arg, _| ends_with(arg).map_err(|e| e.to_string()),
    Eq: "eq" => |arg, _| eq(arg).map_err(|e| e.to_string()),
    Lt: "lt" => |arg, _| lt(arg).map_err(|e| e.to_string()),
    Le: "le" => |arg, _| le(arg).map_err(|e| e.to_string()),
    Gt: "gt" => |arg, _| gt(arg).map_err(|e| e.to_string()),
    Ge: "ge" => |arg, _| ge(arg).map_err(|e| e.to_string()),
    IpMatch: "ipmatch" => |arg, _| ip_match(arg),
    IpMatchFromFile: "ipmatchfromfile" | "ipmatchf" => |arg, ctx| {
        ip_match_from_file(ctx.base_dir.join(arg))
    },
    IpMatchFromDataset: "ipmatchfromdataset" => |arg, ctx| ip_match_from_dataset(arg, ctx.datasets),
    ValidateByteRange: "validatebyterange" => |arg, _| validate_byte_range(arg),
    ValidateUrlEncoding: "validateurlencoding" => |_, _| Ok(validate_url_encoding()),
    ValidateUtf8Encoding: "validateutf8encoding" => |_, _| Ok(validate_utf8_encoding()),
    DetectSQLi: "detectsqli" => |_, _| Ok(detect_sqli()),
    DetectXSS: "detectxss" => |_, _| Ok(detect_xss()),
    // Go Coraza's @geoLookup matches unconditionally too
    UnconditionalMatch: "unconditionalmatch" | "geolookup" => |_, _| Ok(unconditional_match()),
    RestPath: "restpath" => |arg, _| rest_path(arg),
    ValidateNid: "validatenid" => |arg, _| validate_nid(arg),
    InspectFile: "inspectfile" => |arg, _| Ok(inspect_file(arg)),
    Rbl: "rbl" => |arg, _| Ok(rbl(arg)),
    NoMatch: "nomatch" => |_, _| Ok(no_match()),
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
