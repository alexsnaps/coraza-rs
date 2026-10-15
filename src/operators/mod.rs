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
    /// The operator reads `tx` (to expand macros such as `%{TX.score}`) but never changes
    /// it: what it hands back to its rule, captures and `@restpath`'s path arguments, goes
    /// to `out`.
    ///
    /// Returns true if the operator matches the input value according to its
    /// configured parameter (after macro expansion).
    fn evaluate(&self, tx: &Transaction, input: &str, out: &mut Outputs) -> bool;
}

/// What operators hand back to their rule for a value: its captures, if the rule asked for
/// them (`capture`), and the path arguments `@restpath` takes from it.
///
/// The rule owns it and stores its content in the transaction after each value: captures
/// in `TX.0` to `TX.9`, path arguments in `ARGS_PATH`.
#[derive(Debug, Default)]
pub struct Outputs {
    /// Whether the rule asked for captures
    capturing: bool,
    /// Captures by index, 0 to 9, in the order the operator made them
    captures: Vec<(usize, String)>,
    /// Path arguments, as key and value
    path_arguments: Vec<(String, String)>,
}

impl Outputs {
    /// Outputs for a rule that asks for captures if `capturing`.
    pub fn new(capturing: bool) -> Self {
        Self {
            capturing,
            ..Self::default()
        }
    }

    /// Whether the rule asked for captures; operators can skip the work of capturing
    /// when it didn't.
    pub fn wants_captures(&self) -> bool {
        self.capturing
    }

    /// Captures `value` as capture `index` (0 to 9), if the rule asked for captures.
    pub fn capture(&mut self, index: usize, value: &str) {
        if self.capturing {
            self.captures.push((index, value.to_string()));
        }
    }

    /// Adds a path argument, as `@restpath` takes from a value.
    pub fn add_path_argument(&mut self, key: &str, value: &str) {
        self.path_arguments
            .push((key.to_string(), value.to_string()));
    }

    /// The captures, by index and in the order they were made, leaving none.
    pub(crate) fn take_captures(&mut self) -> std::vec::Drain<'_, (usize, String)> {
        self.captures.drain(..)
    }

    /// The path arguments, in the order they were added, leaving none.
    pub(crate) fn take_path_arguments(&mut self) -> std::vec::Drain<'_, (String, String)> {
        self.path_arguments.drain(..)
    }
}

/// `matches(input)` for tests: evaluates an operator in an empty transaction, without captures.
#[cfg(test)]
pub(crate) trait Matches {
    fn matches(&self, input: &str) -> bool;
}

#[cfg(test)]
impl<O: Operator> Matches for O {
    fn matches(&self, input: &str) -> bool {
        self.evaluate(&Transaction::default(), input, &mut Outputs::default())
    }
}

/// For tests: evaluates `op` on `input` in `tx`, for a rule that captures if `capturing`, and
/// stores what it handed back in `tx`, as the rule does.
#[cfg(test)]
pub(crate) fn evaluate_in(
    op: &impl Operator,
    tx: &mut Transaction,
    input: &str,
    capturing: bool,
) -> bool {
    let mut out = Outputs::new(capturing);
    let matched = op.evaluate(tx, input, &mut out);
    tx.store_operator_outputs(&mut out);
    matched
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
            pub fn evaluate(&self, tx: &Transaction, input: &str, out: &mut Outputs) -> bool {
                match self {
                    $(Self::$variant(op) => op.evaluate(tx, input, out),)+
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
        assert!(!op.evaluate(&Transaction::default(), "anything", &mut Outputs::default()));

        let err = OperatorEnum::new("ipMatchFromFile", "/nonexistent").unwrap_err();
        assert!(!err.contains("unknown operator"), "{}", err);
    }

    #[test]
    fn new_rejects_unknown_names() {
        let err = OperatorEnum::new("noSuchOp", "").unwrap_err();
        assert_eq!(err, "unknown operator: noSuchOp");
    }
}
