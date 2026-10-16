// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Operator parser for SecRule directives.
//!
//! Parses operator syntax like:
//! - `@rx pattern` - Regex operator
//! - `@pm word1 word2` - Pattern match
//! - `!@streq value` - Negated string equality
//! - `pattern` - Default to @rx (implicit)
//! - `!pattern` - Negated @rx (implicit)

use winnow::combinator::{alt, opt, preceded};
use winnow::error::EmptyError;
use winnow::prelude::*;
use winnow::token::{rest, take_till};

use crate::operators::{OperatorContext, OperatorEnum};
use crate::rules::RuleOperator;

use crate::seclang::CompileError;

type ParseResult<T> = Result<T, CompileError>;

/// Parses an operator as SecRule writes it, created with no base directory or datasets:
/// `@rx attack`, `!@contains bad`, or `attack` and `!attack` for an implicit `@rx`.
#[cfg(test)]
pub(crate) fn parse_operator(input: &str) -> ParseResult<RuleOperator> {
    parse_operator_in(input, &OperatorContext::default())
}

/// Parses an operator as SecRule writes it, creating it in `context`.
pub(crate) fn parse_operator_in(
    input: &str,
    context: &OperatorContext<'_>,
) -> ParseResult<RuleOperator> {
    let OperatorSpec {
        function,
        name,
        argument,
    } = operator_spec
        .parse(input.trim())
        .expect("any text is an operator");

    let operator = OperatorEnum::with_context(name, argument, context)
        .map_err(|e| CompileError::new(format!("failed to create @{} operator: {}", name, e)))?;

    Ok(RuleOperator::new(operator, function.starts_with('!')))
}

/// An operator as written.
#[derive(Debug, PartialEq, Eq)]
struct OperatorSpec<'a> {
    /// `@NAME` or `!@NAME`, as written but for an implicit `@rx`
    function: &'a str,
    /// NAME
    name: &'a str,
    /// What follows NAME, trimmed
    argument: &'a str,
}

/// `[!]@NAME[ ARGUMENT]`, or `[!]ARGUMENT` for `@rx`.
///
/// NAME runs to the first space; whitespace around it and around ARGUMENT is dropped.
fn operator_spec<'i>(input: &mut &'i str) -> winnow::Result<OperatorSpec<'i>, EmptyError> {
    let explicit = (
        preceded((opt('!'), '@'), take_till(0.., ' ')).with_taken(),
        opt(preceded(' ', rest)),
    )
        .map(
            |((name, function), argument): ((&str, &str), Option<&str>)| OperatorSpec {
                function: function.trim_end(),
                name: name.trim_end(),
                argument: argument.unwrap_or_default().trim(),
            },
        );
    let implicit = (opt('!'), rest).map(|(negation, argument): (Option<_>, &str)| OperatorSpec {
        function: if negation.is_some() { "!@rx" } else { "@rx" },
        name: "rx",
        argument: argument.trim(),
    });
    alt((explicit, implicit)).parse_next(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::Outputs;
    use crate::transaction::Transaction;

    /// Whether the operator `input` gives matches `value`.
    fn matches(input: &str, value: &str) -> bool {
        let operator = parse_operator(input).unwrap();
        operator.evaluate(
            &Transaction::new("test"),
            value.as_bytes(),
            &mut Outputs::default(),
        )
    }

    /// `(function, name, argument)` of `input`, which has been trimmed.
    fn spec(input: &str) -> (&str, &str, &str) {
        let spec = operator_spec.parse(input).unwrap();
        (spec.function, spec.name, spec.argument)
    }

    #[test]
    fn test_spec_implicit_rx() {
        assert_eq!(spec(""), ("@rx", "rx", ""));
        assert_eq!(spec("attack"), ("@rx", "rx", "attack"));
        assert_eq!(spec("!"), ("!@rx", "rx", ""));
        assert_eq!(spec("!attack"), ("!@rx", "rx", "attack"));
        assert_eq!(spec("! attack"), ("!@rx", "rx", "attack"));
    }

    #[test]
    fn test_spec_explicit_operator() {
        assert_eq!(spec("@rx attack"), ("@rx", "rx", "attack"));
        assert_eq!(spec("!@rx attack"), ("!@rx", "rx", "attack"));
        assert_eq!(spec("@pm"), ("@pm", "pm", ""));
    }

    #[test]
    fn test_spec_name_ends_at_a_space() {
        // A tab doesn't end the name, as in Go Coraza
        assert_eq!(spec("@rx\tattack"), ("@rx\tattack", "rx\tattack", ""));
        assert_eq!(spec("@rx\t attack"), ("@rx", "rx", "attack"));
    }

    #[test]
    fn test_parse_rx_operator() {
        assert!(matches("@rx attack", "an attack"));
        assert!(!matches("@rx attack", "benign"));
    }

    #[test]
    fn test_parse_implicit_rx() {
        assert!(matches("attack", "an attack"));
        assert!(!matches("attack", "benign"));
    }

    #[test]
    fn test_parse_negated_operator() {
        assert!(!matches("!@streq admin", "admin"));
        assert!(matches("!@streq admin", "user"));
    }

    #[test]
    fn test_parse_negated_implicit_rx() {
        assert!(!matches("!attack", "an attack"));
        assert!(matches("!attack", "benign"));
    }

    #[test]
    fn test_parse_operator_no_arguments() {
        assert!(parse_operator("@pm").is_ok());
    }

    #[test]
    fn test_parse_streq_operator() {
        assert!(matches("@streq admin", "admin"));
        assert!(!matches("@streq admin", "admins"));
    }

    #[test]
    fn test_parse_contains_operator() {
        assert!(matches("@contains bad", "very bad"));
        assert!(!matches("@contains bad", "good"));
    }

    #[test]
    fn test_parse_eq_operator() {
        assert!(matches("@eq 5", "5"));
        assert!(!matches("@eq 5", "6"));
    }

    #[test]
    fn test_parse_unknown_operator() {
        let result = parse_operator("@unknownop test");
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("unknown operator"));
    }

    #[test]
    fn test_parse_operator_case_insensitive() {
        // The name is looked up case-insensitively
        for input in ["@RX attack", "@rx attack", "@Rx attack"] {
            assert!(matches(input, "an attack"), "{input}");
        }
    }

    #[test]
    fn test_parse_operator_with_multiple_spaces() {
        // The argument keeps its inner spaces
        assert!(matches("@rx   attack   pattern  ", "attack   pattern"));
        assert!(!matches("@rx   attack   pattern  ", "attack pattern"));
    }

    #[test]
    fn test_parse_negation_only() {
        // A negated empty @rx, which matches anything
        assert!(!matches("!", "anything"));
    }
}
