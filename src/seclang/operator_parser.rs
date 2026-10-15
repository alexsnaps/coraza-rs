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

/// Parse operator from SecRule syntax
///
/// Parses operator specifications like:
/// - `@rx attack` - Regex operator
/// - `@streq admin` - String equality
/// - `!@contains bad` - Negated contains
/// - `attack` - Default to @rx (implicit)
/// - `!attack` - Negated @rx (implicit)
///
/// # Arguments
///
/// * `input` - Operator specification string
///
/// # Returns
///
/// The operator, with its function name (e.g. `"!@streq"`, which marks it negated) and argument
///
/// # Example
///
/// ```
/// use coraza::seclang::parse_operator;
///
/// // Parse explicit operator
/// let op = parse_operator("@rx attack")?;
/// assert_eq!((op.function(), op.data()), ("@rx", "attack"));
///
/// // Parse implicit @rx
/// let op = parse_operator("attack")?;
/// assert_eq!((op.function(), op.data()), ("@rx", "attack"));
///
/// // Parse negated operator
/// let op = parse_operator("!@streq admin")?;
/// assert_eq!((op.function(), op.data()), ("!@streq", "admin"));
/// assert!(op.is_negated());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn parse_operator(input: &str) -> ParseResult<RuleOperator> {
    parse_operator_in(input, &OperatorContext::default())
}

/// Like [`parse_operator`], creating the operator in `context`.
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

    Ok(RuleOperator::new(operator, function, argument))
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
        let op = parse_operator("@rx attack").unwrap();
        assert_eq!(op.function(), "@rx");
        assert_eq!(op.data(), "attack");
    }

    #[test]
    fn test_parse_implicit_rx() {
        let op = parse_operator("attack").unwrap();
        assert_eq!(op.function(), "@rx");
        assert_eq!(op.data(), "attack");
    }

    #[test]
    fn test_parse_negated_operator() {
        let op = parse_operator("!@streq admin").unwrap();
        assert_eq!(op.function(), "!@streq");
        assert_eq!(op.data(), "admin");
    }

    #[test]
    fn test_parse_negated_implicit_rx() {
        let op = parse_operator("!attack").unwrap();
        assert_eq!(op.function(), "!@rx");
        assert_eq!(op.data(), "attack");
    }

    #[test]
    fn test_parse_operator_no_arguments() {
        let op = parse_operator("@pm").unwrap();
        assert_eq!(op.function(), "@pm");
        assert_eq!(op.data(), "");
    }

    #[test]
    fn test_parse_streq_operator() {
        let op = parse_operator("@streq admin").unwrap();
        assert_eq!(op.function(), "@streq");
        assert_eq!(op.data(), "admin");
    }

    #[test]
    fn test_parse_contains_operator() {
        let op = parse_operator("@contains bad").unwrap();
        assert_eq!(op.function(), "@contains");
        assert_eq!(op.data(), "bad");
    }

    #[test]
    fn test_parse_eq_operator() {
        let op = parse_operator("@eq 5").unwrap();
        assert_eq!(op.function(), "@eq");
        assert_eq!(op.data(), "5");
    }

    #[test]
    fn test_parse_unknown_operator() {
        let result = parse_operator("@unknownop test");
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("unknown operator"));
    }

    #[test]
    fn test_parse_operator_case_insensitive() {
        let op1 = parse_operator("@RX attack").unwrap();
        let op2 = parse_operator("@rx attack").unwrap();
        let op3 = parse_operator("@Rx attack").unwrap();

        assert_eq!(op1.function(), "@RX");
        assert_eq!(op2.function(), "@rx");
        assert_eq!(op3.function(), "@Rx");
        // All should work (case-insensitive lookup)
    }

    #[test]
    fn test_parse_operator_with_multiple_spaces() {
        let op = parse_operator("@rx   attack   pattern  ").unwrap();
        assert_eq!(op.function(), "@rx");
        assert_eq!(op.data(), "attack   pattern"); // Preserves internal spaces
    }

    #[test]
    fn test_parse_negation_only() {
        let op = parse_operator("!").unwrap();
        assert_eq!(op.function(), "!@rx");
        assert_eq!(op.data(), "");
    }
}
