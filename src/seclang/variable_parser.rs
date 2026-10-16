// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Variable parser for SecRule directives.
//!
//! Parses variable syntax like:
//! - `ARGS` - All arguments
//! - `ARGS:id` - Specific argument by key
//! - `ARGS:/regex/` - Arguments matching regex
//! - `!ARGS:id` - Negation (exception)
//! - `&ARGS` - Count of arguments
//! - `ARGS|HEADERS` - Multiple variables
//! - `XML:xpath` - XPath selection
//! - `JSON:path` - JSON path selection

use std::borrow::Cow;
use std::str::FromStr;

use regex::RegexBuilder;
use winnow::combinator::{alt, eof, not, opt, preceded, repeat, terminated};
use winnow::error::EmptyError;
use winnow::prelude::*;
use winnow::token::{any, one_of, take_till};

use crate::rules::{VariableKey, VariableSpec};
use crate::seclang::CompileError;
use crate::types::RuleVariable;

type ParseResult<T> = Result<T, CompileError>;

/// Parsed variable result
///
/// Represents a single variable specification parsed from SecRule syntax.
#[derive(Debug, Clone)]
struct ParsedVariable {
    /// The variable type (ARGS, HEADERS, etc.)
    variable: RuleVariable,

    /// Optional key selector
    key: Option<String>,

    /// Is this a negation (!)
    is_negation: bool,

    /// Is this a count (&)
    is_count: bool,
}

/// Parse variables from SecRule syntax
///
/// Parses variable specifications like:
/// - `ARGS` - All arguments
/// - `ARGS:id` - Specific key
/// - `ARGS:/user.*/` - Regex key
/// - `!ARGS:id` - Negation
/// - `&ARGS` - Count
/// - `ARGS|HEADERS|TX` - Multiple variables
///
/// # Arguments
///
/// * `input` - Variable specification string
///
/// # Returns
///
/// Vector of VariableSpec objects
///
/// # Example
///
/// ```
/// use coraza::seclang::parse_variables;
///
/// // Parse simple variable
/// let vars = parse_variables("ARGS")?;
/// assert_eq!(vars.len(), 1);
///
/// // Parse multiple variables
/// let vars = parse_variables("ARGS|REQUEST_HEADERS")?;
/// assert_eq!(vars.len(), 2);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn parse_variables(input: &str) -> ParseResult<Vec<VariableSpec>> {
    let mut variables = Vec::new();
    VariableList::parse(input)?.apply_to(&mut variables);
    Ok(variables)
}

/// A parsed variable list (`ARGS|!ARGS:id|&TX:score`), to apply to a rule's variables.
pub(crate) struct VariableList(Vec<Element>);

impl VariableList {
    pub(crate) fn parse(input: &str) -> ParseResult<Self> {
        if input.is_empty() {
            return Err(CompileError::new(
                "empty variable specification".to_string(),
            ));
        }
        // Any text is a list as written: what's wrong with one shows as its variables are
        // looked up, in order, then built
        let written: Vec<WrittenVariable> = repeat(0.., written_variable)
            .parse(input.as_bytes())
            .expect("any text is a list of variables");
        let parsed = written
            .into_iter()
            .map(WrittenVariable::resolve)
            .collect::<ParseResult<Vec<_>>>()?;
        parsed
            .into_iter()
            .map(build_element)
            .collect::<ParseResult<_>>()
            .map(Self)
    }

    /// Adds the list's variables to `variables`, in order.
    ///
    /// A negated element (`!ARGS:id`) adds nothing: it excludes its key from every
    /// variable of that collection in `variables` at that point, as in Go Coraza.
    pub(crate) fn apply_to(&self, variables: &mut Vec<VariableSpec>) {
        for element in &self.0 {
            match element {
                // Cloned, as one list may be applied to several rules
                Element::Inspect(spec) => variables.push(spec.clone()),
                Element::Exclude(variable, key) => {
                    for spec in variables
                        .iter_mut()
                        .filter(|spec| spec.variable() == *variable)
                    {
                        match key {
                            VariableKey::String(key) => spec.add_exception_string(key.clone()),
                            VariableKey::Regex(key) => spec.add_exception_regex(key.clone()),
                        }
                    }
                }
            }
        }
    }
}

/// A variable of a list as written, its name not looked up yet.
struct WrittenVariable<'a> {
    /// Without the `!` and `&` marking a negation or a count
    name: Cow<'a, [u8]>,
    is_negation: bool,
    is_count: bool,
    key: WrittenKey<'a>,
    /// Whether a quote opened in the key is left open
    unclosed_quote: bool,
}

/// The key of a variable as written.
enum WrittenKey<'a> {
    /// A string, or no key if empty
    Text(Vec<u8>),
    /// An XPath or JSON path, or no key if empty
    Path(&'a [u8]),
    /// What's between the slashes of `/PATTERN/`, or no key if empty
    Regex(Vec<u8>),
}

impl WrittenVariable<'_> {
    /// Looks the variable up, checking it can have the key it is written with.
    fn resolve(self) -> ParseResult<ParsedVariable> {
        let name = String::from_utf8_lossy(&self.name);
        let variable = RuleVariable::from_str(&name)
            .map_err(|e| CompileError::new(format!("invalid variable name '{}': {}", name, e)))?;

        let (text, key) = match &self.key {
            WrittenKey::Text(text) => {
                if !text.is_empty() && !variable.can_be_selected() {
                    return Err(CompileError::new(format!(
                        "attempting to select a value inside a non-selectable collection: {}",
                        name
                    )));
                }
                (text.as_slice(), String::from_utf8_lossy(text).into_owned())
            }
            WrittenKey::Path(path) => (*path, String::from_utf8_lossy(path).into_owned()),
            WrittenKey::Regex(pattern) => (
                pattern.as_slice(),
                format!("/{}/", String::from_utf8_lossy(pattern)),
            ),
        };
        if self.unclosed_quote {
            return Err(CompileError::new(format!(
                "unclosed quote: {:?}",
                String::from_utf8_lossy(text)
            )));
        }

        Ok(ParsedVariable {
            variable,
            key: (!text.is_empty()).then_some(key),
            is_negation: self.is_negation,
            is_count: self.is_count,
        })
    }
}

/// A variable of a list, `[!][&]NAME[:KEY]`, and the `|` ending it.
///
/// The list's last character belongs to the name or key it ends, whatever it is: `ARGS:`
/// names a variable `ARGS:`, as in Go Coraza.
fn written_variable<'i>(input: &mut &'i [u8]) -> winnow::Result<WrittenVariable<'i>, EmptyError> {
    not(eof).parse_next(input)?;
    let (name, is_negation, is_count) = name(input)?;
    let (key, unclosed_quote) = match opt(b':').parse_next(input)? {
        None => {
            opt(b'|').parse_next(input)?;
            (WrittenKey::Text(Vec::new()), false)
        }
        Some(_) if *name == *b"XML" || *name == *b"JSON" => {
            let path = terminated(take_till(0.., b'|'), opt(b'|')).parse_next(input)?;
            (WrittenKey::Path(path), false)
        }
        Some(_) => key(input)?,
    };
    Ok(WrittenVariable {
        name,
        is_negation,
        is_count,
        key,
        unclosed_quote,
    })
}

/// NAME, up to a `|` or `:`: `(name, is_negation, is_count)`, a `!` or `&` anywhere in
/// it marking a negation or a count.
fn name<'i>(input: &mut &'i [u8]) -> winnow::Result<(Cow<'i, [u8]>, bool, bool), EmptyError> {
    // The list's last character is the name's, even a `:`, `!` or `&`
    let written = (take_till(0.., (b'|', b':')), opt((b':', eof)))
        .take()
        .parse_next(input)?;
    let (marked, last) = match input.is_empty() {
        true => written.split_at(written.len().saturating_sub(1)),
        false => (written, &b""[..]),
    };
    let is_marker = |c: &u8| matches!(c, b'!' | b'&');
    let name = match marked.iter().any(is_marker) {
        true => Cow::Owned(
            marked
                .iter()
                .filter(|c| !is_marker(c))
                .chain(last)
                .copied()
                .collect(),
        ),
        false => Cow::Borrowed(written),
    };
    Ok((name, marked.contains(&b'!'), marked.contains(&b'&')))
}

/// KEY of a collection other than `XML` and `JSON`, and what ends the variable: a
/// string, `/PATTERN/`, or a string then `/PATTERN/`, which join into one regex; and
/// whether a quote is left open.
///
/// A `'` in KEY is dropped, and marks the key quoted. What follows the `/` closing a
/// regex, or the `|` ending a string, is then skipped unread: two characters for a quoted
/// key, taken to be the `'` and `|` of `'/PATTERN/'|` (the quote is left open unless the
/// first is a `'`), and one for an unquoted regex, taken to be the `|`.
fn key<'i>(input: &mut &'i [u8]) -> winnow::Result<(WrittenKey<'i>, bool), EmptyError> {
    let piece = alt((
        take_till(1.., (b'|', b'/', b'\'')).map(Some),
        terminated(one_of((b'/', b'\'')), eof).take().map(Some),
        b'\''.value(None),
    ));
    let (mut text, is_quoted): (Vec<u8>, bool) = repeat(0.., piece)
        .fold(
            || (Vec::new(), false),
            |(mut text, is_quoted), piece| match piece {
                Some(piece) => {
                    text.extend_from_slice(piece);
                    (text, is_quoted)
                }
                None => (text, true),
            },
        )
        .parse_next(input)?;

    let (key, is_closed_regex) = match opt(preceded(b'/', pattern)).parse_next(input)? {
        Some((pattern, is_closed)) => {
            text.extend_from_slice(pattern);
            (WrittenKey::Regex(text), is_closed)
        }
        None => {
            opt(b'|').parse_next(input)?;
            (WrittenKey::Text(text), false)
        }
    };
    let unclosed_quote = is_quoted && input.first().is_some_and(|&c| c != b'\'');
    let skipped = match (is_quoted, is_closed_regex) {
        (true, _) => 2,
        (false, true) => 1,
        (false, false) => 0,
    };
    repeat::<_, _, (), _, _>(0..=skipped, any).parse_next(input)?;
    Ok((key, unclosed_quote))
}

/// What follows the `/` opening a regex: PATTERN, in which a backslash escapes the
/// character after it, up to the `/` closing it or the end of the list; and whether it
/// is closed.
fn pattern<'i>(input: &mut &'i [u8]) -> winnow::Result<(&'i [u8], bool), EmptyError> {
    let pattern = repeat::<_, _, (), _, _>(
        0..,
        alt((
            (b'\\', any).void(),
            take_till(1.., (b'\\', b'/')).void(),
            (b'\\', eof).void(),
        )),
    )
    .take()
    .parse_next(input)?;
    let is_closed = opt(b'/').parse_next(input)?.is_some();
    // An escaped `/` ending the list is dropped, as the closing one would be
    let pattern = match is_closed {
        true => pattern,
        false => pattern.strip_suffix(b"/").unwrap_or(pattern),
    };
    Ok((pattern, is_closed))
}

/// What one element of a variable list does to the rule's variables.
enum Element {
    /// A collection, or some of its keys, to inspect: `ARGS`, `ARGS:id`, `&ARGS`
    Inspect(VariableSpec),
    /// A key to leave out of the collection's other variables: `!ARGS:id`
    Exclude(RuleVariable, VariableKey),
}

fn build_element(var: ParsedVariable) -> ParseResult<Element> {
    let key = var
        .key
        .as_deref()
        .map(|key| parse_key(var.variable, key))
        .transpose()?;

    if var.is_negation {
        let key = key.ok_or_else(|| {
            CompileError::new(format!("a negated variable needs a key: !{}", var.variable))
        })?;
        return Ok(Element::Exclude(var.variable, key));
    }

    let mut spec = match key {
        Some(VariableKey::Regex(regex)) => VariableSpec::new_regex(var.variable, regex),
        Some(VariableKey::String(key)) => VariableSpec::new_string(var.variable, key),
        None => VariableSpec::new(var.variable),
    };
    spec.set_count(var.is_count);
    Ok(Element::Inspect(spec))
}

/// A regex key for `/pattern/`, otherwise a string key, for `variable`.
///
/// The regex ignores case unless `variable`'s keys are case-sensitive: the others' are
/// matched lowercase, as Go Coraza lowercases the pattern for them.
fn parse_key(variable: RuleVariable, key: &str) -> ParseResult<VariableKey> {
    match key.strip_prefix('/').and_then(|k| k.strip_suffix('/')) {
        Some(pattern) if !pattern.is_empty() => RegexBuilder::new(pattern)
            .case_insensitive(!variable.has_case_sensitive_keys())
            .build()
            .map(VariableKey::Regex)
            .map_err(|e| CompileError::new(format!("invalid regex pattern '{}': {}", pattern, e))),
        _ => Ok(VariableKey::String(key.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_variable() {
        let vars = parse_variables("ARGS").unwrap();
        assert_eq!(vars.len(), 1);
        // Variable should match ARGS with no key
    }

    #[test]
    fn test_parse_variable_with_string_key() {
        let vars = parse_variables("ARGS:username").unwrap();
        assert_eq!(vars.len(), 1);
    }

    #[test]
    fn test_parse_variable_with_regex_key() {
        let vars = parse_variables("ARGS:/user.*/").unwrap();
        assert_eq!(vars.len(), 1);
    }

    #[test]
    fn test_parse_count_variable() {
        let vars = parse_variables("&ARGS").unwrap();
        assert_eq!(vars.len(), 1);
    }

    #[test]
    fn test_parse_negation_excludes_from_earlier_variables() {
        let vars = parse_variables("ARGS|ARGS_GET|ARGS:id|!ARGS:id").unwrap();
        let exceptions: Vec<_> = vars.iter().map(|v| v.exception_count()).collect();
        assert_eq!(exceptions, [1, 0, 1]);
    }

    #[test]
    fn test_parse_negation_without_earlier_variable_adds_nothing() {
        assert!(parse_variables("!ARGS:id").unwrap().is_empty());
    }

    #[test]
    fn test_parse_negation_needs_a_key() {
        let err = parse_variables("ARGS|!ARGS").unwrap_err();
        assert!(err.message.contains("needs a key"), "{}", err.message);
    }

    #[test]
    fn test_parse_multiple_variables() {
        let vars = parse_variables("ARGS|REQUEST_HEADERS").unwrap();
        assert_eq!(vars.len(), 2);
    }

    #[test]
    fn test_parse_multiple_variables_with_keys() {
        let vars = parse_variables("ARGS:id|REQUEST_HEADERS:user-agent").unwrap();
        assert_eq!(vars.len(), 2);
    }

    #[test]
    fn test_parse_regex_with_escape() {
        let vars = parse_variables("ARGS:/test\\b/").unwrap();
        assert_eq!(vars.len(), 1);
    }

    #[test]
    fn test_parse_empty_input() {
        let result = parse_variables("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_variable() {
        let result = parse_variables("INVALID_VAR");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_non_selectable_with_key() {
        // REQUEST_URI cannot be selected with a key
        let result = parse_variables("REQUEST_URI:foo");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .message
                .contains("non-selectable collection")
        );
    }

    // Test cases from Go: TestParseRule
    #[test]
    fn test_parse_does_not_contain_escape_characters() {
        // ARGS_GET:/(test)/|REQUEST_XML
        let vars = parse_variables("ARGS_GET:/(test)/|REQUEST_XML").unwrap();
        assert_eq!(vars.len(), 2);
    }

    #[test]
    fn test_parse_last_variable_contains_escape_characters() {
        // ARGS_GET|REQUEST_XML:/(test)\b/
        let vars = parse_variables("ARGS_GET|REQUEST_XML:/(test)\\b/").unwrap();
        assert_eq!(vars.len(), 2);
    }

    #[test]
    fn test_parse_contains_escape_characters() {
        // ARGS_GET:/(test\b)/|REQUEST_XML
        let vars = parse_variables("ARGS_GET:/(test\\b)/|REQUEST_XML").unwrap();
        assert_eq!(vars.len(), 2);
    }

    /// The keys `variables` selects in `tx`.
    fn keys(variables: &str, tx: &crate::transaction::Transaction) -> Vec<String> {
        let mut keys: Vec<String> = parse_variables(variables)
            .unwrap()
            .iter()
            .flat_map(|spec| spec.get_matches(tx))
            .map(|matched| matched.key)
            .collect();
        keys.sort();
        keys
    }

    #[test]
    fn test_regex_key_case_follows_the_collection() {
        let mut tx = crate::transaction::Transaction::new("test");
        tx.add_request_header("X-Forwarded-For", "1.2.3.4");
        tx.add_request_header("Host", "localhost");
        tx.add_get_argument("Foo", "1");
        tx.add_get_argument("foo", "2");

        // Header names are case-insensitive, and so is a regex for them, as in Go
        assert_eq!(
            keys("REQUEST_HEADERS:/^X-FORWARDED/", &tx),
            ["X-Forwarded-For"]
        );
        assert_eq!(
            keys("REQUEST_HEADERS|!REQUEST_HEADERS:/^X-/", &tx),
            ["Host"]
        );
        // Argument names are case-sensitive
        assert_eq!(keys("ARGS:/^Foo$/", &tx), ["Foo"]);
    }

    #[test]
    fn test_regex_keys_quoted_or_holding_a_pipe() {
        let mut tx = crate::transaction::Transaction::new("test");
        tx.add_get_argument("id_1", "1");
        tx.add_get_argument("name", "2");

        assert_eq!(keys("ARGS:'/^id_/'", &tx), ["id_1"]);
        assert_eq!(keys("ARGS:/a|e/|ARGS_NAMES", &tx), ["id_1", "name", "name"]);
    }

    #[test]
    fn test_parse_path_keys() {
        let vars = parse_variables("XML:/*|XML://@*|JSON:a.b").unwrap();
        assert_eq!(vars.len(), 3);
    }

    #[test]
    fn test_parse_last_character_belongs_to_the_last_variable() {
        let err = parse_variables("ARGS|ARGS:").unwrap_err();
        assert!(
            err.message.contains("invalid variable name 'ARGS:'"),
            "{}",
            err.message
        );
    }

    #[test]
    fn test_parse_unclosed_quote() {
        let err = parse_variables("ARGS:'/a/|TX").unwrap_err();
        assert_eq!(err.message, "unclosed quote: \"a\"");
    }
}
