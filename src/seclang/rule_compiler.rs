// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Rule compilation from SecLang directives.
//!
//! Compiles SecRule, SecAction, and SecMarker directives into executable Rule structures.

use std::borrow::Cow;
use std::collections::BTreeMap;

use winnow::combinator::{alt, delimited, repeat};
use winnow::error::EmptyError;
use winnow::prelude::*;
use winnow::token::{any, take_till};

use crate::RulePhase;
use crate::actions::{Action, ActionType, RuleMetadata};
use crate::operators::OperatorContext;
use crate::rules::Rule;
use crate::seclang::CompileError;
use crate::seclang::action_parser::ParsedAction;
use crate::seclang::operator_parser::parse_operator_in;
use crate::seclang::{parse_actions, parse_variables};
use crate::utils::strings::maybe_remove_quotes;

type CompileResult<T> = Result<T, CompileError>;

/// Compile a SecRule directive into a Rule.
///
/// Parses the format: `SecRule VARIABLES OPERATOR ACTIONS`
///
/// # Arguments
///
/// * `input` - Full SecRule directive string (without "SecRule" prefix)
///
/// The operator is created in the default [`OperatorContext`]: a relative data file
/// is relative to the working directory. The actions are merged with the built-in
/// defaults, as in a configuration without `SecDefaultAction`.
///
/// # Example
///
/// ```
/// use coraza::seclang::compile_sec_rule;
///
/// let rule = compile_sec_rule("ARGS \"@rx attack\" \"id:1,deny,log\"")?;
/// assert_eq!(rule.metadata().id, 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn compile_sec_rule(input: &str) -> CompileResult<Rule> {
    compile_sec_rule_in(
        input,
        &OperatorContext::default(),
        &DefaultActions::default(),
    )
}

/// Like [`compile_sec_rule`], creating the operator in `context` and merging the
/// actions with `defaults`.
pub(crate) fn compile_sec_rule_in(
    input: &str,
    context: &OperatorContext<'_>,
    defaults: &DefaultActions,
) -> CompileResult<Rule> {
    let RuleArguments {
        variables: vars,
        operator,
        actions,
    } = RuleArguments::parse(input)?;

    // Parse variables
    let variable_specs = parse_variables(vars)
        .map_err(|e| CompileError::new(format!("failed to parse variables '{}': {}", vars, e)))?;

    // Parse operator
    let rule_operator = parse_operator_in(operator, context).map_err(|e| {
        CompileError::new(format!("failed to parse operator '{}': {}", operator, e))
    })?;

    // Parse actions (none if empty)
    let parsed_actions = parse_actions(actions)
        .map_err(|e| CompileError::new(format!("failed to parse actions '{}': {}", actions, e)))?;

    // Build rule
    let mut rule = Rule::new();

    // Add variables
    for var_spec in variable_specs {
        rule = rule.add_variable(var_spec);
    }

    rule = rule.with_operator(rule_operator);

    add_actions(rule, parsed_actions, defaults)
}

/// Compile a SecAction directive into a Rule.
///
/// Parses the format: `SecAction ACTIONS`
///
/// SecAction creates an operator-less rule that always matches.
///
/// # Arguments
///
/// * `input` - Full SecAction directive string (without "SecAction" prefix)
///
/// The actions are merged with the built-in defaults, as in a configuration without
/// `SecDefaultAction`.
///
/// # Example
///
/// ```
/// use coraza::seclang::compile_sec_action;
///
/// let rule = compile_sec_action("\"id:1,deny,nolog\"")?;
/// assert_eq!(rule.metadata().id, 1);
/// assert!(rule.operator().is_none());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn compile_sec_action(input: &str) -> CompileResult<Rule> {
    compile_sec_action_in(input, &DefaultActions::default())
}

/// Like [`compile_sec_action`], merging the actions with `defaults`.
pub(crate) fn compile_sec_action_in(input: &str, defaults: &DefaultActions) -> CompileResult<Rule> {
    // Remove quotes from actions
    let actions = maybe_remove_quotes(input);

    // Parse actions
    let parsed_actions = parse_actions(actions)
        .map_err(|e| CompileError::new(format!("failed to parse actions '{}': {}", actions, e)))?;

    // Build rule (no operator, no variables)
    add_actions(Rule::new(), parsed_actions, defaults)
}

/// Applies a rule's parsed actions to `rule`, merged with the defaults of its phase.
///
/// As in Go Coraza, the defaults' actions other than the disruptive one apply first,
/// then the rule's own, but for `block`. The defaults' disruptive action applies last,
/// if the rule has no other. Without defaults for its phase, a rule keeps its actions
/// as written, `block` included (which then does nothing).
fn add_actions(
    mut rule: Rule,
    parsed_actions: Vec<ParsedAction>,
    defaults: &DefaultActions,
) -> CompileResult<Rule> {
    let Some(defaults) = defaults.for_phase(phase_of(&parsed_actions)?) else {
        apply_actions(&mut rule, &parsed_actions)?;
        return Ok(rule);
    };

    apply_actions(&mut rule, &defaults.others)?;
    apply_actions(
        &mut rule,
        parsed_actions.iter().filter(|a| a.key != "block"),
    )?;
    if !rule
        .actions()
        .iter()
        .any(|action| action.action_type() == ActionType::Disruptive)
    {
        apply_actions(&mut rule, [&defaults.disruptive])?;
    }
    Ok(rule)
}

/// Applies parsed actions to `rule` in order: metadata actions update its metadata,
/// the others are added to it (a later disruptive action replaces an earlier one).
pub(crate) fn apply_actions<'a>(
    rule: &mut Rule,
    parsed_actions: impl IntoIterator<Item = &'a ParsedAction>,
) -> CompileResult<()> {
    for parsed in parsed_actions {
        if let Some(action) = Action::parse(&parsed.key, &parsed.value, rule.metadata_mut())? {
            rule.push_action(action);
        }
    }
    Ok(())
}

/// The phase that the `phase` action among `actions` gives a rule (2 without one).
fn phase_of(actions: &[ParsedAction]) -> CompileResult<RulePhase> {
    let mut metadata = RuleMetadata::new();
    for action in actions.iter().filter(|a| a.key == "phase") {
        Action::parse(&action.key, &action.value, &mut metadata)?;
    }
    Ok(metadata.phase)
}

/// The actions `SecDefaultAction` gives the rules of each phase, which rules compiled
/// after it inherit; see `add_actions`.
///
/// Phase 2 has built-in defaults, `phase:2,log,auditlog,pass`, until a
/// `SecDefaultAction` sets its own; the other phases have none.
#[derive(Debug, Clone, Default)]
pub(crate) struct DefaultActions {
    phases: BTreeMap<RulePhase, PhaseDefaults>,
}

/// The defaults of one phase.
#[derive(Debug, Clone)]
struct PhaseDefaults {
    /// Actions applied before the rule's own, in order
    others: Vec<ParsedAction>,
    /// Applies when the rule has no disruptive action, or `block`
    disruptive: ParsedAction,
}

impl DefaultActions {
    /// Adds the defaults of one `SecDefaultAction`.
    ///
    /// # Errors
    ///
    /// If `actions` is not valid, names no phase or no disruptive action, holds metadata
    /// actions (`id`, `msg`, `tag`, ...) or transformations, or its phase already has
    /// defaults.
    pub(crate) fn add(&mut self, actions: &str) -> CompileResult<()> {
        const METADATA: [&str; 8] = [
            "accuracy", "id", "maturity", "msg", "rev", "severity", "tag", "ver",
        ];

        let mut metadata = RuleMetadata::new();
        let mut has_phase = false;
        let mut others = Vec::new();
        let mut disruptive = None;
        for parsed in parse_actions(actions)? {
            if METADATA.contains(&parsed.key.as_str()) {
                return Err(CompileError::new(format!(
                    "SecDefaultAction must not contain metadata actions: {}",
                    parsed.key
                )));
            }
            if parsed.key == "t" {
                return Err(CompileError::new(
                    "SecDefaultAction must not contain transformations (t)".to_string(),
                ));
            }
            let action = Action::parse(&parsed.key, &parsed.value, &mut metadata)?;
            if parsed.key == "phase" {
                has_phase = true;
            } else if action.is_some_and(|a| a.action_type() == ActionType::Disruptive) {
                disruptive = Some(parsed);
            } else {
                others.push(parsed);
            }
        }

        if !has_phase {
            return Err(CompileError::new(
                "SecDefaultAction must contain a phase".to_string(),
            ));
        }
        let disruptive = disruptive.ok_or_else(|| {
            CompileError::new("SecDefaultAction must contain a disruptive action".to_string())
        })?;
        if self.phases.contains_key(&metadata.phase) {
            return Err(CompileError::new(format!(
                "SecDefaultAction already defined for phase {}",
                metadata.phase
            )));
        }
        self.phases
            .insert(metadata.phase, PhaseDefaults { others, disruptive });
        Ok(())
    }

    fn for_phase(&self, phase: RulePhase) -> Option<Cow<'_, PhaseDefaults>> {
        match self.phases.get(&phase) {
            Some(defaults) => Some(Cow::Borrowed(defaults)),
            None if phase == RulePhase::RequestBody => {
                let action = |key: &str| ParsedAction {
                    key: key.to_string(),
                    value: String::new(),
                };
                Some(Cow::Owned(PhaseDefaults {
                    others: vec![action("log"), action("auditlog")],
                    disruptive: action("pass"),
                }))
            }
            None => None,
        }
    }
}

/// Compile a SecMarker directive into a Rule.
///
/// Parses the format: `SecMarker LABEL`
///
/// SecMarker creates a flow control marker with no evaluation logic.
///
/// # Arguments
///
/// * `input` - Marker label
///
/// # Example
///
/// ```
/// use coraza::seclang::compile_sec_marker;
///
/// let rule = compile_sec_marker("BEGIN_PHASE_1")?;
/// // Marker rules have ID 0 and no operator
/// assert_eq!(rule.metadata().id, 0);
/// assert!(rule.operator().is_none());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn compile_sec_marker(input: &str) -> CompileResult<Rule> {
    let label = maybe_remove_quotes(input.trim());
    if label.is_empty() {
        return Err(CompileError::new("SecMarker requires a label".to_string()));
    }

    // Create marker rule with ID 0 and phase Unknown (matches all phases)
    let mut rule = Rule::new().with_id(0);

    // Set marker label in metadata
    rule.metadata_mut().sec_mark = Some(label.to_string());
    rule.metadata_mut().phase = crate::RulePhase::Unknown;

    Ok(rule)
}

/// The arguments of a `SecRule`, as written: `VARIABLES "OPERATOR" ["ACTIONS"]`.
#[derive(Debug, PartialEq, Eq)]
struct RuleArguments<'a> {
    variables: &'a str,
    /// Between the quotes, escapes kept
    operator: &'a str,
    /// Between the quotes; empty without actions
    actions: &'a str,
}

impl<'a> RuleArguments<'a> {
    /// Splits `data`: VARIABLES runs to the first space, then OPERATOR is double-quoted, a
    /// backslash escaping the character after it, and ACTIONS takes all that follows, in
    /// double quotes.
    fn parse(data: &'a str) -> CompileResult<Self> {
        let data = data.trim();
        let invalid = |part: &str| {
            CompileError::new(format!("invalid {part} for rule with operator: {data:?}"))
        };

        let (variables, rest) = data.split_once(' ').ok_or_else(|| invalid("format"))?;
        let rest = rest.trim_start();
        if !rest.starts_with('"') {
            return Err(invalid("operator"));
        }
        let (rest, operator) = double_quoted
            .parse_peek(rest)
            .map_err(|_| CompileError::new(format!("expected terminating quote: {:?}", rest)))?;
        let actions = match rest.trim_start() {
            "" => "",
            rest => rest
                .strip_prefix('"')
                .and_then(|rest| rest.strip_suffix('"'))
                .ok_or_else(|| invalid("actions"))?,
        };

        Ok(Self {
            variables,
            operator,
            actions,
        })
    }
}

/// `"..."`, in which a backslash escapes the character after it; returns what's between
/// the quotes, escapes kept.
fn double_quoted<'i>(input: &mut &'i str) -> winnow::Result<&'i str, EmptyError> {
    let inside = repeat::<_, _, (), _, _>(
        0..,
        alt((('\\', any).void(), take_till(1.., ['\\', '"']).void())),
    );
    delimited('"', inside.take(), '"').parse_next(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(variables, operator, actions)` of `data`.
    fn split(data: &str) -> CompileResult<(&str, &str, &str)> {
        RuleArguments::parse(data).map(|args| (args.variables, args.operator, args.actions))
    }

    #[test]
    fn test_double_quoted() {
        assert_eq!(
            double_quoted.parse_peek("\"value\" rest"),
            Ok((" rest", "value"))
        );
        assert_eq!(
            double_quoted.parse_peek("\"val\\\"ue\" rest"),
            Ok((" rest", "val\\\"ue"))
        );
        // An even number of backslashes doesn't escape the quote
        assert_eq!(double_quoted.parse_peek("\"a\\\\\"b"), Ok(("b", "a\\\\")));
        assert!(double_quoted.parse_peek("\"unclosed").is_err());
        assert!(double_quoted.parse_peek("\"unclosed\\\"").is_err());
        assert!(double_quoted.parse_peek("value\"").is_err());
    }

    #[test]
    fn test_split_rule_arguments() {
        assert_eq!(
            split("ARGS \"@rx attack\" \"id:1,deny\""),
            Ok(("ARGS", "@rx attack", "id:1,deny"))
        );
        assert_eq!(split("ARGS \"@rx attack\""), Ok(("ARGS", "@rx attack", "")));
        assert_eq!(
            split("ARGS \"@rx \\\"quoted\\\"\" \"id:1\""),
            Ok(("ARGS", "@rx \\\"quoted\\\"", "id:1"))
        );
        assert_eq!(
            split("ARGS|REQUEST_HEADERS  \t\"@rx attack\"\t\"id:1\""),
            Ok(("ARGS|REQUEST_HEADERS", "@rx attack", "id:1"))
        );
    }

    #[test]
    fn test_split_rule_arguments_errors() {
        let message = |data| split(data).unwrap_err().message;
        assert_eq!(
            message("ARGS"),
            "invalid format for rule with operator: \"ARGS\""
        );
        assert_eq!(
            message("ARGS @rx"),
            "invalid operator for rule with operator: \"ARGS @rx\""
        );
        assert_eq!(
            message("ARGS  \"@rx"),
            "expected terminating quote: \"\\\"@rx\""
        );
        assert_eq!(
            message("ARGS \"@rx\" id:1"),
            "invalid actions for rule with operator: \"ARGS \\\"@rx\\\" id:1\""
        );
    }

    #[test]
    fn test_compile_sec_rule_simple() {
        let rule = compile_sec_rule("ARGS \"@rx attack\" \"id:1,deny,log\"").unwrap();
        assert_eq!(rule.metadata().id, 1);
        assert!(rule.operator().is_some());
    }

    #[test]
    fn test_compile_sec_action_simple() {
        let rule = compile_sec_action("\"id:100,nolog\"").unwrap();
        assert_eq!(rule.metadata().id, 100);
        assert!(rule.operator().is_none());
    }

    #[test]
    fn test_compile_sec_marker_simple() {
        let rule = compile_sec_marker("BEGIN_TESTS").unwrap();
        assert_eq!(rule.metadata().id, 0);
        assert!(rule.operator().is_none());
        assert_eq!(rule.metadata().sec_mark, Some("BEGIN_TESTS".to_string()));
    }

    #[test]
    fn test_compile_sec_marker_empty() {
        let result = compile_sec_marker("");
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_sec_marker_lone_quote() {
        // Not a pair of quotes around the label, which is the quote
        let rule = compile_sec_marker("\"").unwrap();
        assert_eq!(rule.metadata().sec_mark.as_deref(), Some("\""));
    }

    #[test]
    fn test_unknown_action_is_a_compile_error() {
        let err = compile_sec_action("id:1,unknownaction").unwrap_err();
        assert!(err.message.contains("unknown action"), "{}", err.message);
    }

    #[test]
    fn test_last_disruptive_action_wins() {
        let rule = compile_sec_action("id:1,deny,setvar:tx.a=1,drop").unwrap();
        let names: Vec<&str> = rule.actions().iter().map(|a| a.name()).collect();
        assert_eq!(names, ["setvar", "drop"]);
    }
}
