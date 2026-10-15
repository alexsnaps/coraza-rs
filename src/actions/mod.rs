// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Rule actions for WAF processing.
//!
//! Actions define how the system handles HTTP requests when rule conditions match.
//! Actions are defined as part of a SecRule or as parameters for SecAction or SecDefaultAction.
//! A rule can have no or several actions which need to be separated by a comma.
//!
//! # Action Categories
//!
//! Most actions only describe the rule (`id`, `msg`, `tag`, `severity`, `phase`, `t`,
//! `chain`, `status`, `log`, ...): they are applied to its [`RuleMetadata`] when the rule
//! is compiled. The others are [`Action`]s, run when the rule matches, at a point set by
//! their [`ActionType`]:
//!
//! - **Non-disruptive** (`setvar`, `ctl`, `setenv`): for every value the rule matches.
//! - **Flow** (`skip`, `skipAfter`): once the rule's whole chain matched.
//! - **Disruptive** (`deny`, `drop`, `block`, `allow`, `redirect`, `pass`): once the whole
//!   chain matched, and only if SecRuleEngine is `On`. Only the last one a rule lists applies.
//!
//! # Usage
//!
//! Actions are specified in SecRule directives as comma-separated values:
//!
//! ```text
//! SecRule ARGS "@rx attack" "id:100,deny,log,msg:'Attack detected'"
//! ```

mod ctl;
mod deferred;
mod disruptive;
mod flow;
mod logging;
mod metadata;
mod special;
mod variables;

use std::fmt;

use crate::operators::Macro;
use crate::rules::TransformationChain;
use crate::transaction::Transaction;
use crate::{RulePhase, RuleSeverity};

pub use ctl::CtlAction;
pub use deferred::SetenvAction;
pub use disruptive::{
    AllowAction, AllowType, BlockAction, DenyAction, DropAction, PassAction, RedirectAction,
};
pub use flow::{SkipAction, SkipAfterAction};
pub use variables::SetvarAction;

/// Action execution errors.
#[derive(Debug, Clone, PartialEq)]
pub enum ActionError {
    /// Action requires arguments but none were provided.
    MissingArguments,
    /// Action does not accept arguments but some were provided.
    UnexpectedArguments,
    /// Action arguments have invalid syntax.
    InvalidArguments(String),
    /// Action name is unknown/not registered.
    UnknownAction(String),
    /// Macro expansion error in action parameter.
    MacroError(String),
}

impl fmt::Display for ActionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActionError::MissingArguments => write!(f, "missing arguments"),
            ActionError::UnexpectedArguments => write!(f, "unexpected arguments"),
            ActionError::InvalidArguments(msg) => write!(f, "invalid arguments: {}", msg),
            ActionError::UnknownAction(name) => write!(f, "unknown action: {}", name),
            ActionError::MacroError(msg) => write!(f, "macro error: {}", msg),
        }
    }
}

impl std::error::Error for ActionError {}

impl From<crate::operators::MacroError> for ActionError {
    fn from(err: crate::operators::MacroError) -> Self {
        ActionError::MacroError(err.to_string())
    }
}

/// When an [`Action`] runs, relative to its rule's chain and the rule engine mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionType {
    /// Runs for every value the rule matches, even if a later chain link fails
    /// (setvar, ctl, setenv).
    Nondisruptive,

    /// Runs once the whole chain matched (skip, skipAfter).
    Flow,

    /// Runs once the whole chain matched, and only if the rule engine is `On`
    /// (deny, drop, block, allow, redirect, pass). A rule has at most one.
    Disruptive,
}

/// Metadata and flags of one rule (ID, message, severity, logging flags, ...).
///
/// Actions fill this in when the rule is compiled ([`Action::init`]) and read it
/// when the rule matches ([`Action::evaluate`]). The evaluated rule itself is
/// [`crate::rules::Rule`].
#[derive(Debug, Clone)]
pub struct RuleMetadata {
    /// Rule ID (mandatory, set by id action)
    pub id: i32,
    /// Rule message with macro expansion support
    pub msg: Option<Macro>,
    /// Severity level (0-7)
    pub severity: Option<RuleSeverity>,
    /// Classification tags
    pub tags: Vec<String>,
    /// Revision number
    pub rev: String,
    /// Version string
    pub ver: String,
    /// Maturity level (1-9); 0 when unset
    pub maturity: u8,
    /// Accuracy level (1-9); 0 when unset
    pub accuracy: u8,
    /// Additional log data with macro expansion
    pub log_data: Option<Macro>,
    /// HTTP status code for blocking actions
    pub status: i32,
    /// Whether to log matches
    pub log: bool,
    /// Whether to audit log matches
    pub audit_log: bool,
    /// Whether the rule has the `chain` action: the next rule added to a
    /// [`crate::rules::RuleGroup`] joins this rule's chain
    pub has_chain: bool,
    /// Whether to capture regex groups into TX variables
    pub capture: bool,
    /// Whether to check variables before/after each transformation
    pub multi_match: bool,
    /// Transformations applied to each variable value before the operator (`t:`)
    pub transformations: TransformationChain,
    /// SecMarker label (for flow control markers)
    pub sec_mark: Option<String>,
    /// Processing phase (1-5)
    pub phase: RulePhase,
    /// File the rule was written in; empty for a rule not read from a file
    pub file: String,
    /// Line of `file` the rule's directive starts on; 0 when unknown
    pub line: usize,
    /// The rule's directive as written; empty for a rule not compiled from SecLang
    pub raw: String,
}

impl RuleMetadata {
    /// Create a new rule with default values.
    pub fn new() -> Self {
        Self {
            id: 0,
            msg: None,
            severity: None,
            tags: Vec::new(),
            rev: String::new(),
            ver: String::new(),
            maturity: 0,
            accuracy: 0,
            log_data: None,
            status: 0,
            log: false,
            audit_log: false,
            has_chain: false,
            capture: false,
            multi_match: false,
            transformations: TransformationChain::new(),
            sec_mark: None,
            phase: RulePhase::RequestBody, // Default phase is 2 (request body)
            file: String::new(),
            line: 0,
            raw: String::new(),
        }
    }
}

impl Default for RuleMetadata {
    fn default() -> Self {
        Self::new()
    }
}

/// What a rule does at runtime when it matches.
///
/// Actions that only describe the rule (`id`, `msg`, `phase`, `t`, `chain`, `status`, ...)
/// are applied to its [`RuleMetadata`] when the rule is compiled and have no runtime part;
/// see [`Action::parse`].
#[derive(Debug, Clone)]
pub enum Action {
    Deny(DenyAction),
    Drop(DropAction),
    Block(BlockAction),
    Pass(PassAction),
    Allow(AllowAction),
    Redirect(RedirectAction),
    Skip(SkipAction),
    SkipAfter(SkipAfterAction),
    Setvar(SetvarAction),
    Ctl(CtlAction),
    Setenv(SetenvAction),
}

impl Action {
    /// Parses the SecLang action `name` (case-insensitive) with its `argument`
    /// (empty if none).
    ///
    /// Actions that only describe the rule update `rule` and return `None`; the others
    /// return the action to run when the rule matches.
    ///
    /// # Errors
    ///
    /// Returns `ActionError::UnknownAction` for an unknown name, or another
    /// `ActionError` if the argument is invalid for that action.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::actions::{Action, RuleMetadata};
    ///
    /// let mut rule = RuleMetadata::new();
    /// assert!(Action::parse("id", "1", &mut rule).unwrap().is_none());
    /// assert_eq!(rule.id, 1);
    ///
    /// let deny = Action::parse("deny", "", &mut rule).unwrap().unwrap();
    /// assert_eq!(deny.name(), "deny");
    /// ```
    pub fn parse(
        name: &str,
        argument: &str,
        rule: &mut RuleMetadata,
    ) -> Result<Option<Self>, ActionError> {
        let lowercase = name.to_ascii_lowercase();

        type ApplyToRule = fn(&mut RuleMetadata, &str) -> Result<(), ActionError>;
        let apply: Option<ApplyToRule> = match lowercase.as_str() {
            "id" => Some(metadata::id),
            "msg" => Some(metadata::msg),
            "tag" => Some(metadata::tag),
            "severity" => Some(metadata::severity),
            "rev" => Some(metadata::rev),
            "ver" => Some(metadata::ver),
            "maturity" => Some(metadata::maturity),
            "accuracy" => Some(metadata::accuracy),
            "phase" => Some(metadata::phase),
            "log" => Some(logging::log),
            "nolog" => Some(logging::nolog),
            "auditlog" => Some(logging::auditlog),
            "noauditlog" => Some(logging::noauditlog),
            "logdata" => Some(logging::logdata),
            "capture" => Some(special::capture),
            "multimatch" => Some(special::multimatch),
            "status" => Some(special::status),
            "t" => Some(special::t),
            "chain" => Some(flow::chain),
            "exec" => Some(deferred::exec),
            "expirevar" => Some(deferred::expirevar),
            "initcol" => Some(deferred::initcol),
            _ => None,
        };
        if let Some(apply) = apply {
            apply(rule, argument)?;
            return Ok(None);
        }

        let action = match lowercase.as_str() {
            "deny" => Self::Deny(DenyAction::parse(argument)?),
            "drop" => Self::Drop(DropAction::parse(argument)?),
            "block" => Self::Block(BlockAction::parse(argument)?),
            "pass" => Self::Pass(PassAction::parse(argument)?),
            "allow" => Self::Allow(AllowAction::parse(argument)?),
            "redirect" => Self::Redirect(RedirectAction::parse(argument)?),
            "skip" => Self::Skip(SkipAction::parse(argument)?),
            "skipafter" => Self::SkipAfter(SkipAfterAction::parse(argument)?),
            "setvar" => Self::Setvar(SetvarAction::parse(argument)?),
            "ctl" => Self::Ctl(CtlAction::parse(argument)?),
            "setenv" => Self::Setenv(SetenvAction::parse(argument)?),
            _ => return Err(ActionError::UnknownAction(name.to_string())),
        };
        Ok(Some(action))
    }

    /// The SecLang name of the action, e.g. `"skipAfter"`.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Deny(_) => "deny",
            Self::Drop(_) => "drop",
            Self::Block(_) => "block",
            Self::Pass(_) => "pass",
            Self::Allow(_) => "allow",
            Self::Redirect(_) => "redirect",
            Self::Skip(_) => "skip",
            Self::SkipAfter(_) => "skipAfter",
            Self::Setvar(_) => "setvar",
            Self::Ctl(_) => "ctl",
            Self::Setenv(_) => "setenv",
        }
    }

    /// When the action runs; see [`ActionType`].
    pub fn action_type(&self) -> ActionType {
        match self {
            Self::Deny(_)
            | Self::Drop(_)
            | Self::Block(_)
            | Self::Pass(_)
            | Self::Allow(_)
            | Self::Redirect(_) => ActionType::Disruptive,
            Self::Skip(_) | Self::SkipAfter(_) => ActionType::Flow,
            Self::Setvar(_) | Self::Ctl(_) | Self::Setenv(_) => ActionType::Nondisruptive,
        }
    }

    /// Runs the action for a match of the rule described by `rule`.
    pub fn evaluate(&self, rule: &RuleMetadata, tx: &mut Transaction) {
        match self {
            Self::Deny(action) => action.evaluate(rule, tx),
            Self::Drop(action) => action.evaluate(rule, tx),
            // `block` left in a rule (its phase has no defaults) does nothing
            Self::Block(_) | Self::Pass(_) => {}
            Self::Allow(action) => action.evaluate(tx),
            Self::Redirect(action) => action.evaluate(rule, tx),
            Self::Skip(action) => action.evaluate(tx),
            Self::SkipAfter(action) => action.evaluate(tx),
            Self::Setvar(action) => action.evaluate(tx),
            Self::Ctl(action) => action.evaluate(tx),
            Self::Setenv(action) => action.evaluate(tx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(name: &str, argument: &str) -> Result<Option<Action>, ActionError> {
        Action::parse(name, argument, &mut RuleMetadata::new())
    }

    #[test]
    fn test_action_error_display() {
        assert_eq!(
            ActionError::MissingArguments.to_string(),
            "missing arguments"
        );
        assert_eq!(
            ActionError::UnexpectedArguments.to_string(),
            "unexpected arguments"
        );
        assert_eq!(
            ActionError::InvalidArguments("bad syntax".to_string()).to_string(),
            "invalid arguments: bad syntax"
        );
        assert_eq!(
            ActionError::UnknownAction("foo".to_string()).to_string(),
            "unknown action: foo"
        );
    }

    #[test]
    fn test_parse_unknown_action() {
        assert_eq!(
            parse("nonexistent_action", "").unwrap_err(),
            ActionError::UnknownAction("nonexistent_action".to_string())
        );
    }

    #[test]
    fn test_parse_is_case_insensitive() {
        let mut rule = RuleMetadata::new();
        assert!(Action::parse("ID", "7", &mut rule).unwrap().is_none());
        assert_eq!(rule.id, 7);
        assert!(parse("DeNy", "").unwrap().is_some());
    }

    #[test]
    fn test_metadata_actions_have_no_runtime_part() {
        for (name, argument) in [
            ("id", "1"),
            ("msg", "m"),
            ("tag", "t"),
            ("severity", "2"),
            ("rev", "1"),
            ("ver", "1"),
            ("maturity", "1"),
            ("phase", "2"),
            ("log", ""),
            ("nolog", ""),
            ("auditlog", ""),
            ("noauditlog", ""),
            ("logdata", "d"),
            ("capture", ""),
            ("multimatch", ""),
            ("status", "403"),
            ("t", "lowercase"),
            ("chain", ""),
            ("exec", "/bin/true"),
            ("expirevar", "tx.a=60"),
            ("initcol", "ip=%{REMOTE_ADDR}"),
        ] {
            assert!(
                parse(name, argument).unwrap().is_none(),
                "{} should only update metadata",
                name
            );
        }
    }

    #[test]
    fn test_runtime_actions_and_their_types() {
        for (name, argument, expected) in [
            ("deny", "", ActionType::Disruptive),
            ("drop", "", ActionType::Disruptive),
            ("block", "", ActionType::Disruptive),
            ("pass", "", ActionType::Disruptive),
            ("allow", "phase", ActionType::Disruptive),
            ("redirect", "http://example.com", ActionType::Disruptive),
            ("skip", "2", ActionType::Flow),
            ("skipafter", "END", ActionType::Flow),
            ("setvar", "tx.a=1", ActionType::Nondisruptive),
            ("ctl", "ruleEngine=Off", ActionType::Nondisruptive),
            ("setenv", "A=b", ActionType::Nondisruptive),
        ] {
            let action = parse(name, argument).unwrap().expect(name);
            assert_eq!(action.action_type(), expected, "{}", name);
            assert!(action.name().eq_ignore_ascii_case(name), "{}", name);
        }
    }
}
