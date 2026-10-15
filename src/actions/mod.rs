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
//! Actions are categorized into five types:
//!
//! ## 1. Disruptive Actions
//!
//! Trigger WAF operations such as blocking or allowing transactions.
//! Only one disruptive action per rule applies; if multiple are specified,
//! the last one takes precedence. Disruptive actions will NOT be executed
//! if SecRuleEngine is set to DetectionOnly.
//!
//! Examples: deny, drop, redirect, allow, block, pass
//!
//! ## 2. Non-disruptive Actions
//!
//! Perform operations without affecting rule flow, such as variable modifications,
//! logging, or setting metadata. These actions execute regardless of SecRuleEngine mode.
//!
//! Examples: log, nolog, setvar, msg, logdata, severity, tag
//!
//! ## 3. Flow Actions
//!
//! Control rule processing and execution flow. These actions determine which rules
//! are evaluated and in what order.
//!
//! Examples: chain, skip, skipAfter
//!
//! ## 4. Meta-data Actions
//!
//! Provide information about rules, such as identification, versioning, and classification.
//! These actions do not affect transaction processing.
//!
//! Examples: id, rev, msg, tag, severity, maturity, ver
//!
//! ## 5. Data Actions
//!
//! Containers that hold data for use by other actions, such as status codes
//! for blocking responses.
//!
//! Examples: status (used with deny/redirect)
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
pub use disruptive::{
    AllowAction, AllowType, BlockAction, DenyAction, DropAction, PassAction, RedirectAction,
};
pub use flow::{ChainAction, SkipAction, SkipAfterAction};
pub use logging::{AuditlogAction, LogAction, LogdataAction, NoauditlogAction, NologAction};
pub use metadata::{
    IdAction, MaturityAction, MsgAction, PhaseAction, RevAction, SeverityAction, TagAction,
    VerAction,
};
pub use special::{CaptureAction, MultimatchAction, StatusAction, TAction};
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

/// Action type categories.
///
/// Actions are categorized into five types that define when and how they execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionType {
    /// Metadata actions provide information about rules.
    ///
    /// Examples: id, rev, msg, tag, severity, maturity, ver
    Metadata,

    /// Disruptive actions trigger WAF operations like blocking.
    ///
    /// Only one disruptive action per rule applies. These actions are NOT
    /// executed if SecRuleEngine is set to DetectionOnly.
    ///
    /// Examples: deny, drop, redirect, allow, block, pass
    Disruptive,

    /// Data actions are containers that hold data for use by other actions.
    ///
    /// Examples: status (used with deny/redirect)
    Data,

    /// Non-disruptive actions perform operations without affecting rule flow.
    ///
    /// Examples: log, nolog, setvar, msg, logdata, severity, tag
    Nondisruptive,

    /// Flow actions control rule processing and execution flow.
    ///
    /// Examples: chain, skip, skipAfter
    Flow,
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
    /// Maturity level (1-9)
    pub maturity: u8,
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
        }
    }
}

impl Default for RuleMetadata {
    fn default() -> Self {
        Self::new()
    }
}

/// Rule action trait.
///
/// Actions define what happens when a rule matches. Each action implements this trait
/// with two key methods: `init()` for parsing parameters during rule compilation, and
/// `evaluate()` for executing the action during transaction processing.
///
/// # Examples
///
/// ```
/// use coraza::actions::{Action, ActionType, ActionError, RuleMetadata};
/// use coraza::transaction::Transaction;
///
/// // Simple action that requires no parameters
/// struct DenyAction;
///
/// impl Action for DenyAction {
///     fn init(&mut self, _rule: &mut RuleMetadata, data: &str) -> Result<(), ActionError> {
///         if !data.is_empty() {
///             return Err(ActionError::UnexpectedArguments);
///         }
///         Ok(())
///     }
///
///     fn evaluate(&self, _rule: &RuleMetadata, _tx: &mut Transaction) {
///         // Execute action logic (e.g., interrupt transaction)
///     }
///
///     fn action_type(&self) -> ActionType {
///         ActionType::Disruptive
///     }
/// }
/// ```
pub trait Action: Send + Sync {
    /// Initialize the action with parameters from the rule.
    ///
    /// This method is called during rule compilation to parse and validate
    /// action parameters. Actions can modify the rule metadata during initialization
    /// (e.g., storing the rule ID, message, or severity).
    ///
    /// # Arguments
    ///
    /// * `rule` - Mutable reference to rule for storing action configuration
    /// * `data` - Parameter string for the action (may be empty for parameterless actions)
    ///
    /// # Returns
    ///
    /// * `Ok(())` if initialization succeeded
    /// * `Err(ActionError)` if parameters are invalid
    fn init(&mut self, rule: &mut RuleMetadata, data: &str) -> Result<(), ActionError>;

    /// Evaluate the action during transaction processing.
    ///
    /// This method is called when a rule matches and the action should execute.
    /// Actions can modify transaction state, log messages, interrupt processing, etc.
    ///
    /// # Arguments
    ///
    /// * `rule` - Immutable reference to rule
    /// * `tx` - Mutable reference to transaction state
    fn evaluate(&self, rule: &RuleMetadata, tx: &mut Transaction);

    /// Return the action type category.
    fn action_type(&self) -> ActionType;
}

/// Creates a new, uninitialized instance of the built-in action named `name`
/// (case-insensitive).
///
/// # Errors
///
/// Returns `ActionError::UnknownAction` if no built-in action has that name.
///
/// # Examples
///
/// ```
/// use coraza::actions::get;
///
/// let action = get("deny").unwrap();
/// assert!(get("noSuchAction").is_err());
/// ```
pub fn get(name: &str) -> Result<Box<dyn Action>, ActionError> {
    let action: Box<dyn Action> = match name.to_ascii_lowercase().as_str() {
        "id" => Box::new(IdAction),
        "msg" => Box::new(MsgAction),
        "tag" => Box::new(TagAction),
        "severity" => Box::new(SeverityAction),
        "rev" => Box::new(RevAction),
        "ver" => Box::new(VerAction),
        "maturity" => Box::new(MaturityAction),
        "phase" => Box::new(PhaseAction),
        "log" => Box::new(LogAction),
        "nolog" => Box::new(NologAction),
        "auditlog" => Box::new(AuditlogAction),
        "noauditlog" => Box::new(NoauditlogAction),
        "logdata" => Box::new(LogdataAction),
        "deny" => Box::new(DenyAction),
        "drop" => Box::new(DropAction),
        "allow" => Box::new(AllowAction::new()),
        "block" => Box::new(BlockAction),
        "redirect" => Box::new(RedirectAction::new()),
        "pass" => Box::new(PassAction),
        "setvar" => Box::new(SetvarAction::new()),
        "chain" => Box::new(ChainAction),
        "skip" => Box::new(SkipAction::new()),
        "skipafter" => Box::new(SkipAfterAction::new()),
        "capture" => Box::new(CaptureAction),
        "multimatch" => Box::new(MultimatchAction),
        "status" => Box::new(StatusAction),
        "t" => Box::new(TAction),
        "ctl" => Box::new(CtlAction::new()),
        "exec" => Box::new(deferred::ExecAction::new()),
        "expirevar" => Box::new(deferred::ExpirevarAction::new()),
        "setenv" => Box::new(deferred::SetenvAction::new()),
        "initcol" => Box::new(deferred::InitcolAction::new()),
        _ => return Err(ActionError::UnknownAction(name.to_string())),
    };
    Ok(action)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock action for testing
    struct MockAction {
        initialized: bool,
    }

    impl Action for MockAction {
        fn init(&mut self, _rule: &mut RuleMetadata, data: &str) -> Result<(), ActionError> {
            if !data.is_empty() {
                return Err(ActionError::UnexpectedArguments);
            }
            self.initialized = true;
            Ok(())
        }

        fn evaluate(&self, _rule: &RuleMetadata, _tx: &mut Transaction) {
            // Mock evaluation
        }

        fn action_type(&self) -> ActionType {
            ActionType::Nondisruptive
        }
    }

    #[test]
    fn test_action_type_categories() {
        assert_eq!(ActionType::Metadata, ActionType::Metadata);
        assert_ne!(ActionType::Metadata, ActionType::Disruptive);
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
    fn test_mock_action_init() {
        let mut action = MockAction { initialized: false };
        let mut rule = RuleMetadata::new();

        // Should succeed with empty data
        assert!(action.init(&mut rule, "").is_ok());
        assert!(action.initialized);

        // Should fail with non-empty data
        let mut action2 = MockAction { initialized: false };
        let result = action2.init(&mut rule, "unexpected");
        assert_eq!(result, Err(ActionError::UnexpectedArguments));
    }

    #[test]
    fn test_get_unknown_action() {
        let result = get("nonexistent_action");
        assert!(matches!(result, Err(ActionError::UnknownAction(_))));
    }

    #[test]
    fn test_get_id_action() {
        let action = get("id");
        assert!(action.is_ok());
        assert_eq!(action.unwrap().action_type(), ActionType::Metadata);
    }

    #[test]
    fn test_get_msg_action() {
        let action = get("msg");
        assert!(action.is_ok());
        assert_eq!(action.unwrap().action_type(), ActionType::Metadata);
    }

    #[test]
    fn test_get_severity_action() {
        let action = get("severity");
        assert!(action.is_ok());
        assert_eq!(action.unwrap().action_type(), ActionType::Metadata);
    }

    #[test]
    fn test_get_case_insensitive() {
        // Registry should be case-insensitive
        assert!(get("ID").is_ok());
        assert!(get("Id").is_ok());
        assert!(get("MSG").is_ok());
        assert!(get("Msg").is_ok());
    }

    #[test]
    fn test_all_metadata_actions_registered() {
        // Ensure all 7 metadata actions are registered
        let actions = vec!["id", "msg", "tag", "severity", "rev", "ver", "maturity"];
        for name in actions {
            assert!(get(name).is_ok(), "Action '{}' not registered", name);
        }
    }

    #[test]
    fn test_all_logging_actions_registered() {
        // Ensure all 5 logging actions are registered
        let actions = vec!["log", "nolog", "auditlog", "noauditlog", "logdata"];
        for name in actions {
            assert!(get(name).is_ok(), "Action '{}' not registered", name);
        }
    }

    #[test]
    fn test_logging_action_types() {
        // Verify all logging actions have Nondisruptive type
        let actions = vec!["log", "nolog", "auditlog", "noauditlog", "logdata"];
        for name in actions {
            let action = get(name).unwrap();
            assert_eq!(
                action.action_type(),
                ActionType::Nondisruptive,
                "Action '{}' should be Nondisruptive",
                name
            );
        }
    }

    #[test]
    fn test_all_disruptive_actions_registered() {
        // Ensure all 6 disruptive actions are registered
        let actions = vec!["deny", "drop", "allow", "block", "redirect", "pass"];
        for name in actions {
            assert!(get(name).is_ok(), "Action '{}' not registered", name);
        }
    }

    #[test]
    fn test_disruptive_action_types() {
        // Verify all disruptive actions have Disruptive type
        let actions = vec!["deny", "drop", "allow", "block", "redirect", "pass"];
        for name in actions {
            let action = get(name).unwrap();
            assert_eq!(
                action.action_type(),
                ActionType::Disruptive,
                "Action '{}' should be Disruptive",
                name
            );
        }
    }

    #[test]
    fn test_setvar_registered() {
        // Ensure setvar action is registered
        assert!(get("setvar").is_ok(), "Action 'setvar' not registered");
    }

    #[test]
    fn test_all_flow_actions_registered() {
        // Ensure all 3 flow actions are registered
        let actions = vec!["chain", "skip", "skipafter"];
        for name in actions {
            assert!(get(name).is_ok(), "Action '{}' not registered", name);
        }
    }

    #[test]
    fn test_flow_action_types() {
        // Verify all flow actions have Flow type
        let actions = vec!["chain", "skip", "skipafter"];
        for name in actions {
            let action = get(name).unwrap();
            assert_eq!(
                action.action_type(),
                ActionType::Flow,
                "Action '{}' should be Flow",
                name
            );
        }
    }

    #[test]
    fn test_all_special_actions_registered() {
        // Ensure all 5 special actions are registered (4 + ctl)
        let actions = vec!["capture", "multimatch", "status", "t", "ctl"];
        for name in actions {
            assert!(get(name).is_ok(), "Action '{}' not registered", name);
        }
    }

    #[test]
    fn test_special_action_types() {
        // Verify special action types
        assert_eq!(
            get("capture").unwrap().action_type(),
            ActionType::Nondisruptive,
            "capture should be Nondisruptive"
        );
        assert_eq!(
            get("multimatch").unwrap().action_type(),
            ActionType::Nondisruptive,
            "multimatch should be Nondisruptive"
        );
        assert_eq!(
            get("status").unwrap().action_type(),
            ActionType::Data,
            "status should be Data"
        );
        assert_eq!(
            get("t").unwrap().action_type(),
            ActionType::Nondisruptive,
            "t should be Nondisruptive"
        );
        assert_eq!(
            get("ctl").unwrap().action_type(),
            ActionType::Nondisruptive,
            "ctl should be Nondisruptive"
        );
    }

    #[test]
    fn test_setvar_action_type() {
        // Verify setvar has Nondisruptive type
        let action = get("setvar").unwrap();
        assert_eq!(
            action.action_type(),
            ActionType::Nondisruptive,
            "Action 'setvar' should be Nondisruptive"
        );
    }

    // ===== Deferred Actions Registration Tests (Step 10) =====

    #[test]
    fn test_deferred_actions_registered() {
        // Verify all 4 deferred actions are registered in the global registry
        assert!(get("exec").is_ok(), "exec action should be registered");
        assert!(
            get("expirevar").is_ok(),
            "expirevar action should be registered"
        );
        assert!(get("setenv").is_ok(), "setenv action should be registered");
        assert!(
            get("initcol").is_ok(),
            "initcol action should be registered"
        );
    }

    #[test]
    fn test_deferred_actions_types() {
        // Verify all deferred actions are Nondisruptive
        assert_eq!(
            get("exec").unwrap().action_type(),
            ActionType::Nondisruptive,
            "exec should be Nondisruptive"
        );
        assert_eq!(
            get("expirevar").unwrap().action_type(),
            ActionType::Nondisruptive,
            "expirevar should be Nondisruptive"
        );
        assert_eq!(
            get("setenv").unwrap().action_type(),
            ActionType::Nondisruptive,
            "setenv should be Nondisruptive"
        );
        assert_eq!(
            get("initcol").unwrap().action_type(),
            ActionType::Nondisruptive,
            "initcol should be Nondisruptive"
        );
    }
}
