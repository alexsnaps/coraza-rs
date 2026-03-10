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

mod disruptive;
mod flow;
mod logging;
mod metadata;
mod variables;

use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;

use crate::RuleSeverity;
use crate::operators::Macro;

pub use disruptive::{
    AllowAction, AllowType, BlockAction, DenyAction, DropAction, PassAction, RedirectAction,
};
pub use flow::{ChainAction, SkipAction, SkipAfterAction};
pub use logging::{AuditlogAction, LogAction, LogdataAction, NoauditlogAction, NologAction};
pub use metadata::{
    IdAction, MaturityAction, MsgAction, RevAction, SeverityAction, TagAction, VerAction,
};
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

/// Rule configuration and metadata.
///
/// Stores all metadata and configuration for a single rule. Actions modify
/// this struct during initialization to set rule properties like ID, message,
/// severity, and logging flags.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Rule ID (mandatory, set by id action)
    pub id: i32,
    /// Parent rule ID (for chained rules)
    pub parent_id: i32,
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
    /// Whether this rule chains to the next
    pub has_chain: bool,
}

impl Rule {
    /// Create a new rule with default values.
    pub fn new() -> Self {
        Self {
            id: 0,
            parent_id: 0,
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
        }
    }
}

impl Default for Rule {
    fn default() -> Self {
        Self::new()
    }
}

/// Transaction state interface for action evaluation.
///
/// Re-exported from operators module to avoid duplication.
pub use crate::operators::TransactionState;

/// Rule action trait.
///
/// Actions define what happens when a rule matches. Each action implements this trait
/// with two key methods: `init()` for parsing parameters during rule compilation, and
/// `evaluate()` for executing the action during transaction processing.
///
/// # Examples
///
/// ```
/// use coraza::actions::{Action, ActionType, ActionError, Rule, TransactionState};
///
/// // Simple action that requires no parameters
/// struct DenyAction;
///
/// impl Action for DenyAction {
///     fn init(&mut self, _rule: &mut Rule, data: &str) -> Result<(), ActionError> {
///         if !data.is_empty() {
///             return Err(ActionError::UnexpectedArguments);
///         }
///         Ok(())
///     }
///
///     fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
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
    fn init(&mut self, rule: &mut Rule, data: &str) -> Result<(), ActionError>;

    /// Evaluate the action during transaction processing.
    ///
    /// This method is called when a rule matches and the action should execute.
    /// Actions can modify transaction state, log messages, interrupt processing, etc.
    ///
    /// # Arguments
    ///
    /// * `rule` - Immutable reference to rule
    /// * `tx` - Mutable reference to transaction state
    fn evaluate(&self, rule: &Rule, tx: &mut dyn TransactionState);

    /// Return the action type category.
    fn action_type(&self) -> ActionType;
}

/// Action factory function type.
///
/// The registry stores factory functions that create new action instances.
type ActionFactory = fn() -> Box<dyn Action>;

/// Global action registry.
static ACTION_REGISTRY: OnceLock<HashMap<String, ActionFactory>> = OnceLock::new();

/// Helper functions to create action instances (for registry)
fn create_id() -> Box<dyn Action> {
    Box::new(IdAction)
}
fn create_msg() -> Box<dyn Action> {
    Box::new(MsgAction)
}
fn create_tag() -> Box<dyn Action> {
    Box::new(TagAction)
}
fn create_severity() -> Box<dyn Action> {
    Box::new(SeverityAction)
}
fn create_rev() -> Box<dyn Action> {
    Box::new(RevAction)
}
fn create_ver() -> Box<dyn Action> {
    Box::new(VerAction)
}
fn create_maturity() -> Box<dyn Action> {
    Box::new(MaturityAction)
}
fn create_log() -> Box<dyn Action> {
    Box::new(LogAction)
}
fn create_nolog() -> Box<dyn Action> {
    Box::new(NologAction)
}
fn create_auditlog() -> Box<dyn Action> {
    Box::new(AuditlogAction)
}
fn create_noauditlog() -> Box<dyn Action> {
    Box::new(NoauditlogAction)
}
fn create_logdata() -> Box<dyn Action> {
    Box::new(LogdataAction)
}
fn create_deny() -> Box<dyn Action> {
    Box::new(DenyAction)
}
fn create_drop() -> Box<dyn Action> {
    Box::new(DropAction)
}
fn create_allow() -> Box<dyn Action> {
    Box::new(AllowAction::new())
}
fn create_block() -> Box<dyn Action> {
    Box::new(BlockAction)
}
fn create_redirect() -> Box<dyn Action> {
    Box::new(RedirectAction::new())
}
fn create_pass() -> Box<dyn Action> {
    Box::new(PassAction)
}
fn create_setvar() -> Box<dyn Action> {
    Box::new(SetvarAction::new())
}
fn create_chain() -> Box<dyn Action> {
    Box::new(ChainAction)
}
fn create_skip() -> Box<dyn Action> {
    Box::new(SkipAction::new())
}
fn create_skipafter() -> Box<dyn Action> {
    Box::new(SkipAfterAction::new())
}

/// Initialize the action registry with built-in actions.
fn init_registry() -> HashMap<String, ActionFactory> {
    let mut registry = HashMap::new();

    // Metadata actions
    registry.insert("id".to_string(), create_id as ActionFactory);
    registry.insert("msg".to_string(), create_msg as ActionFactory);
    registry.insert("tag".to_string(), create_tag as ActionFactory);
    registry.insert("severity".to_string(), create_severity as ActionFactory);
    registry.insert("rev".to_string(), create_rev as ActionFactory);
    registry.insert("ver".to_string(), create_ver as ActionFactory);
    registry.insert("maturity".to_string(), create_maturity as ActionFactory);

    // Logging actions
    registry.insert("log".to_string(), create_log as ActionFactory);
    registry.insert("nolog".to_string(), create_nolog as ActionFactory);
    registry.insert("auditlog".to_string(), create_auditlog as ActionFactory);
    registry.insert("noauditlog".to_string(), create_noauditlog as ActionFactory);
    registry.insert("logdata".to_string(), create_logdata as ActionFactory);

    // Disruptive actions
    registry.insert("deny".to_string(), create_deny as ActionFactory);
    registry.insert("drop".to_string(), create_drop as ActionFactory);
    registry.insert("allow".to_string(), create_allow as ActionFactory);
    registry.insert("block".to_string(), create_block as ActionFactory);
    registry.insert("redirect".to_string(), create_redirect as ActionFactory);
    registry.insert("pass".to_string(), create_pass as ActionFactory);

    // Variable manipulation actions
    registry.insert("setvar".to_string(), create_setvar as ActionFactory);

    // Flow control actions
    registry.insert("chain".to_string(), create_chain as ActionFactory);
    registry.insert("skip".to_string(), create_skip as ActionFactory);
    registry.insert("skipafter".to_string(), create_skipafter as ActionFactory);

    registry
}

/// Register a new action in the global registry.
///
/// This function can be used to register both built-in and plugin actions.
/// If an action with the same name already exists, it will be overwritten.
///
/// # Arguments
///
/// * `name` - Action name (case-insensitive)
/// * `factory` - Factory function that creates new action instances
///
/// # Examples
///
/// ```no_run
/// use coraza::actions::{register, Action, ActionType, ActionError, RuleMetadata, TransactionState};
///
/// struct CustomAction;
///
/// impl Action for CustomAction {
///     fn init(&mut self, _rule: &mut dyn RuleMetadata, _data: &str) -> Result<(), ActionError> {
///         Ok(())
///     }
///
///     fn evaluate(&self, _rule: &dyn RuleMetadata, _tx: &mut dyn TransactionState) {
///         // Custom action logic
///     }
///
///     fn action_type(&self) -> ActionType {
///         ActionType::Nondisruptive
///     }
/// }
///
/// // Register the custom action
/// register("mycustom", || Box::new(CustomAction));
/// ```
pub fn register(_name: &str, _factory: ActionFactory) {
    // Note: Runtime registration is not currently supported with OnceLock.
    // The registry is initialized once with built-in actions.
    // For plugin actions, consider using a different registration mechanism
    // or compile-time registration via feature flags.
    todo!(
        "Runtime action registration not yet implemented - registry is read-only after initialization"
    )
}

/// Get an action by name from the registry.
///
/// Returns a new instance of the requested action, or an error if the action
/// is not registered.
///
/// # Arguments
///
/// * `name` - Action name (case-insensitive)
///
/// # Returns
///
/// * `Ok(Box<dyn Action>)` - New action instance
/// * `Err(ActionError::UnknownAction)` - Action not found in registry
///
/// # Examples
///
/// ```no_run
/// use coraza::actions::get;
///
/// // Get a built-in action (when implemented)
/// let action = get("deny").unwrap();
/// ```
pub fn get(name: &str) -> Result<Box<dyn Action>, ActionError> {
    let registry = ACTION_REGISTRY.get_or_init(init_registry);
    let name_lower = name.to_lowercase();

    registry
        .get(&name_lower)
        .map(|factory| factory())
        .ok_or_else(|| ActionError::UnknownAction(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock action for testing
    struct MockAction {
        initialized: bool,
    }

    impl Action for MockAction {
        fn init(&mut self, _rule: &mut Rule, data: &str) -> Result<(), ActionError> {
            if !data.is_empty() {
                return Err(ActionError::UnexpectedArguments);
            }
            self.initialized = true;
            Ok(())
        }

        fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
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
        let mut rule = Rule::new();

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
    fn test_setvar_action_type() {
        // Verify setvar has Nondisruptive type
        let action = get("setvar").unwrap();
        assert_eq!(
            action.action_type(),
            ActionType::Nondisruptive,
            "Action 'setvar' should be Nondisruptive"
        );
    }
}
