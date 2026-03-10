// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Logging actions for controlling rule logging behavior.
//!
//! Logging actions control whether and how rule matches are logged to error logs
//! and audit logs. These actions are non-disruptive and do not affect transaction
//! processing - they only control logging behavior.

use crate::actions::{Action, ActionError, ActionType, Rule, TransactionState};
use crate::operators::Macro;

/// `log` action - Enables logging for the rule.
///
/// Indicates that a successful match of the rule needs to be logged.
/// This action enables both error logging and audit logging.
///
/// # Arguments
///
/// No arguments accepted
///
/// # Examples
///
/// ```text
/// SecAction "phase:1,id:117,pass,initcol:ip=%{REMOTE_ADDR},log"
/// ```
#[derive(Debug)]
pub struct LogAction;

impl Action for LogAction {
    fn init(&mut self, rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if !data.is_empty() {
            return Err(ActionError::UnexpectedArguments);
        }

        rule.log = true;
        rule.audit_log = true;
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // Logging actions don't execute at runtime
    }

    fn action_type(&self) -> ActionType {
        ActionType::Nondisruptive
    }
}

/// `nolog` action - Disables logging for the rule.
///
/// Prevents rule matches from appearing in both error and audit logs.
/// Although `nolog` implies `noauditlog`, you can override the former by
/// using `nolog,auditlog`.
///
/// # Arguments
///
/// No arguments accepted
///
/// # Examples
///
/// ```text
/// SecRule REQUEST_HEADERS:User-Agent "@streq Test" "allow,nolog,id:121"
/// ```
#[derive(Debug)]
pub struct NologAction;

impl Action for NologAction {
    fn init(&mut self, rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if !data.is_empty() {
            return Err(ActionError::UnexpectedArguments);
        }

        rule.log = false;
        rule.audit_log = false;
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // Logging actions don't execute at runtime
    }

    fn action_type(&self) -> ActionType {
        ActionType::Nondisruptive
    }
}

/// `auditlog` action - Enables audit logging for the rule.
///
/// Marks the transaction for logging in the audit log. This action only
/// affects audit logging, not error logging.
///
/// # Arguments
///
/// No arguments accepted
///
/// # Examples
///
/// ```text
/// SecRule REMOTE_ADDR "^192\.168\.1\.100$" "auditlog,phase:1,id:100,allow"
/// ```
#[derive(Debug)]
pub struct AuditlogAction;

impl Action for AuditlogAction {
    fn init(&mut self, rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if !data.is_empty() {
            return Err(ActionError::UnexpectedArguments);
        }

        rule.audit_log = true;
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // Logging actions don't execute at runtime
    }

    fn action_type(&self) -> ActionType {
        ActionType::Nondisruptive
    }
}

/// `noauditlog` action - Disables audit logging for the rule.
///
/// Indicates that a successful match of the rule should not be used as criteria
/// to determine whether the transaction should be logged to the audit log.
///
/// - If `SecAuditEngine` is set to `On`, all transactions will be logged.
/// - If it is set to `RelevantOnly`, you can control logging with this action.
/// - This action affects only the current rule. A match in another rule will
///   still cause audit logging to take place.
/// - To prevent audit logging from taking place regardless of any rule matches,
///   use `ctl:auditEngine=Off`.
///
/// # Arguments
///
/// No arguments accepted
///
/// # Examples
///
/// ```text
/// SecRule REQUEST_HEADERS:User-Agent "@streq Test" "allow,noauditlog,id:120"
/// ```
#[derive(Debug)]
pub struct NoauditlogAction;

impl Action for NoauditlogAction {
    fn init(&mut self, rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if !data.is_empty() {
            return Err(ActionError::UnexpectedArguments);
        }

        rule.audit_log = false;
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // Logging actions don't execute at runtime
    }

    fn action_type(&self) -> ActionType {
        ActionType::Nondisruptive
    }
}

/// `logdata` action - Logs additional data with the alert.
///
/// Logs a data fragment as part of the alert message. The logdata information
/// appears in the error and/or audit log files. Macro expansion is performed,
/// so you may use variable names such as `%{TX.0}` or `%{MATCHED_VAR}`.
/// The information is properly escaped for use with logging of binary data.
///
/// # Arguments
///
/// Data string with macro expansion support (e.g., `%{MATCHED_VAR}`)
///
/// # Examples
///
/// ```text
/// SecRule ARGS:p "@rx <script>" "phase:2,id:118,log,pass,logdata:%{MATCHED_VAR}"
/// ```
#[derive(Debug)]
pub struct LogdataAction;

impl Action for LogdataAction {
    fn init(&mut self, rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if data.is_empty() {
            return Err(ActionError::MissingArguments);
        }

        let log_data = Macro::new(data)?;
        rule.log_data = Some(log_data);
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // logdata macro expansion is performed after all other actions have been
        // evaluated (and potentially all the needed variables have been set)
    }

    fn action_type(&self) -> ActionType {
        ActionType::Nondisruptive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // LogAction Tests
    #[test]
    fn test_log_init() {
        let mut rule = Rule::new();
        let mut action = LogAction;
        assert!(action.init(&mut rule, "").is_ok());
        assert!(rule.log, "log should be enabled");
        assert!(rule.audit_log, "audit should be enabled");
    }

    #[test]
    fn test_log_unexpected_arguments() {
        let mut rule = Rule::new();
        let mut action = LogAction;
        assert_eq!(
            action.init(&mut rule, "unexpected"),
            Err(ActionError::UnexpectedArguments)
        );
    }

    // NologAction Tests
    #[test]
    fn test_nolog_no_arguments() {
        let mut rule = Rule::new();
        let mut action = NologAction;
        assert!(action.init(&mut rule, "").is_ok());
        assert!(!rule.log, "log should be disabled");
        assert!(!rule.audit_log, "audit should be disabled");
    }

    #[test]
    fn test_nolog_unexpected_arguments() {
        let mut rule = Rule::new();
        let mut action = NologAction;
        assert_eq!(
            action.init(&mut rule, "abc"),
            Err(ActionError::UnexpectedArguments)
        );
    }

    // AuditlogAction Tests
    #[test]
    fn test_auditlog_no_arguments() {
        let mut rule = Rule::new();
        let mut action = AuditlogAction;
        assert!(action.init(&mut rule, "").is_ok());
        assert!(rule.audit_log, "audit should be enabled");
    }

    #[test]
    fn test_auditlog_unexpected_arguments() {
        let mut rule = Rule::new();
        let mut action = AuditlogAction;
        assert_eq!(
            action.init(&mut rule, "unexpected"),
            Err(ActionError::UnexpectedArguments)
        );
    }

    // NoauditlogAction Tests
    #[test]
    fn test_noauditlog_no_arguments() {
        let mut rule = Rule::new();
        let mut action = NoauditlogAction;
        assert!(action.init(&mut rule, "").is_ok());
        assert!(!rule.audit_log, "audit should be disabled");
    }

    #[test]
    fn test_noauditlog_unexpected_arguments() {
        let mut rule = Rule::new();
        let mut action = NoauditlogAction;
        assert_eq!(
            action.init(&mut rule, "abc"),
            Err(ActionError::UnexpectedArguments)
        );
    }

    // LogdataAction Tests
    #[test]
    fn test_logdata_empty() {
        let mut rule = Rule::new();
        let mut action = LogdataAction;
        assert_eq!(
            action.init(&mut rule, ""),
            Err(ActionError::MissingArguments)
        );
    }

    #[test]
    fn test_logdata_valid() {
        let mut rule = Rule::new();
        let mut action = LogdataAction;
        assert!(action.init(&mut rule, "%{tx.count}").is_ok());
        assert!(rule.log_data.is_some());
    }

    #[test]
    fn test_logdata_invalid_macro() {
        let mut rule = Rule::new();
        let mut action = LogdataAction;
        // Invalid macro syntax (unclosed brace)
        assert!(matches!(
            action.init(&mut rule, "%{tx.count"),
            Err(ActionError::MacroError(_))
        ));
    }

    #[test]
    fn test_action_types() {
        assert_eq!(LogAction.action_type(), ActionType::Nondisruptive);
        assert_eq!(NologAction.action_type(), ActionType::Nondisruptive);
        assert_eq!(AuditlogAction.action_type(), ActionType::Nondisruptive);
        assert_eq!(NoauditlogAction.action_type(), ActionType::Nondisruptive);
        assert_eq!(LogdataAction.action_type(), ActionType::Nondisruptive);
    }
}
