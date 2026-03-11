// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! CTL (control) action for runtime configuration changes.
//!
//! The CTL action allows changing WAF configuration on a per-transaction basis.
//! Changes made with CTL only affect the current transaction and don't modify
//! the global configuration or other parallel transactions.
//!
//! **Note:** This is currently a parsing-only stub. Full transaction manipulation
//! will be implemented in Phase 8 when the transaction system is complete.

use crate::RuleVariable;
use crate::actions::{Action, ActionError, ActionType, Rule, TransactionState};
use std::str::FromStr;

/// CTL command types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Will be used in Phase 8
enum CtlCommand {
    /// Remove specific targets from a rule by ID
    RuleRemoveTargetById,
    /// Remove specific targets from rules by tag
    RuleRemoveTargetByTag,
    /// Remove specific targets from rules by message
    RuleRemoveTargetByMsg,
    /// Set audit engine status (On/Off/RelevantOnly)
    AuditEngine,
    /// Set audit log parts (which sections to log)
    AuditLogParts,
    /// Force REQUEST_BODY variable creation
    ForceRequestBodyVariable,
    /// Enable/disable request body access
    RequestBodyAccess,
    /// Set request body size limit
    RequestBodyLimit,
    /// Set rule engine status (On/Off/DetectionOnly)
    RuleEngine,
    /// Remove rule(s) by ID (supports ranges)
    RuleRemoveById,
    /// Remove rules by message
    RuleRemoveByMsg,
    /// Remove rules by tag
    RuleRemoveByTag,
    /// Hash engine (not supported)
    HashEngine,
    /// Hash enforcement (not supported)
    HashEnforcement,
    /// Set request body processor (JSON/XML/URLENCODED/MULTIPART)
    RequestBodyProcessor,
    /// Force RESPONSE_BODY variable creation
    ForceResponseBodyVariable,
    /// Set response body processor
    ResponseBodyProcessor,
    /// Enable/disable response body access
    ResponseBodyAccess,
    /// Set response body size limit
    ResponseBodyLimit,
    /// Set debug log level
    DebugLogLevel,
}

/// `ctl` action - Change WAF configuration at runtime.
///
/// Changes configuration on a per-transaction basis. All changes affect only
/// the current transaction, leaving the default configuration and other
/// transactions unchanged.
///
/// # Supported Commands
///
/// ## Engine Control
/// - `ruleEngine=On|Off|DetectionOnly` - Set rule engine status
/// - `auditEngine=On|Off|RelevantOnly` - Set audit engine status
///
/// ## Request Body
/// - `requestBodyAccess=On|Off` - Enable/disable request body inspection
/// - `requestBodyLimit=N` - Set request body size limit (bytes)
/// - `requestBodyProcessor=JSON|XML|URLENCODED|MULTIPART` - Set body parser
/// - `forceRequestBodyVariable=On|Off` - Force REQUEST_BODY variable
///
/// ## Response Body
/// - `responseBodyAccess=On|Off` - Enable/disable response body inspection
/// - `responseBodyLimit=N` - Set response body size limit (bytes)
/// - `responseBodyProcessor=JSON|XML` - Set body parser
/// - `forceResponseBodyVariable=On|Off` - Force RESPONSE_BODY variable
///
/// ## Rule Removal
/// - `ruleRemoveById=ID` or `ID1-ID2` - Remove rule(s) by ID or range
/// - `ruleRemoveByTag=TAG` - Remove rules by tag
/// - `ruleRemoveByMsg=MSG` - Remove rules by message
/// - `ruleRemoveTargetById=ID;COLLECTION:key` - Remove variable from rule
/// - `ruleRemoveTargetByTag=TAG;COLLECTION:key` - Remove variable from tagged rules
/// - `ruleRemoveTargetByMsg=MSG;COLLECTION:key` - Remove variable from rules by message
///
/// ## Logging
/// - `auditLogParts=ABCDEFGHIJK` - Set which audit log parts to include
/// - `debugLogLevel=0-9` - Set debug log verbosity
///
/// # Arguments
///
/// Command in format: `command=value` or `command=value;collection:key`
///
/// # Examples
///
/// ```text
/// # Parse XML request bodies
/// SecRule REQUEST_CONTENT_TYPE "^text/xml" \
///   "nolog,pass,id:106,phase:1,ctl:requestBodyProcessor=XML"
///
/// # Whitelist user parameter for rule 981260 on /index.php
/// SecRule REQUEST_URI "@beginsWith /index.php" \
///   "phase:1,t:none,pass,nolog,ctl:ruleRemoveTargetById=981260;ARGS:user"
///
/// # Disable rule engine for trusted IPs
/// SecRule REMOTE_ADDR "^10\.0\.0\." "phase:1,id:107,ctl:ruleEngine=Off"
/// ```
#[derive(Debug)]
pub struct CtlAction {
    command: CtlCommand,
    value: String,
    collection: Option<RuleVariable>,
    key: Option<String>,
}

impl CtlAction {
    pub fn new() -> Self {
        Self {
            command: CtlCommand::RuleEngine,
            value: String::new(),
            collection: None,
            key: None,
        }
    }

    /// Parse on/off toggle values.
    fn parse_on_off(value: &str) -> Result<bool, ActionError> {
        match value.to_lowercase().as_str() {
            "on" => Ok(true),
            "off" => Ok(false),
            _ => Err(ActionError::InvalidArguments(format!(
                "expected 'on' or 'off', got '{}'",
                value
            ))),
        }
    }
}

impl Default for CtlAction {
    fn default() -> Self {
        Self::new()
    }
}

impl Action for CtlAction {
    fn init(&mut self, _rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        // Parse syntax: command=value or command=value;collection:key
        let (command_part, value_part) = data
            .split_once('=')
            .ok_or_else(|| ActionError::InvalidArguments("expected 'command=value'".to_string()))?;

        // Split value and optional collection:key
        let (value, collection_key) = if let Some((val, col)) = value_part.split_once(';') {
            (val, Some(col))
        } else {
            (value_part, None)
        };

        // Parse collection and key if present
        if let Some(col_key) = collection_key {
            let (col_name, key) = if let Some((col, k)) = col_key.split_once(':') {
                let key = if k.is_empty() {
                    None
                } else {
                    Some(k.to_lowercase())
                };
                (col.trim(), key)
            } else {
                (col_key.trim(), None)
            };

            // Parse collection variable
            if !col_name.is_empty() {
                let collection = col_name.parse::<RuleVariable>().map_err(|_| {
                    ActionError::InvalidArguments(format!("unknown collection '{}'", col_name))
                })?;
                self.collection = Some(collection);
            }

            self.key = key;
        }

        // Parse command
        self.command = match command_part {
            "auditEngine" => CtlCommand::AuditEngine,
            "auditLogParts" => CtlCommand::AuditLogParts,
            "requestBodyAccess" => CtlCommand::RequestBodyAccess,
            "requestBodyLimit" => CtlCommand::RequestBodyLimit,
            "requestBodyProcessor" => CtlCommand::RequestBodyProcessor,
            "forceRequestBodyVariable" => CtlCommand::ForceRequestBodyVariable,
            "responseBodyProcessor" => CtlCommand::ResponseBodyProcessor,
            "responseBodyAccess" => CtlCommand::ResponseBodyAccess,
            "responseBodyLimit" => CtlCommand::ResponseBodyLimit,
            "forceResponseBodyVariable" => CtlCommand::ForceResponseBodyVariable,
            "ruleEngine" => CtlCommand::RuleEngine,
            "ruleRemoveById" => CtlCommand::RuleRemoveById,
            "ruleRemoveByMsg" => CtlCommand::RuleRemoveByMsg,
            "ruleRemoveByTag" => CtlCommand::RuleRemoveByTag,
            "ruleRemoveTargetById" => CtlCommand::RuleRemoveTargetById,
            "ruleRemoveTargetByMsg" => CtlCommand::RuleRemoveTargetByMsg,
            "ruleRemoveTargetByTag" => CtlCommand::RuleRemoveTargetByTag,
            "hashEngine" => CtlCommand::HashEngine,
            "hashEnforcement" => CtlCommand::HashEnforcement,
            "debugLogLevel" => CtlCommand::DebugLogLevel,
            _ => {
                return Err(ActionError::InvalidArguments(format!(
                    "unknown ctl command '{}'",
                    command_part
                )));
            }
        };

        // Basic validation for toggle commands
        if matches!(
            self.command,
            CtlCommand::RequestBodyAccess
                | CtlCommand::ResponseBodyAccess
                | CtlCommand::ForceRequestBodyVariable
                | CtlCommand::ForceResponseBodyVariable
        ) {
            Self::parse_on_off(value)?;
        }

        // Basic validation for limit commands
        if matches!(
            self.command,
            CtlCommand::RequestBodyLimit | CtlCommand::ResponseBodyLimit
        ) {
            value.parse::<i64>().map_err(|_| {
                ActionError::InvalidArguments(format!("expected numeric limit, got '{}'", value))
            })?;
        }

        // Basic validation for debug log level
        if matches!(self.command, CtlCommand::DebugLogLevel) {
            let level = value.parse::<i32>().map_err(|_| {
                ActionError::InvalidArguments(format!(
                    "expected numeric log level, got '{}'",
                    value
                ))
            })?;
            if !(0..=9).contains(&level) {
                return Err(ActionError::InvalidArguments(format!(
                    "log level must be 0-9, got {}",
                    level
                )));
            }
        }

        self.value = value.to_string();
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, tx: &mut dyn TransactionState) {
        use crate::RuleEngineStatus;
        use crate::types::RulePhase;

        match self.command {
            CtlCommand::RuleEngine => {
                // Parse and set rule engine status
                if let Ok(status) = RuleEngineStatus::from_str(&self.value) {
                    tx.ctl_set_rule_engine(status);
                }
                // Note: Errors are already caught during init(), silently ignore here
            }

            CtlCommand::RequestBodyAccess => {
                // Only allow changing before request body phase
                if let Some(phase) = tx.ctl_last_phase()
                    && phase >= RulePhase::RequestBody
                {
                    // Too late to change, silently ignore
                    return;
                }

                if let Ok(enabled) = Self::parse_on_off(&self.value) {
                    tx.ctl_set_request_body_access(enabled);
                }
            }

            CtlCommand::RequestBodyLimit => {
                // Only allow changing before request body phase
                if let Some(phase) = tx.ctl_last_phase()
                    && phase >= RulePhase::RequestBody
                {
                    return;
                }

                if let Ok(limit) = self.value.parse::<i64>() {
                    tx.ctl_set_request_body_limit(limit);
                }
            }

            CtlCommand::ForceRequestBodyVariable => {
                if let Ok(enabled) = Self::parse_on_off(&self.value) {
                    tx.ctl_set_force_request_body_variable(enabled);
                }
            }

            CtlCommand::ResponseBodyAccess => {
                // Only allow changing before response body phase
                if let Some(phase) = tx.ctl_last_phase()
                    && phase >= RulePhase::ResponseBody
                {
                    return;
                }

                if let Ok(enabled) = Self::parse_on_off(&self.value) {
                    tx.ctl_set_response_body_access(enabled);
                }
            }

            CtlCommand::ResponseBodyLimit => {
                // Only allow changing before response body phase
                if let Some(phase) = tx.ctl_last_phase()
                    && phase >= RulePhase::ResponseBody
                {
                    return;
                }

                if let Ok(limit) = self.value.parse::<i64>() {
                    tx.ctl_set_response_body_limit(limit);
                }
            }

            CtlCommand::ForceResponseBodyVariable => {
                if let Ok(enabled) = Self::parse_on_off(&self.value) {
                    tx.ctl_set_force_response_body_variable(enabled);
                }
            }

            // These commands require WAF-level integration and will be implemented
            // in Phase 10 when we have full WAF infrastructure
            CtlCommand::RuleRemoveById
            | CtlCommand::RuleRemoveByTag
            | CtlCommand::RuleRemoveByMsg
            | CtlCommand::RuleRemoveTargetById
            | CtlCommand::RuleRemoveTargetByTag
            | CtlCommand::RuleRemoveTargetByMsg => {
                // Deferred to Phase 10 - requires WAF.Rules access
            }

            // Body processor and audit settings - deferred to Phase 10
            CtlCommand::RequestBodyProcessor
            | CtlCommand::ResponseBodyProcessor
            | CtlCommand::AuditEngine
            | CtlCommand::AuditLogParts
            | CtlCommand::DebugLogLevel => {
                // Deferred to Phase 10 - requires additional infrastructure
            }

            // Not supported
            CtlCommand::HashEngine | CtlCommand::HashEnforcement => {
                // Hash engine is not supported in Coraza
            }
        }
    }

    fn action_type(&self) -> ActionType {
        ActionType::Nondisruptive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test parsing of all CTL commands
    #[test]
    fn test_ctl_parse_audit_engine() {
        let mut action = CtlAction::new();
        assert!(action.init(&mut Rule::new(), "auditEngine=On").is_ok());
        assert_eq!(action.command, CtlCommand::AuditEngine);
        assert_eq!(action.value, "On");
    }

    #[test]
    fn test_ctl_parse_audit_log_parts() {
        let mut action = CtlAction::new();
        assert!(action.init(&mut Rule::new(), "auditLogParts=ABZ").is_ok());
        assert_eq!(action.command, CtlCommand::AuditLogParts);
        assert_eq!(action.value, "ABZ");
    }

    #[test]
    fn test_ctl_parse_request_body_access() {
        let mut action = CtlAction::new();
        assert!(
            action
                .init(&mut Rule::new(), "requestBodyAccess=On")
                .is_ok()
        );
        assert_eq!(action.command, CtlCommand::RequestBodyAccess);
        assert_eq!(action.value, "On");
    }

    #[test]
    fn test_ctl_parse_request_body_limit() {
        let mut action = CtlAction::new();
        assert!(
            action
                .init(&mut Rule::new(), "requestBodyLimit=12345")
                .is_ok()
        );
        assert_eq!(action.command, CtlCommand::RequestBodyLimit);
        assert_eq!(action.value, "12345");
    }

    #[test]
    fn test_ctl_parse_request_body_processor() {
        let mut action = CtlAction::new();
        assert!(
            action
                .init(&mut Rule::new(), "requestBodyProcessor=XML")
                .is_ok()
        );
        assert_eq!(action.command, CtlCommand::RequestBodyProcessor);
        assert_eq!(action.value, "XML");
    }

    #[test]
    fn test_ctl_parse_rule_engine() {
        let mut action = CtlAction::new();
        assert!(action.init(&mut Rule::new(), "ruleEngine=Off").is_ok());
        assert_eq!(action.command, CtlCommand::RuleEngine);
        assert_eq!(action.value, "Off");
    }

    #[test]
    fn test_ctl_parse_rule_remove_by_id() {
        let mut action = CtlAction::new();
        assert!(action.init(&mut Rule::new(), "ruleRemoveById=123").is_ok());
        assert_eq!(action.command, CtlCommand::RuleRemoveById);
        assert_eq!(action.value, "123");
    }

    #[test]
    fn test_ctl_parse_rule_remove_by_id_range() {
        let mut action = CtlAction::new();
        assert!(action.init(&mut Rule::new(), "ruleRemoveById=1-9").is_ok());
        assert_eq!(action.value, "1-9");
    }

    #[test]
    fn test_ctl_parse_rule_remove_by_tag() {
        let mut action = CtlAction::new();
        assert!(
            action
                .init(&mut Rule::new(), "ruleRemoveByTag=MY_TAG")
                .is_ok()
        );
        assert_eq!(action.command, CtlCommand::RuleRemoveByTag);
        assert_eq!(action.value, "MY_TAG");
    }

    #[test]
    fn test_ctl_parse_rule_remove_by_msg() {
        let mut action = CtlAction::new();
        assert!(
            action
                .init(&mut Rule::new(), "ruleRemoveByMsg=MY_MSG")
                .is_ok()
        );
        assert_eq!(action.command, CtlCommand::RuleRemoveByMsg);
        assert_eq!(action.value, "MY_MSG");
    }

    #[test]
    fn test_ctl_parse_rule_remove_target_with_collection() {
        let mut action = CtlAction::new();
        assert!(
            action
                .init(&mut Rule::new(), "ruleRemoveTargetById=123;ARGS:user")
                .is_ok()
        );
        assert_eq!(action.command, CtlCommand::RuleRemoveTargetById);
        assert_eq!(action.value, "123");
        assert_eq!(action.collection, Some(RuleVariable::Args));
        assert_eq!(action.key, Some("user".to_string()));
    }

    #[test]
    fn test_ctl_parse_rule_remove_target_no_key() {
        let mut action = CtlAction::new();
        assert!(
            action
                .init(&mut Rule::new(), "ruleRemoveTargetById=2;REQUEST_FILENAME:")
                .is_ok()
        );
        assert_eq!(action.collection, Some(RuleVariable::RequestFilename));
        assert_eq!(action.key, None);
    }

    #[test]
    fn test_ctl_parse_response_body_access() {
        let mut action = CtlAction::new();
        assert!(
            action
                .init(&mut Rule::new(), "responseBodyAccess=On")
                .is_ok()
        );
        assert_eq!(action.command, CtlCommand::ResponseBodyAccess);
        assert_eq!(action.value, "On");
    }

    #[test]
    fn test_ctl_parse_debug_log_level() {
        let mut action = CtlAction::new();
        assert!(action.init(&mut Rule::new(), "debugLogLevel=3").is_ok());
        assert_eq!(action.command, CtlCommand::DebugLogLevel);
        assert_eq!(action.value, "3");
    }

    // Test error cases
    #[test]
    fn test_ctl_invalid_syntax_no_equals() {
        let mut action = CtlAction::new();
        assert!(matches!(
            action.init(&mut Rule::new(), "invalid"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_ctl_unknown_command() {
        let mut action = CtlAction::new();
        assert!(matches!(
            action.init(&mut Rule::new(), "unknownCommand=value"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_ctl_invalid_on_off() {
        let mut action = CtlAction::new();
        assert!(matches!(
            action.init(&mut Rule::new(), "requestBodyAccess=Maybe"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_ctl_invalid_limit() {
        let mut action = CtlAction::new();
        assert!(matches!(
            action.init(&mut Rule::new(), "requestBodyLimit=abc"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_ctl_invalid_debug_level() {
        let mut action = CtlAction::new();
        assert!(matches!(
            action.init(&mut Rule::new(), "debugLogLevel=10"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_ctl_invalid_collection() {
        let mut action = CtlAction::new();
        assert!(matches!(
            action.init(&mut Rule::new(), "ruleRemoveTargetById=123;INVALID:key"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_ctl_action_type() {
        assert_eq!(CtlAction::new().action_type(), ActionType::Nondisruptive);
    }

    #[test]
    fn test_ctl_parse_on_off() {
        assert_eq!(CtlAction::parse_on_off("on"), Ok(true));
        assert_eq!(CtlAction::parse_on_off("ON"), Ok(true));
        assert_eq!(CtlAction::parse_on_off("On"), Ok(true));
        assert_eq!(CtlAction::parse_on_off("off"), Ok(false));
        assert_eq!(CtlAction::parse_on_off("OFF"), Ok(false));
        assert_eq!(CtlAction::parse_on_off("Off"), Ok(false));
        assert!(CtlAction::parse_on_off("maybe").is_err());
    }

    // CTL Execution Tests

    #[test]
    fn test_ctl_execute_rule_engine() {
        use crate::transaction::Transaction;

        let mut action = CtlAction::new();
        let mut rule = Rule::default();
        action.init(&mut rule, "ruleEngine=DetectionOnly").unwrap();

        let mut tx = Transaction::new("test-1");
        assert_eq!(tx.rule_engine(), crate::RuleEngineStatus::On); // default

        action.evaluate(&rule, &mut tx);
        assert_eq!(tx.rule_engine(), crate::RuleEngineStatus::DetectionOnly);
    }

    #[test]
    fn test_ctl_execute_request_body_access() {
        use crate::transaction::Transaction;

        let mut action = CtlAction::new();
        let mut rule = Rule::default();
        action.init(&mut rule, "requestBodyAccess=off").unwrap();

        let mut tx = Transaction::new("test-2");
        assert!(tx.request_body_access()); // default is true

        action.evaluate(&rule, &mut tx);
        assert!(!tx.request_body_access());
    }

    #[test]
    fn test_ctl_execute_request_body_limit() {
        use crate::transaction::Transaction;

        let mut action = CtlAction::new();
        let mut rule = Rule::default();
        action.init(&mut rule, "requestBodyLimit=256000").unwrap();

        let mut tx = Transaction::new("test-3");
        assert_eq!(tx.request_body_limit(), 131072); // default is 128KB

        action.evaluate(&rule, &mut tx);
        assert_eq!(tx.request_body_limit(), 256000);
    }

    #[test]
    fn test_ctl_execute_force_request_body_variable() {
        use crate::transaction::Transaction;

        let mut action = CtlAction::new();
        let mut rule = Rule::default();
        action
            .init(&mut rule, "forceRequestBodyVariable=on")
            .unwrap();

        let mut tx = Transaction::new("test-4");
        assert!(!tx.force_request_body_variable()); // default is false

        action.evaluate(&rule, &mut tx);
        assert!(tx.force_request_body_variable());
    }

    #[test]
    fn test_ctl_execute_response_body_access() {
        use crate::transaction::Transaction;

        let mut action = CtlAction::new();
        let mut rule = Rule::default();
        action.init(&mut rule, "responseBodyAccess=on").unwrap();

        let mut tx = Transaction::new("test-5");
        assert!(!tx.response_body_access()); // default is false

        action.evaluate(&rule, &mut tx);
        assert!(tx.response_body_access());
    }

    #[test]
    fn test_ctl_execute_response_body_limit() {
        use crate::transaction::Transaction;

        let mut action = CtlAction::new();
        let mut rule = Rule::default();
        action.init(&mut rule, "responseBodyLimit=1048576").unwrap();

        let mut tx = Transaction::new("test-6");
        assert_eq!(tx.response_body_limit(), 524288); // default is 512KB

        action.evaluate(&rule, &mut tx);
        assert_eq!(tx.response_body_limit(), 1048576);
    }

    #[test]
    fn test_ctl_execute_force_response_body_variable() {
        use crate::transaction::Transaction;

        let mut action = CtlAction::new();
        let mut rule = Rule::default();
        action
            .init(&mut rule, "forceResponseBodyVariable=on")
            .unwrap();

        let mut tx = Transaction::new("test-7");
        assert!(!tx.force_response_body_variable()); // default is false

        action.evaluate(&rule, &mut tx);
        assert!(tx.force_response_body_variable());
    }

    #[test]
    fn test_ctl_phase_restriction_request_body() {
        use crate::transaction::Transaction;

        let mut action = CtlAction::new();
        let mut rule = Rule::default();
        action.init(&mut rule, "requestBodyAccess=off").unwrap();

        let mut tx = Transaction::new("test-8");
        // Simulate being in request body phase
        tx.process_request_body(b"test").unwrap();

        assert!(tx.request_body_access()); // default is true

        // Try to change it - should be silently ignored
        action.evaluate(&rule, &mut tx);
        assert!(tx.request_body_access()); // unchanged
    }

    #[test]
    fn test_ctl_phase_restriction_response_body() {
        use crate::transaction::Transaction;

        let mut action = CtlAction::new();
        let mut rule = Rule::default();
        action.init(&mut rule, "responseBodyLimit=1000").unwrap();

        let mut tx = Transaction::new("test-9");
        // Simulate being in response body phase
        tx.process_response_body(b"test");

        assert_eq!(tx.response_body_limit(), 524288); // default

        // Try to change it - should be silently ignored
        action.evaluate(&rule, &mut tx);
        assert_eq!(tx.response_body_limit(), 524288); // unchanged
    }
}
