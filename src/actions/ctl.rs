// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! CTL (control) action for runtime configuration changes.
//!
//! The CTL action allows changing WAF configuration on a per-transaction basis.
//! Changes made with CTL only affect the current transaction and don't modify
//! the global configuration or other parallel transactions.
//!
use crate::actions::{ActionError, RuleMetadata};
use crate::body_processors::BodyProcessorKind;
use crate::transaction::Transaction;
use crate::types::{AuditEngineStatus, ParseValueError, RuleEngineStatus, RulePhase, RuleVariable};
use std::ops::RangeInclusive;
use std::str::FromStr;

/// A `ctl` command with its value, parsed when the rule is compiled.
#[derive(Debug, Clone, PartialEq)]
enum CtlCommand {
    RuleEngine(RuleEngineStatus),
    RequestBodyAccess(bool),
    RequestBodyLimit(i64),
    ForceRequestBodyVariable(bool),
    ResponseBodyAccess(bool),
    ResponseBodyLimit(i64),
    ForceResponseBodyVariable(bool),
    RequestBodyProcessor(BodyProcessorKind),
    ResponseBodyProcessor(BodyProcessorKind),
    /// Inclusive range of rule IDs; a single ID is a one-element range
    RuleRemoveById(RangeInclusive<i32>),
    RuleRemoveByTag(String),
    RuleRemoveByMsg(String),
    RuleRemoveTargetById(i32, RuleTarget),
    RuleRemoveTargetByTag(String, RuleTarget),
    RuleRemoveTargetByMsg(String, RuleTarget),
    /// Accepted (and validated where possible) but not acted on yet: `auditEngine`,
    /// `auditLogParts`, `debugLogLevel`, `hashEngine`, `hashEnforcement`
    NotImplemented,
}

/// A variable excluded from rules by the `ruleRemoveTarget*` commands.
#[derive(Debug, Clone, PartialEq)]
struct RuleTarget {
    variable: RuleVariable,
    /// Lowercase key; empty excludes the whole collection
    key: String,
}

impl CtlCommand {
    /// Parses `command=value`, or `command=value;COLLECTION[:key]` for `ruleRemoveTarget*`.
    fn parse(data: &str) -> Result<Self, ActionError> {
        let (name, value) = data
            .split_once('=')
            .ok_or_else(|| invalid("expected 'command=value'".to_string()))?;

        let command = match name {
            "ruleEngine" => Self::RuleEngine(
                value
                    .parse()
                    .map_err(|e: ParseValueError| invalid(e.to_string()))?,
            ),
            "requestBodyAccess" => Self::RequestBodyAccess(parse_on_off(value)?),
            "requestBodyLimit" => Self::RequestBodyLimit(parse_limit(value)?),
            "forceRequestBodyVariable" => Self::ForceRequestBodyVariable(parse_on_off(value)?),
            "responseBodyAccess" => Self::ResponseBodyAccess(parse_on_off(value)?),
            "responseBodyLimit" => Self::ResponseBodyLimit(parse_limit(value)?),
            "forceResponseBodyVariable" => Self::ForceResponseBodyVariable(parse_on_off(value)?),
            "requestBodyProcessor" => Self::RequestBodyProcessor(parse_processor(value)?),
            "responseBodyProcessor" => Self::ResponseBodyProcessor(parse_processor(value)?),
            "ruleRemoveById" => Self::RuleRemoveById(parse_id_range(value)?),
            "ruleRemoveByTag" => Self::RuleRemoveByTag(value.to_string()),
            "ruleRemoveByMsg" => Self::RuleRemoveByMsg(value.to_string()),
            "ruleRemoveTargetById" => {
                let (id, target) = split_target(value)?;
                Self::RuleRemoveTargetById(parse_id(id)?, target)
            }
            "ruleRemoveTargetByTag" => {
                let (tag, target) = split_target(value)?;
                Self::RuleRemoveTargetByTag(tag.to_string(), target)
            }
            "ruleRemoveTargetByMsg" => {
                let (msg, target) = split_target(value)?;
                Self::RuleRemoveTargetByMsg(msg.to_string(), target)
            }
            "auditEngine" => {
                AuditEngineStatus::from_str(value).map_err(|e| invalid(e.to_string()))?;
                Self::NotImplemented
            }
            "debugLogLevel" => {
                match value.parse::<u8>() {
                    Ok(0..=9) => {}
                    _ => return Err(invalid(format!("log level must be 0-9, got '{}'", value))),
                }
                Self::NotImplemented
            }
            "auditLogParts" | "hashEngine" | "hashEnforcement" => Self::NotImplemented,
            _ => return Err(invalid(format!("unknown ctl command '{}'", name))),
        };
        Ok(command)
    }
}

fn invalid(message: String) -> ActionError {
    ActionError::InvalidArguments(message)
}

fn parse_processor(value: &str) -> Result<BodyProcessorKind, ActionError> {
    value
        .parse()
        .map_err(|e: ParseValueError| invalid(e.to_string()))
}

fn parse_on_off(value: &str) -> Result<bool, ActionError> {
    match value.to_lowercase().as_str() {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(invalid(format!("expected 'on' or 'off', got '{}'", value))),
    }
}

fn parse_limit(value: &str) -> Result<i64, ActionError> {
    value
        .parse()
        .map_err(|_| invalid(format!("expected numeric limit, got '{}'", value)))
}

fn parse_id(value: &str) -> Result<i32, ActionError> {
    value
        .parse()
        .map_err(|_| invalid(format!("expected rule id, got '{}'", value)))
}

/// `ID` or `START-END` (inclusive).
fn parse_id_range(value: &str) -> Result<RangeInclusive<i32>, ActionError> {
    match value.split_once('-') {
        Some((start, end)) if !start.is_empty() => Ok(parse_id(start)?..=parse_id(end)?),
        _ => parse_id(value).map(|id| id..=id),
    }
}

/// Splits `rules;COLLECTION[:key]` into the rule selector and the target.
fn split_target(value: &str) -> Result<(&str, RuleTarget), ActionError> {
    let (rules, target) = value.split_once(';').ok_or_else(|| {
        invalid(format!(
            "expected 'value;COLLECTION[:key]', got '{}'",
            value
        ))
    })?;
    let (collection, key) = target.split_once(':').unwrap_or((target, ""));
    let variable = collection
        .trim()
        .parse::<RuleVariable>()
        .map_err(|_| invalid(format!("unknown collection '{}'", collection.trim())))?;
    Ok((
        rules,
        RuleTarget {
            variable,
            key: key.to_lowercase(),
        },
    ))
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
#[derive(Debug, Clone, PartialEq)]
pub struct CtlAction {
    command: CtlCommand,
}

impl CtlAction {
    /// Parses `command=value` (or `command=value;COLLECTION[:key]` for `ruleRemoveTarget*`).
    pub fn parse(data: &str) -> Result<Self, ActionError> {
        CtlCommand::parse(data).map(|command| Self { command })
    }

    pub fn evaluate(&self, tx: &mut Transaction) {
        match &self.command {
            CtlCommand::RuleEngine(status) => tx.set_rule_engine(*status),
            CtlCommand::RequestBodyAccess(enabled) => {
                if before_phase(tx, RulePhase::RequestBody) {
                    tx.set_request_body_access(*enabled);
                }
            }
            CtlCommand::RequestBodyLimit(limit) => {
                if before_phase(tx, RulePhase::RequestBody) {
                    tx.set_request_body_limit(*limit);
                }
            }
            CtlCommand::ForceRequestBodyVariable(enabled) => {
                tx.set_force_request_body_variable(*enabled);
            }
            CtlCommand::ResponseBodyAccess(enabled) => {
                if before_phase(tx, RulePhase::ResponseBody) {
                    tx.set_response_body_access(*enabled);
                }
            }
            CtlCommand::ResponseBodyLimit(limit) => {
                if before_phase(tx, RulePhase::ResponseBody) {
                    tx.set_response_body_limit(*limit);
                }
            }
            CtlCommand::ForceResponseBodyVariable(enabled) => {
                tx.set_force_response_body_variable(*enabled);
            }
            CtlCommand::RequestBodyProcessor(processor) => {
                if before_phase(tx, RulePhase::RequestBody) {
                    tx.set_request_body_processor(*processor);
                }
            }
            CtlCommand::ResponseBodyProcessor(processor) => {
                if before_phase(tx, RulePhase::ResponseBody) {
                    tx.set_response_body_processor(*processor);
                }
            }
            CtlCommand::RuleRemoveById(ids) => {
                for id in ids.clone() {
                    tx.remove_rule_by_id(id);
                }
            }
            CtlCommand::RuleRemoveByTag(tag) => {
                for id in rule_ids(tx, |rule| rule.tags.contains(tag)) {
                    tx.remove_rule_by_id(id);
                }
            }
            CtlCommand::RuleRemoveByMsg(msg) => {
                for id in rule_ids(tx, |rule| has_msg(rule, msg)) {
                    tx.remove_rule_by_id(id);
                }
            }
            CtlCommand::RuleRemoveTargetById(id, target) => {
                tx.remove_rule_target_by_id(*id, target.variable, target.key.as_str());
            }
            CtlCommand::RuleRemoveTargetByTag(tag, target) => {
                for id in rule_ids(tx, |rule| rule.tags.contains(tag)) {
                    tx.remove_rule_target_by_id(id, target.variable, target.key.as_str());
                }
            }
            CtlCommand::RuleRemoveTargetByMsg(msg, target) => {
                for id in rule_ids(tx, |rule| has_msg(rule, msg)) {
                    tx.remove_rule_target_by_id(id, target.variable, target.key.as_str());
                }
            }
            CtlCommand::NotImplemented => {}
        }
    }
}

/// Whether `phase` has not started yet; body settings can't change once their phase began.
fn before_phase(tx: &Transaction, phase: RulePhase) -> bool {
    tx.last_phase().is_none_or(|last| last < phase)
}

/// IDs of the WAF's top-level rules matching `selects`; empty for a transaction without a WAF.
fn rule_ids(tx: &Transaction, selects: impl Fn(&RuleMetadata) -> bool) -> Vec<i32> {
    tx.rules()
        .map(|rules| {
            rules
                .get_rules()
                .iter()
                .map(|rule| rule.metadata())
                .filter(|metadata| selects(metadata))
                .map(|metadata| metadata.id)
                .collect()
        })
        .unwrap_or_default()
}

fn has_msg(rule: &RuleMetadata, msg: &str) -> bool {
    rule.msg.as_ref().is_some_and(|m| m.as_str() == msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(data: &str) -> CtlCommand {
        CtlCommand::parse(data).unwrap()
    }

    #[test]
    fn test_ctl_parses_values_when_compiled() {
        assert_eq!(
            parse("ruleEngine=Off"),
            CtlCommand::RuleEngine(RuleEngineStatus::Off)
        );
        assert_eq!(
            parse("requestBodyAccess=On"),
            CtlCommand::RequestBodyAccess(true)
        );
        assert_eq!(
            parse("requestBodyLimit=12345"),
            CtlCommand::RequestBodyLimit(12345)
        );
        assert_eq!(
            parse("responseBodyAccess=off"),
            CtlCommand::ResponseBodyAccess(false)
        );
        assert_eq!(
            parse("ruleRemoveById=123"),
            CtlCommand::RuleRemoveById(123..=123)
        );
        assert_eq!(
            parse("ruleRemoveById=1-9"),
            CtlCommand::RuleRemoveById(1..=9)
        );
        assert_eq!(
            parse("ruleRemoveByTag=MY_TAG"),
            CtlCommand::RuleRemoveByTag("MY_TAG".to_string())
        );
        assert_eq!(
            parse("ruleRemoveByMsg=a;b"),
            CtlCommand::RuleRemoveByMsg("a;b".to_string())
        );
    }

    #[test]
    fn test_ctl_parses_rule_targets() {
        assert_eq!(
            parse("ruleRemoveTargetById=123;ARGS:User"),
            CtlCommand::RuleRemoveTargetById(
                123,
                RuleTarget {
                    variable: RuleVariable::Args,
                    key: "user".to_string()
                }
            )
        );
        assert_eq!(
            parse("ruleRemoveTargetByTag=t;REQUEST_FILENAME:"),
            CtlCommand::RuleRemoveTargetByTag(
                "t".to_string(),
                RuleTarget {
                    variable: RuleVariable::RequestFilename,
                    key: String::new()
                }
            )
        );
    }

    #[test]
    fn test_ctl_accepts_not_implemented_commands() {
        for data in [
            "auditEngine=RelevantOnly",
            "auditLogParts=ABZ",
            "debugLogLevel=3",
        ] {
            assert_eq!(parse(data), CtlCommand::NotImplemented, "{}", data);
        }
    }

    #[test]
    fn test_ctl_body_processors() {
        assert_eq!(
            parse("requestBodyProcessor=xml"),
            CtlCommand::RequestBodyProcessor(BodyProcessorKind::Xml)
        );

        let mut tx = Transaction::new("ctl-processor");
        CtlAction::parse("requestBodyProcessor=JSON")
            .unwrap()
            .evaluate(&mut tx);
        assert_eq!(
            tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
            Some("JSON")
        );

        // Too late once the request body phase started
        tx.process_request_body(b"").unwrap();
        CtlAction::parse("requestBodyProcessor=XML")
            .unwrap()
            .evaluate(&mut tx);
        assert_eq!(
            tx.get_variable(RuleVariable::ReqbodyProcessor, None).as_deref(),
            Some("JSON")
        );
    }

    #[test]
    fn test_ctl_rejects_invalid_values_when_compiled() {
        for data in [
            "ruleEngine=bogus",
            "auditEngine=bogus",
            "ruleRemoveById=abc",
            "ruleRemoveTargetById=123",
            "ruleRemoveTargetById=abc;ARGS:x",
        ] {
            assert!(
                matches!(
                    CtlCommand::parse(data),
                    Err(ActionError::InvalidArguments(_))
                ),
                "{}",
                data
            );
        }
    }

    // Test error cases
    #[test]
    fn test_ctl_invalid_syntax_no_equals() {
        assert!(matches!(
            CtlAction::parse("invalid").map(|_| ()),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_ctl_unknown_command() {
        assert!(matches!(
            CtlAction::parse("unknownCommand=value").map(|_| ()),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_ctl_invalid_on_off() {
        assert!(matches!(
            CtlAction::parse("requestBodyAccess=Maybe").map(|_| ()),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_ctl_invalid_limit() {
        assert!(matches!(
            CtlAction::parse("requestBodyLimit=abc").map(|_| ()),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_ctl_invalid_debug_level() {
        assert!(matches!(
            CtlAction::parse("debugLogLevel=10").map(|_| ()),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_ctl_invalid_collection() {
        assert!(matches!(
            CtlAction::parse("ruleRemoveTargetById=123;INVALID:key").map(|_| ()),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_ctl_parse_on_off() {
        assert_eq!(parse_on_off("on"), Ok(true));
        assert_eq!(parse_on_off("ON"), Ok(true));
        assert_eq!(parse_on_off("On"), Ok(true));
        assert_eq!(parse_on_off("off"), Ok(false));
        assert_eq!(parse_on_off("OFF"), Ok(false));
        assert_eq!(parse_on_off("Off"), Ok(false));
        assert!(parse_on_off("maybe").is_err());
    }

    // CTL Execution Tests

    #[test]
    fn test_ctl_execute_rule_engine() {
        use crate::transaction::Transaction;

        let action = CtlAction::parse("ruleEngine=DetectionOnly").unwrap();

        let mut tx = Transaction::new("test-1");
        assert_eq!(tx.rule_engine(), crate::RuleEngineStatus::On); // default

        action.evaluate(&mut tx);
        assert_eq!(tx.rule_engine(), crate::RuleEngineStatus::DetectionOnly);
    }

    #[test]
    fn test_ctl_execute_request_body_access() {
        use crate::transaction::Transaction;

        let action = CtlAction::parse("requestBodyAccess=off").unwrap();

        let mut tx = Transaction::new("test-2");
        assert!(tx.request_body_access()); // default is true

        action.evaluate(&mut tx);
        assert!(!tx.request_body_access());
    }

    #[test]
    fn test_ctl_execute_request_body_limit() {
        use crate::transaction::Transaction;

        let action = CtlAction::parse("requestBodyLimit=256000").unwrap();

        let mut tx = Transaction::new("test-3");
        assert_eq!(tx.request_body_limit(), 131072); // default is 128KB

        action.evaluate(&mut tx);
        assert_eq!(tx.request_body_limit(), 256000);
    }

    #[test]
    fn test_ctl_execute_force_request_body_variable() {
        use crate::transaction::Transaction;

        let action = CtlAction::parse("forceRequestBodyVariable=on").unwrap();

        let mut tx = Transaction::new("test-4");
        assert!(!tx.force_request_body_variable()); // default is false

        action.evaluate(&mut tx);
        assert!(tx.force_request_body_variable());
    }

    #[test]
    fn test_ctl_execute_response_body_access() {
        use crate::transaction::Transaction;

        let action = CtlAction::parse("responseBodyAccess=on").unwrap();

        let mut tx = Transaction::new("test-5");
        assert!(!tx.response_body_access()); // default is false

        action.evaluate(&mut tx);
        assert!(tx.response_body_access());
    }

    #[test]
    fn test_ctl_execute_response_body_limit() {
        use crate::transaction::Transaction;

        let action = CtlAction::parse("responseBodyLimit=1048576").unwrap();

        let mut tx = Transaction::new("test-6");
        assert_eq!(tx.response_body_limit(), 524288); // default is 512KB

        action.evaluate(&mut tx);
        assert_eq!(tx.response_body_limit(), 1048576);
    }

    #[test]
    fn test_ctl_execute_force_response_body_variable() {
        use crate::transaction::Transaction;

        let action = CtlAction::parse("forceResponseBodyVariable=on").unwrap();

        let mut tx = Transaction::new("test-7");
        assert!(!tx.force_response_body_variable()); // default is false

        action.evaluate(&mut tx);
        assert!(tx.force_response_body_variable());
    }

    #[test]
    fn test_ctl_phase_restriction_request_body() {
        use crate::transaction::Transaction;

        let action = CtlAction::parse("requestBodyAccess=off").unwrap();

        let mut tx = Transaction::new("test-8");
        // Simulate being in request body phase
        tx.process_request_body(b"test").unwrap();

        assert!(tx.request_body_access()); // default is true

        // Try to change it - should be silently ignored
        action.evaluate(&mut tx);
        assert!(tx.request_body_access()); // unchanged
    }

    #[test]
    fn test_ctl_phase_restriction_response_body() {
        use crate::transaction::Transaction;

        let action = CtlAction::parse("responseBodyLimit=1000").unwrap();

        let mut tx = Transaction::new("test-9");
        // Simulate being in response body phase
        tx.process_response_body(b"test");

        assert_eq!(tx.response_body_limit(), 524288); // default

        // Try to change it - should be silently ignored
        action.evaluate(&mut tx);
        assert_eq!(tx.response_body_limit(), 524288); // unchanged
    }

    // ===== CTL Rule Exclusion Tests =====

    #[test]
    fn test_ctl_execute_rule_remove_by_id_single() {
        use crate::transaction::Transaction;

        let action = CtlAction::parse("ruleRemoveById=123").unwrap();

        let mut tx = Transaction::new("test-remove-1");
        assert!(!tx.is_rule_removed(123));

        action.evaluate(&mut tx);
        assert!(tx.is_rule_removed(123));
        assert!(!tx.is_rule_removed(124)); // other rules not affected
    }

    #[test]
    fn test_ctl_execute_rule_remove_by_id_range() {
        use crate::transaction::Transaction;

        let action = CtlAction::parse("ruleRemoveById=100-199").unwrap();

        let mut tx = Transaction::new("test-remove-2");
        assert!(!tx.is_rule_removed(100));
        assert!(!tx.is_rule_removed(150));
        assert!(!tx.is_rule_removed(199));

        action.evaluate(&mut tx);

        // All rules in range should be removed
        assert!(tx.is_rule_removed(100));
        assert!(tx.is_rule_removed(150));
        assert!(tx.is_rule_removed(199));

        // Rules outside range should not be affected
        assert!(!tx.is_rule_removed(99));
        assert!(!tx.is_rule_removed(200));
    }

    #[test]
    fn test_ctl_execute_rule_remove_target_by_id() {
        use crate::transaction::Transaction;

        let action = CtlAction::parse("ruleRemoveTargetById=981260;ARGS:user").unwrap();

        let mut tx = Transaction::new("test-remove-target-1");
        assert!(!tx.is_rule_target_removed(981260, RuleVariable::Args, "user"));

        action.evaluate(&mut tx);

        // Specific target should be removed
        assert!(tx.is_rule_target_removed(981260, RuleVariable::Args, "user"));

        // Other targets should not be affected
        assert!(!tx.is_rule_target_removed(981260, RuleVariable::Args, "password"));
        assert!(!tx.is_rule_target_removed(981260, RuleVariable::RequestHeaders, "user"));
        assert!(!tx.is_rule_target_removed(999, RuleVariable::Args, "user"));
    }

    #[test]
    fn test_ctl_execute_rule_remove_target_no_key() {
        use crate::transaction::Transaction;

        let action = CtlAction::parse("ruleRemoveTargetById=123;REQUEST_FILENAME:").unwrap();

        let mut tx = Transaction::new("test-remove-target-2");
        action.evaluate(&mut tx);

        // Empty key should be stored as empty string
        assert!(tx.is_rule_target_removed(123, RuleVariable::RequestFilename, ""));
    }

    #[test]
    fn test_ctl_rule_remove_multiple() {
        use crate::transaction::Transaction;

        let mut tx = Transaction::new("test-remove-multi");

        // Remove multiple rules via multiple actions
        let action1 = CtlAction::parse("ruleRemoveById=100").unwrap();
        action1.evaluate(&mut tx);

        let action2 = CtlAction::parse("ruleRemoveById=200").unwrap();
        action2.evaluate(&mut tx);

        let action3 = CtlAction::parse("ruleRemoveById=300-305").unwrap();
        action3.evaluate(&mut tx);

        assert!(tx.is_rule_removed(100));
        assert!(tx.is_rule_removed(200));
        assert!(tx.is_rule_removed(300));
        assert!(tx.is_rule_removed(305));
        assert!(!tx.is_rule_removed(306));
    }

    #[test]
    fn test_ctl_rule_remove_target_multiple() {
        use crate::transaction::Transaction;

        let mut tx = Transaction::new("test-remove-target-multi");

        // Remove multiple targets from same rule
        let action1 = CtlAction::parse("ruleRemoveTargetById=123;ARGS:username").unwrap();
        action1.evaluate(&mut tx);

        let action2 = CtlAction::parse("ruleRemoveTargetById=123;ARGS:password").unwrap();
        action2.evaluate(&mut tx);

        assert!(tx.is_rule_target_removed(123, RuleVariable::Args, "username"));
        assert!(tx.is_rule_target_removed(123, RuleVariable::Args, "password"));
        assert!(!tx.is_rule_target_removed(123, RuleVariable::Args, "email"));
    }

    // ===== CTL Tag/Msg-Based Exclusion Tests =====

    #[test]
    fn test_ctl_execute_rule_remove_by_tag() {
        use crate::config::WafConfig;
        use crate::rules::Rule as WafRule;
        use crate::waf::WafBuilder;

        // Create WAF with tagged rules
        let mut builder = WafBuilder::new(WafConfig::new());

        let mut rule1 = WafRule::new().with_id(100);
        rule1.metadata_mut().tags.push("attack".to_string());
        builder.add_rule(rule1).unwrap();

        let mut rule2 = WafRule::new().with_id(200);
        rule2.metadata_mut().tags.push("attack".to_string());
        builder.add_rule(rule2).unwrap();

        let mut rule3 = WafRule::new().with_id(300);
        rule3.metadata_mut().tags.push("sqli".to_string());
        builder.add_rule(rule3).unwrap();

        // Create transaction from WAF
        let waf = builder.build().expect("Failed to build WAF");
        let mut tx = waf.new_transaction_with_id("test-tag".to_string());

        // Execute ctl:ruleRemoveByTag=attack
        let action = CtlAction::parse("ruleRemoveByTag=attack").unwrap();
        action.evaluate(&mut tx);

        // Rules 100 and 200 should be excluded (they have "attack" tag)
        assert!(tx.is_rule_removed(100));
        assert!(tx.is_rule_removed(200));
        // Rule 300 should not be excluded (has "sqli" tag)
        assert!(!tx.is_rule_removed(300));
    }

    #[test]
    fn test_ctl_execute_rule_remove_by_msg() {
        use crate::config::WafConfig;
        use crate::operators::Macro;
        use crate::rules::Rule as WafRule;
        use crate::waf::WafBuilder;

        // Create WAF with rules having messages
        let mut builder = WafBuilder::new(WafConfig::new());

        let mut rule1 = WafRule::new().with_id(100);
        rule1.metadata_mut().msg = Some(Macro::new("SQL Injection").unwrap());
        builder.add_rule(rule1).unwrap();

        let mut rule2 = WafRule::new().with_id(200);
        rule2.metadata_mut().msg = Some(Macro::new("XSS Attack").unwrap());
        builder.add_rule(rule2).unwrap();

        let mut rule3 = WafRule::new().with_id(300);
        rule3.metadata_mut().msg = Some(Macro::new("SQL Injection").unwrap());
        builder.add_rule(rule3).unwrap();

        // Create transaction from WAF
        let waf = builder.build().expect("Failed to build WAF");
        let mut tx = waf.new_transaction_with_id("test-msg".to_string());

        // Execute ctl:ruleRemoveByMsg=SQL Injection
        let action = CtlAction::parse("ruleRemoveByMsg=SQL Injection").unwrap();
        action.evaluate(&mut tx);

        // Rules 100 and 300 should be excluded (message matches)
        assert!(tx.is_rule_removed(100));
        assert!(tx.is_rule_removed(300));
        // Rule 200 should not be excluded (different message)
        assert!(!tx.is_rule_removed(200));
    }

    #[test]
    fn test_ctl_execute_rule_remove_target_by_tag() {
        use crate::config::WafConfig;
        use crate::rules::Rule as WafRule;
        use crate::waf::WafBuilder;

        // Create WAF with tagged rules
        let mut builder = WafBuilder::new(WafConfig::new());

        let mut rule1 = WafRule::new().with_id(100);
        rule1.metadata_mut().tags.push("crs".to_string());
        builder.add_rule(rule1).unwrap();

        let mut rule2 = WafRule::new().with_id(200);
        rule2.metadata_mut().tags.push("crs".to_string());
        builder.add_rule(rule2).unwrap();

        let mut rule3 = WafRule::new().with_id(300);
        rule3.metadata_mut().tags.push("custom".to_string());
        builder.add_rule(rule3).unwrap();

        // Create transaction from WAF
        let waf = builder.build().expect("Failed to build WAF");
        let mut tx = waf.new_transaction_with_id("test-target-tag".to_string());

        // Execute ctl:ruleRemoveTargetByTag=crs;ARGS:id
        let action = CtlAction::parse("ruleRemoveTargetByTag=crs;ARGS:id").unwrap();
        action.evaluate(&mut tx);

        // ARGS:id should be excluded from rules 100 and 200
        assert!(tx.is_rule_target_removed(100, RuleVariable::Args, "id"));
        assert!(tx.is_rule_target_removed(200, RuleVariable::Args, "id"));
        // Rule 300 should not be affected (different tag)
        assert!(!tx.is_rule_target_removed(300, RuleVariable::Args, "id"));
        // Other variables should not be affected
        assert!(!tx.is_rule_target_removed(100, RuleVariable::Args, "name"));
    }

    #[test]
    fn test_ctl_execute_rule_remove_target_by_msg() {
        use crate::config::WafConfig;
        use crate::operators::Macro;
        use crate::rules::Rule as WafRule;
        use crate::waf::WafBuilder;

        // Create WAF with rules having messages
        let mut builder = WafBuilder::new(WafConfig::new());

        let mut rule1 = WafRule::new().with_id(100);
        rule1.metadata_mut().msg = Some(Macro::new("Parameter Attack").unwrap());
        builder.add_rule(rule1).unwrap();

        let mut rule2 = WafRule::new().with_id(200);
        rule2.metadata_mut().msg = Some(Macro::new("Header Attack").unwrap());
        builder.add_rule(rule2).unwrap();

        let mut rule3 = WafRule::new().with_id(300);
        rule3.metadata_mut().msg = Some(Macro::new("Parameter Attack").unwrap());
        builder.add_rule(rule3).unwrap();

        // Create transaction from WAF
        let waf = builder.build().expect("Failed to build WAF");
        let mut tx = waf.new_transaction_with_id("test-target-msg".to_string());

        // Execute ctl:ruleRemoveTargetByMsg=Parameter Attack;REQUEST_HEADERS:user-agent
        let action =
            CtlAction::parse("ruleRemoveTargetByMsg=Parameter Attack;REQUEST_HEADERS:user-agent")
                .unwrap();
        action.evaluate(&mut tx);

        // REQUEST_HEADERS:user-agent should be excluded from rules 100 and 300
        assert!(tx.is_rule_target_removed(100, RuleVariable::RequestHeaders, "user-agent"));
        assert!(tx.is_rule_target_removed(300, RuleVariable::RequestHeaders, "user-agent"));
        // Rule 200 should not be affected (different message)
        assert!(!tx.is_rule_target_removed(200, RuleVariable::RequestHeaders, "user-agent"));
    }

    #[test]
    fn test_ctl_tag_msg_without_waf_reference() {
        use crate::transaction::Transaction;

        // Create transaction without WAF reference (standalone)
        let mut tx = Transaction::new("standalone");

        // Execute ctl:ruleRemoveByTag - should not panic, just do nothing
        let action = CtlAction::parse("ruleRemoveByTag=attack").unwrap();
        action.evaluate(&mut tx);

        // No rules should be excluded (no WAF reference available)
        assert!(!tx.is_rule_removed(100));
        assert!(!tx.is_rule_removed(200));
    }
}
