// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Metadata actions for rule classification and identification.
//!
//! Metadata actions provide information about rules, such as identification,
//! versioning, and classification. These actions do not affect transaction
//! processing - they only store information that appears in logs and alerts.

use crate::RuleSeverity;
use crate::actions::{Action, ActionError, ActionType, Rule, TransactionState};
use crate::operators::Macro;

/// `id` action - Assigns a unique numeric ID to the rule.
///
/// This action is **mandatory** for all `SecRule` and `SecAction` directives.
/// The ID must be a positive integer and uniquely identifies the rule.
///
/// # Arguments
///
/// Numeric rule ID (must be > 0)
///
/// # Examples
///
/// ```text
/// SecRule ARGS "@rx attack" "id:100,deny,msg:'Attack detected'"
/// ```
#[derive(Debug)]
pub struct IdAction;

impl Action for IdAction {
    fn init(&mut self, rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if data.is_empty() {
            return Err(ActionError::MissingArguments);
        }

        let id = data
            .parse::<i32>()
            .map_err(|e| ActionError::InvalidArguments(format!("invalid id: {}", e)))?;

        if id <= 0 {
            return Err(ActionError::InvalidArguments(format!(
                "invalid id argument, {} must be positive",
                id
            )));
        }

        rule.id = id;
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // Metadata actions don't execute at runtime
    }

    fn action_type(&self) -> ActionType {
        ActionType::Metadata
    }
}

/// `msg` action - Assigns a custom message to the rule.
///
/// The message will be logged along with every alert. Supports macro expansion
/// for dynamic content. The message appears in error and audit log files but is
/// not sent back to the client in response headers.
///
/// # Arguments
///
/// Message string (supports macro expansion with `%{VAR.key}`)
///
/// # Examples
///
/// ```text
/// SecRule REQUEST_HEADERS:Host "@eq 0" "id:60008,severity:2,msg:'Request Missing a Host Header'"
/// SecRule ARGS:id "@gt 100" "id:60009,msg:'ID value is %{ARGS.id}'"
/// ```
#[derive(Debug)]
pub struct MsgAction;

impl Action for MsgAction {
    fn init(&mut self, rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if data.is_empty() {
            return Err(ActionError::MissingArguments);
        }

        // Remove surrounding quotes if present
        let msg_text = crate::utils::strings::maybe_remove_quotes(data);
        let msg = Macro::new(msg_text)?;
        rule.msg = Some(msg);
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // Metadata actions don't execute at runtime
    }

    fn action_type(&self) -> ActionType {
        ActionType::Metadata
    }
}

/// `tag` action - Assigns a classification tag to the rule.
///
/// Tags allow easy automated categorization of events. Multiple tags can be
/// specified on the same rule. Forward slashes can be used to create a
/// hierarchy of categories (e.g., "WEB_ATTACK/XSS").
///
/// # Arguments
///
/// Tag string (can be hierarchical with `/` separator)
///
/// # Examples
///
/// ```text
/// SecRule ARGS "@rx <script" "id:100,tag:'WEB_ATTACK/XSS',tag:'OWASP_TOP_10/A7'"
/// ```
#[derive(Debug)]
pub struct TagAction;

impl Action for TagAction {
    fn init(&mut self, rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if data.is_empty() {
            return Err(ActionError::MissingArguments);
        }

        rule.tags.push(data.to_string());
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // Metadata actions don't execute at runtime
    }

    fn action_type(&self) -> ActionType {
        ActionType::Metadata
    }
}

/// `severity` action - Assigns severity level to the rule.
///
/// Severity values follow the numeric scale of syslog (where 0 is the most severe).
/// Can be specified using either numeric values (0-7) or text values.
///
/// # Severity Levels
///
/// - **0, EMERGENCY**: Correlation of inbound attack and outbound leakage
/// - **1, ALERT**: Correlation of inbound attack and outbound error
/// - **2, CRITICAL**: Anomaly Score of 5, highest without correlation
/// - **3, ERROR**: Anomaly Score of 4, mostly outbound leakage
/// - **4, WARNING**: Anomaly Score of 3, malicious client rules
/// - **5, NOTICE**: Anomaly Score of 2, protocol policy
/// - **6, INFO**: Informational
/// - **7, DEBUG**: Debug information
///
/// # Arguments
///
/// Severity level as string name or numeric value (0-7)
///
/// # Examples
///
/// ```text
/// SecRule REQUEST_METHOD "^PUT$" "id:340002,severity:CRITICAL,msg:'Restricted HTTP function'"
/// SecRule ARGS "@rx test" "id:100,severity:2,msg:'Test rule'"
/// ```
#[derive(Debug)]
pub struct SeverityAction;

impl Action for SeverityAction {
    fn init(&mut self, rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if data.is_empty() {
            return Err(ActionError::MissingArguments);
        }

        let severity = data
            .parse::<RuleSeverity>()
            .map_err(|e| ActionError::InvalidArguments(e.to_string()))?;

        rule.severity = Some(severity);
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // Metadata actions don't execute at runtime
    }

    fn action_type(&self) -> ActionType {
        ActionType::Metadata
    }
}

/// `rev` action - Specifies the rule revision.
///
/// Used in combination with `id` to allow the same rule ID to be used after changes,
/// while still providing some indication about the rule changes.
///
/// # Arguments
///
/// Revision string (typically a version number like "2.1.3")
///
/// # Examples
///
/// ```text
/// SecRule ARGS "@rx attack" "id:950907,rev:'2.1.3',msg:'Command Injection'"
/// ```
#[derive(Debug)]
pub struct RevAction;

impl Action for RevAction {
    fn init(&mut self, rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if data.is_empty() {
            return Err(ActionError::MissingArguments);
        }

        rule.rev = data.to_string();
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // Metadata actions don't execute at runtime
    }

    fn action_type(&self) -> ActionType {
        ActionType::Metadata
    }
}

/// `ver` action - Specifies the rule set version.
///
/// Indicates which version of a rule set this rule belongs to, typically used
/// to track rule set versions like "CRS/2.2.4".
///
/// # Arguments
///
/// Version string (e.g., "CRS/2.2.4", "1.0.0")
///
/// # Examples
///
/// ```text
/// SecRule ARGS "@rx <script" "id:958016,ver:'CRS/2.2.4',msg:'XSS Attack'"
/// ```
#[derive(Debug)]
pub struct VerAction;

impl Action for VerAction {
    fn init(&mut self, rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if data.is_empty() {
            return Err(ActionError::MissingArguments);
        }

        rule.ver = data.to_string();
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // Metadata actions don't execute at runtime
    }

    fn action_type(&self) -> ActionType {
        ActionType::Metadata
    }
}

/// `maturity` action - Specifies the relative maturity level of the rule.
///
/// Indicates the length of time a rule has been public and the amount of testing
/// it has received. The value is a numeric scale from 1-9, where 9 is extensively
/// tested and 1 is a brand new experimental rule.
///
/// # Arguments
///
/// Maturity level (1-9)
///
/// # Examples
///
/// ```text
/// SecRule ARGS "@rx <script" "id:958016,maturity:'9',msg:'Well-tested XSS rule'"
/// SecRule ARGS "@rx newpattern" "id:100,maturity:'1',msg:'Experimental rule'"
/// ```
#[derive(Debug)]
pub struct MaturityAction;

impl Action for MaturityAction {
    fn init(&mut self, rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        let maturity = data
            .parse::<u8>()
            .map_err(|e| ActionError::InvalidArguments(format!("invalid maturity: {}", e)))?;

        if !(1..=9).contains(&maturity) {
            return Err(ActionError::InvalidArguments(format!(
                "invalid argument, {} should be between 1 and 9",
                maturity
            )));
        }

        rule.maturity = maturity;
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // Metadata actions don't execute at runtime
    }

    fn action_type(&self) -> ActionType {
        ActionType::Metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuleSeverity;

    // ID Action Tests
    #[test]
    fn test_id_empty() {
        let mut rule = Rule::new();
        let mut action = IdAction;
        assert_eq!(
            action.init(&mut rule, ""),
            Err(ActionError::MissingArguments)
        );
    }

    #[test]
    fn test_id_non_numeric() {
        let mut rule = Rule::new();
        let mut action = IdAction;
        assert!(matches!(
            action.init(&mut rule, "x"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_id_zero() {
        let mut rule = Rule::new();
        let mut action = IdAction;
        assert!(matches!(
            action.init(&mut rule, "0"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_id_negative() {
        let mut rule = Rule::new();
        let mut action = IdAction;
        assert!(matches!(
            action.init(&mut rule, "-10"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_id_valid() {
        let mut rule = Rule::new();
        let mut action = IdAction;
        assert!(action.init(&mut rule, "10").is_ok());
        assert_eq!(rule.id, 10);
    }

    // MSG Action Tests
    #[test]
    fn test_msg_empty() {
        let mut rule = Rule::new();
        let mut action = MsgAction;
        assert_eq!(
            action.init(&mut rule, ""),
            Err(ActionError::MissingArguments)
        );
    }

    #[test]
    fn test_msg_valid() {
        let mut rule = Rule::new();
        let mut action = MsgAction;
        assert!(action.init(&mut rule, "test message").is_ok());
        assert!(rule.msg.is_some());
    }

    #[test]
    fn test_msg_with_quotes() {
        let mut rule = Rule::new();
        let mut action = MsgAction;
        assert!(action.init(&mut rule, "'quoted message'").is_ok());
        assert!(rule.msg.is_some());
    }

    // TAG Action Tests
    #[test]
    fn test_tag_empty() {
        let mut rule = Rule::new();
        let mut action = TagAction;
        assert_eq!(
            action.init(&mut rule, ""),
            Err(ActionError::MissingArguments)
        );
    }

    #[test]
    fn test_tag_valid() {
        let mut rule = Rule::new();
        let mut action = TagAction;
        assert!(action.init(&mut rule, "WEB_ATTACK/XSS").is_ok());
        assert_eq!(rule.tags, vec!["WEB_ATTACK/XSS"]);
    }

    #[test]
    fn test_tag_multiple() {
        let mut rule = Rule::new();
        let mut action1 = TagAction;
        let mut action2 = TagAction;
        assert!(action1.init(&mut rule, "TAG1").is_ok());
        assert!(action2.init(&mut rule, "TAG2").is_ok());
        assert_eq!(rule.tags, vec!["TAG1", "TAG2"]);
    }

    // SEVERITY Action Tests
    #[test]
    fn test_severity_string_names() {
        let test_cases = vec![
            ("EMERGENCY", RuleSeverity::Emergency),
            ("ALERT", RuleSeverity::Alert),
            ("CRITICAL", RuleSeverity::Critical),
            ("ERROR", RuleSeverity::Error),
            ("WARNING", RuleSeverity::Warning),
            ("NOTICE", RuleSeverity::Notice),
            ("INFO", RuleSeverity::Info),
            ("DEBUG", RuleSeverity::Debug),
        ];

        for (name, expected) in test_cases {
            let mut rule = Rule::new();
            let mut action = SeverityAction;
            assert!(action.init(&mut rule, name).is_ok(), "Failed for {}", name);
            assert_eq!(rule.severity, Some(expected), "Mismatch for {}", name);
        }
    }

    #[test]
    fn test_severity_numeric() {
        for i in 0..=7 {
            let mut rule = Rule::new();
            let mut action = SeverityAction;
            let data = i.to_string();
            assert!(action.init(&mut rule, &data).is_ok());
            assert_eq!(rule.severity.unwrap() as u8, i);
        }
    }

    #[test]
    fn test_severity_empty() {
        let mut rule = Rule::new();
        let mut action = SeverityAction;
        assert_eq!(
            action.init(&mut rule, ""),
            Err(ActionError::MissingArguments)
        );
    }

    // REV Action Tests
    #[test]
    fn test_rev_empty() {
        let mut rule = Rule::new();
        let mut action = RevAction;
        assert_eq!(
            action.init(&mut rule, ""),
            Err(ActionError::MissingArguments)
        );
    }

    #[test]
    fn test_rev_valid() {
        let mut rule = Rule::new();
        let mut action = RevAction;
        assert!(action.init(&mut rule, "2.1.3").is_ok());
        assert_eq!(rule.rev, "2.1.3");
    }

    // VER Action Tests
    #[test]
    fn test_ver_empty() {
        let mut rule = Rule::new();
        let mut action = VerAction;
        assert_eq!(
            action.init(&mut rule, ""),
            Err(ActionError::MissingArguments)
        );
    }

    #[test]
    fn test_ver_valid() {
        let mut rule = Rule::new();
        let mut action = VerAction;
        assert!(action.init(&mut rule, "1.2.3").is_ok());
        assert_eq!(rule.ver, "1.2.3");
    }

    // MATURITY Action Tests
    #[test]
    fn test_maturity_empty() {
        let mut rule = Rule::new();
        let mut action = MaturityAction;
        assert!(matches!(
            action.init(&mut rule, ""),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_maturity_non_numeric() {
        let mut rule = Rule::new();
        let mut action = MaturityAction;
        assert!(matches!(
            action.init(&mut rule, "abc"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_maturity_negative() {
        let mut rule = Rule::new();
        let mut action = MaturityAction;
        assert!(matches!(
            action.init(&mut rule, "-10"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_maturity_zero() {
        let mut rule = Rule::new();
        let mut action = MaturityAction;
        assert!(matches!(
            action.init(&mut rule, "0"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    #[test]
    fn test_maturity_valid() {
        let mut rule = Rule::new();
        let mut action = MaturityAction;
        assert!(action.init(&mut rule, "5").is_ok());
        assert_eq!(rule.maturity, 5);
    }

    #[test]
    fn test_maturity_out_of_range() {
        let mut rule = Rule::new();
        let mut action = MaturityAction;
        assert!(matches!(
            action.init(&mut rule, "10"),
            Err(ActionError::InvalidArguments(_))
        ));
    }
}
