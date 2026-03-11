// Copyright 2024 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

//! WAF instance management.
//!
//! This module provides the main WAF struct that manages configuration,
//! rule storage, and transaction creation.

use std::collections::HashMap;

use crate::config::WafConfig;
use crate::rules::{Rule, RuleAction, RuleGroup, VariableSpec};
use crate::transaction::Transaction;
use crate::types::RulePhase;
use crate::utils::strings::random_string;

/// Error type for configuration validation during WAF creation.
///
/// This error only occurs when creating a new WAF instance with invalid configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigError(String);

impl ConfigError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid WAF configuration: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Error type for WAF runtime operations.
///
/// These errors occur after the WAF has been successfully created,
/// during operations like rule loading or audit logging.
#[derive(Debug, Clone, PartialEq)]
pub enum WafError {
    /// Rule loading or compilation failed
    RuleError(String),
    /// Audit logging initialization failed
    AuditLogError(String),
}

impl std::fmt::Display for WafError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WafError::RuleError(msg) => write!(f, "Rule error: {}", msg),
            WafError::AuditLogError(msg) => write!(f, "Audit log error: {}", msg),
        }
    }
}

impl std::error::Error for WafError {}

/// WAF instance that manages configuration, rules, and transactions.
///
/// A WAF instance is thread-safe and can be shared across multiple threads.
/// Each web application should have its own WAF instance, but you can share
/// an instance if you're okay with sharing configurations and rules.
///
/// # Examples
///
/// ```
/// use coraza::waf::Waf;
/// use coraza::config::WafConfig;
/// use coraza::RuleEngineStatus;
///
/// let config = WafConfig::new()
///     .with_rule_engine(RuleEngineStatus::On)
///     .with_request_body_limit(1048576);
///
/// let waf = Waf::new(config).unwrap();
///
/// // Create transactions
/// let tx1 = waf.new_transaction();
/// let tx2 = waf.new_transaction_with_id("custom-id".to_string());
/// ```
#[derive(Debug)]
pub struct Waf {
    /// Configuration settings
    config: WafConfig,

    /// Rule group for evaluation
    /// Rules can be added during WAF setup, then the WAF is used read-only
    rules: RuleGroup,

    /// Default actions per phase
    /// These are applied to rules in each phase if they don't have explicit actions
    default_actions: HashMap<RulePhase, Vec<RuleAction>>,
}

impl Waf {
    /// Creates a new WAF instance with the provided configuration.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if configuration validation fails:
    /// - Negative body limits or timeout values
    /// - Invalid debug log level (must be 0-9)
    /// - Invalid argument limit (must be > 0)
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::waf::Waf;
    /// use coraza::config::WafConfig;
    ///
    /// let config = WafConfig::new();
    /// let waf = Waf::new(config).unwrap();
    /// ```
    pub fn new(config: WafConfig) -> Result<Self, ConfigError> {
        // Validate configuration
        Self::validate_config(&config)?;

        // Create empty rule group
        let rules = RuleGroup::new();

        // Initialize default actions storage
        let default_actions = HashMap::new();

        Ok(Self {
            config,
            rules,
            default_actions,
        })
    }

    /// Creates a new transaction with an auto-generated ID.
    ///
    /// The transaction inherits configuration from the WAF instance.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::waf::Waf;
    /// use coraza::config::WafConfig;
    ///
    /// let waf = Waf::new(WafConfig::new()).unwrap();
    /// let tx = waf.new_transaction();
    /// ```
    pub fn new_transaction(&self) -> Transaction {
        let id = random_string(19);
        self.new_transaction_with_id(id)
    }

    /// Creates a new transaction with a custom ID.
    ///
    /// The transaction inherits configuration from the WAF instance.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::waf::Waf;
    /// use coraza::config::WafConfig;
    ///
    /// let waf = Waf::new(WafConfig::new()).unwrap();
    /// let tx = waf.new_transaction_with_id("request-123".to_string());
    /// assert_eq!(tx.id(), "request-123");
    /// ```
    pub fn new_transaction_with_id(&self, id: String) -> Transaction {
        let mut tx = Transaction::new(id);

        // Inherit configuration from WAF
        tx.set_rule_engine(self.config.rule_engine());
        tx.set_request_body_access(self.config.request_body_access());
        tx.set_request_body_limit(self.config.request_body_limit());
        tx.set_response_body_access(self.config.response_body_access());
        tx.set_response_body_limit(self.config.response_body_limit());

        tx
    }

    /// Returns a reference to the WAF configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::waf::Waf;
    /// use coraza::config::WafConfig;
    /// use coraza::RuleEngineStatus;
    ///
    /// let config = WafConfig::new().with_rule_engine(RuleEngineStatus::DetectionOnly);
    /// let waf = Waf::new(config).unwrap();
    ///
    /// assert_eq!(waf.config().rule_engine(), RuleEngineStatus::DetectionOnly);
    /// ```
    pub fn config(&self) -> &WafConfig {
        &self.config
    }

    /// Returns a reference to the rule group.
    pub fn rules(&self) -> &RuleGroup {
        &self.rules
    }

    /// Returns the number of rules loaded in this WAF.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::waf::Waf;
    /// use coraza::config::WafConfig;
    ///
    /// let waf = Waf::new(WafConfig::new()).unwrap();
    /// assert_eq!(waf.rule_count(), 0); // No rules loaded yet
    /// ```
    pub fn rule_count(&self) -> usize {
        self.rules.count()
    }

    /// Adds a single rule to the WAF.
    ///
    /// # Errors
    ///
    /// Returns `WafError::RuleError` if:
    /// - A rule with the same ID already exists
    /// - The rule is invalid
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::waf::Waf;
    /// use coraza::config::WafConfig;
    /// use coraza::rules::Rule;
    ///
    /// let mut waf = Waf::new(WafConfig::new()).unwrap();
    /// let rule = Rule::new().with_id(1);
    ///
    /// waf.add_rule(rule).unwrap();
    /// assert_eq!(waf.rule_count(), 1);
    /// ```
    pub fn add_rule(&mut self, rule: Rule) -> Result<(), WafError> {
        self.rules.add(rule).map_err(WafError::RuleError)
    }

    // Note: SecLang rule parsing (SecRule directives) will be added in future steps.
    // For now, rules must be constructed programmatically using the Rule builder.

    /// Removes a rule by its ID.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::waf::Waf;
    /// use coraza::config::WafConfig;
    /// use coraza::rules::Rule;
    ///
    /// let mut waf = Waf::new(WafConfig::new()).unwrap();
    /// waf.add_rule(Rule::new().with_id(1)).unwrap();
    /// waf.add_rule(Rule::new().with_id(2)).unwrap();
    ///
    /// waf.remove_rule_by_id(1);
    /// assert_eq!(waf.rule_count(), 1);
    /// ```
    pub fn remove_rule_by_id(&mut self, id: i32) {
        self.rules.delete_by_id(id);
    }

    /// Removes rules within an ID range (inclusive).
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::waf::Waf;
    /// use coraza::config::WafConfig;
    /// use coraza::rules::Rule;
    ///
    /// let mut waf = Waf::new(WafConfig::new()).unwrap();
    /// waf.add_rule(Rule::new().with_id(100)).unwrap();
    /// waf.add_rule(Rule::new().with_id(101)).unwrap();
    /// waf.add_rule(Rule::new().with_id(102)).unwrap();
    /// waf.add_rule(Rule::new().with_id(200)).unwrap();
    ///
    /// waf.remove_rules_by_id_range(100, 102);
    /// assert_eq!(waf.rule_count(), 1); // Only 200 remains
    /// ```
    pub fn remove_rules_by_id_range(&mut self, start: i32, end: i32) {
        self.rules.delete_by_range(start, end);
    }

    /// Removes rules by tag.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::waf::Waf;
    /// use coraza::config::WafConfig;
    /// use coraza::rules::Rule;
    ///
    /// let mut waf = Waf::new(WafConfig::new()).unwrap();
    ///
    /// let mut rule1 = Rule::new().with_id(1);
    /// rule1.metadata_mut().tags.push("attack".to_string());
    /// waf.add_rule(rule1).unwrap();
    ///
    /// let mut rule2 = Rule::new().with_id(2);
    /// rule2.metadata_mut().tags.push("sqli".to_string());
    /// waf.add_rule(rule2).unwrap();
    ///
    /// waf.remove_rules_by_tag("attack");
    /// assert_eq!(waf.rule_count(), 1); // Only rule 2 remains
    /// ```
    pub fn remove_rules_by_tag(&mut self, tag: &str) {
        self.rules.delete_by_tag(tag);
    }

    /// Removes rules by message.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::waf::Waf;
    /// use coraza::config::WafConfig;
    /// use coraza::rules::Rule;
    /// use coraza::operators::Macro;
    ///
    /// let mut waf = Waf::new(WafConfig::new()).unwrap();
    ///
    /// let mut rule1 = Rule::new().with_id(1);
    /// rule1.metadata_mut().msg = Some(Macro::new("SQL Injection").unwrap());
    /// waf.add_rule(rule1).unwrap();
    ///
    /// let mut rule2 = Rule::new().with_id(2);
    /// rule2.metadata_mut().msg = Some(Macro::new("XSS Attack").unwrap());
    /// waf.add_rule(rule2).unwrap();
    ///
    /// waf.remove_rules_by_msg("SQL Injection");
    /// assert_eq!(waf.rule_count(), 1); // Only rule 2 remains
    /// ```
    pub fn remove_rules_by_msg(&mut self, msg: &str) {
        self.rules.delete_by_msg(msg);
    }

    /// Finds a rule by its ID.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::waf::Waf;
    /// use coraza::config::WafConfig;
    /// use coraza::rules::Rule;
    ///
    /// let mut waf = Waf::new(WafConfig::new()).unwrap();
    /// waf.add_rule(Rule::new().with_id(123)).unwrap();
    ///
    /// assert!(waf.find_rule_by_id(123).is_some());
    /// assert!(waf.find_rule_by_id(999).is_none());
    /// ```
    pub fn find_rule_by_id(&self, id: i32) -> Option<&Rule> {
        self.rules.find_by_id(id)
    }

    /// Sets default actions for a specific phase.
    ///
    /// Default actions are applied to all rules in the phase that don't have
    /// explicit actions defined.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::waf::Waf;
    /// use coraza::config::WafConfig;
    /// use coraza::RulePhase;
    /// use coraza::rules::RuleAction;
    ///
    /// let mut waf = Waf::new(WafConfig::new()).unwrap();
    ///
    /// let actions = vec![]; // Would contain actual actions
    /// waf.set_default_actions(RulePhase::RequestHeaders, actions);
    /// ```
    pub fn set_default_actions(&mut self, phase: RulePhase, actions: Vec<RuleAction>) {
        self.default_actions.insert(phase, actions);
    }

    /// Gets default actions for a specific phase.
    ///
    /// Returns an empty slice if no default actions are set for the phase.
    pub fn get_default_actions(&self, phase: RulePhase) -> &[RuleAction] {
        self.default_actions
            .get(&phase)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Updates the variables (targets) for a rule by ID.
    ///
    /// # Errors
    ///
    /// Returns `WafError::RuleError` if the rule is not found.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::waf::Waf;
    /// use coraza::config::WafConfig;
    /// use coraza::rules::{Rule, VariableSpec};
    /// use coraza::RuleVariable;
    ///
    /// let mut waf = Waf::new(WafConfig::new()).unwrap();
    /// waf.add_rule(Rule::new().with_id(1)).unwrap();
    ///
    /// let new_vars = vec![VariableSpec::new(RuleVariable::Args)];
    /// waf.update_rule_variables_by_id(1, new_vars).unwrap();
    /// ```
    pub fn update_rule_variables_by_id(
        &mut self,
        id: i32,
        variables: Vec<VariableSpec>,
    ) -> Result<(), WafError> {
        let rule = self
            .rules
            .find_by_id_mut(id)
            .ok_or_else(|| WafError::RuleError(format!("Rule {} not found", id)))?;

        rule.set_variables(variables);
        Ok(())
    }

    /// Updates the actions for a rule by ID.
    ///
    /// # Errors
    ///
    /// Returns `WafError::RuleError` if the rule is not found.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::waf::Waf;
    /// use coraza::config::WafConfig;
    /// use coraza::rules::Rule;
    ///
    /// let mut waf = Waf::new(WafConfig::new()).unwrap();
    /// waf.add_rule(Rule::new().with_id(1)).unwrap();
    ///
    /// // In practice, you would create actual RuleAction instances:
    /// // let new_actions = vec![...];
    /// // waf.update_rule_actions_by_id(1, new_actions).unwrap();
    /// ```
    pub fn update_rule_actions_by_id(
        &mut self,
        id: i32,
        actions: Vec<RuleAction>,
    ) -> Result<(), WafError> {
        let rule = self
            .rules
            .find_by_id_mut(id)
            .ok_or_else(|| WafError::RuleError(format!("Rule {} not found", id)))?;

        rule.set_actions(actions);
        Ok(())
    }

    /// Updates the variables (targets) for all rules matching a tag.
    ///
    /// Returns the number of rules updated.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::waf::Waf;
    /// use coraza::config::WafConfig;
    /// use coraza::rules::{Rule, VariableSpec};
    /// use coraza::RuleVariable;
    ///
    /// let mut waf = Waf::new(WafConfig::new()).unwrap();
    ///
    /// let mut rule = Rule::new().with_id(1);
    /// rule.metadata_mut().tags.push("attack".to_string());
    /// waf.add_rule(rule).unwrap();
    ///
    /// let new_vars = vec![VariableSpec::new(RuleVariable::Args)];
    /// // let count = waf.update_rule_variables_by_tag("attack", new_vars).unwrap();
    /// // assert_eq!(count, 1);
    /// ```
    pub fn update_rule_variables_by_tag(
        &mut self,
        tag: &str,
        variables: Vec<VariableSpec>,
    ) -> Result<usize, WafError> {
        // Clone variables outside the closure to avoid lifetime issues
        let vars_clone = variables.clone();
        let count = self.rules.update_by_tag(tag, move |rule| {
            rule.set_variables(vars_clone.clone());
        });
        Ok(count)
    }

    /// Validates the WAF configuration.
    ///
    /// Checks for:
    /// - Valid body limits (positive, within reasonable bounds)
    /// - Valid timeout values
    /// - Valid log levels
    fn validate_config(config: &WafConfig) -> Result<(), ConfigError> {
        // Validate body limits
        if config.request_body_limit() < 0 {
            return Err(ConfigError::new("Request body limit must be non-negative"));
        }

        if config.response_body_limit() < 0 {
            return Err(ConfigError::new("Response body limit must be non-negative"));
        }

        if config.request_body_in_memory_limit() < 0 {
            return Err(ConfigError::new(
                "Request body in-memory limit must be non-negative",
            ));
        }

        // Validate collection timeout
        if config.collection_timeout() < 0 {
            return Err(ConfigError::new("Collection timeout must be non-negative"));
        }

        // Validate debug log level
        if !(0..=9).contains(&config.debug_log_level()) {
            return Err(ConfigError::new("Debug log level must be between 0 and 9"));
        }

        // Validate argument limit
        if config.argument_limit() == 0 {
            return Err(ConfigError::new("Argument limit must be greater than 0"));
        }

        Ok(())
    }
}

impl Default for Waf {
    /// Creates a new WAF with default configuration.
    fn default() -> Self {
        Self::new(WafConfig::default()).expect("Default config should be valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuleEngineStatus;

    #[test]
    fn test_waf_new() {
        let config = WafConfig::new();
        let waf = Waf::new(config);
        assert!(waf.is_ok());
    }

    #[test]
    fn test_waf_default() {
        let waf = Waf::default();
        assert_eq!(waf.config().rule_engine(), RuleEngineStatus::On);
    }

    #[test]
    fn test_waf_config_access() {
        let config = WafConfig::new()
            .with_rule_engine(RuleEngineStatus::DetectionOnly)
            .with_request_body_limit(2097152);

        let waf = Waf::new(config).unwrap();

        assert_eq!(waf.config().rule_engine(), RuleEngineStatus::DetectionOnly);
        assert_eq!(waf.config().request_body_limit(), 2097152);
    }

    #[test]
    fn test_waf_new_transaction() {
        let waf = Waf::default();
        let tx = waf.new_transaction();

        // Transaction should inherit WAF config
        assert_eq!(tx.rule_engine(), waf.config().rule_engine());
    }

    #[test]
    fn test_waf_new_transaction_with_id() {
        let waf = Waf::default();
        let tx = waf.new_transaction_with_id("custom-123".to_string());

        assert_eq!(tx.id(), "custom-123");
    }

    #[test]
    fn test_waf_transaction_inherits_config() {
        let config = WafConfig::new()
            .with_rule_engine(RuleEngineStatus::DetectionOnly)
            .with_request_body_access(true)
            .with_request_body_limit(1048576)
            .with_response_body_access(true)
            .with_response_body_limit(2097152);

        let waf = Waf::new(config).unwrap();
        let tx = waf.new_transaction();

        assert_eq!(tx.rule_engine(), RuleEngineStatus::DetectionOnly);
        assert!(tx.request_body_access());
        assert_eq!(tx.request_body_limit(), 1048576);
        assert!(tx.response_body_access());
        assert_eq!(tx.response_body_limit(), 2097152);
    }

    #[test]
    fn test_waf_rule_count_initially_zero() {
        let waf = Waf::default();
        assert_eq!(waf.rule_count(), 0);
    }

    #[test]
    fn test_waf_validate_negative_request_body_limit() {
        let config = WafConfig::new().with_request_body_limit(-1);
        let result = Waf::new(config);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid WAF configuration: Request body limit must be non-negative"
        );
    }

    #[test]
    fn test_waf_validate_negative_response_body_limit() {
        let config = WafConfig::new().with_response_body_limit(-1);
        let result = Waf::new(config);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid WAF configuration: Response body limit must be non-negative"
        );
    }

    #[test]
    fn test_waf_validate_negative_collection_timeout() {
        let config = WafConfig::new().with_collection_timeout(-1);
        let result = Waf::new(config);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid WAF configuration: Collection timeout must be non-negative"
        );
    }

    #[test]
    fn test_waf_validate_invalid_debug_log_level() {
        let config = WafConfig::new().with_debug_log_level(10);
        let result = Waf::new(config);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid WAF configuration: Debug log level must be between 0 and 9"
        );
    }

    #[test]
    fn test_waf_validate_zero_argument_limit() {
        let config = WafConfig::new().with_argument_limit(0);
        let result = Waf::new(config);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid WAF configuration: Argument limit must be greater than 0"
        );
    }

    #[test]
    fn test_waf_validate_valid_config() {
        let config = WafConfig::new()
            .with_request_body_limit(1048576)
            .with_response_body_limit(524288)
            .with_collection_timeout(3600)
            .with_debug_log_level(5)
            .with_argument_limit(500);

        let result = Waf::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_waf_multiple_transactions() {
        let waf = Waf::default();

        let tx1 = waf.new_transaction();
        let tx2 = waf.new_transaction();
        let tx3 = waf.new_transaction_with_id("custom".to_string());

        // All should have unique IDs
        assert_ne!(tx1.id(), tx2.id());
        assert_ne!(tx1.id(), tx3.id());
        assert_eq!(tx3.id(), "custom");
    }

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::new("test error");
        assert_eq!(err.to_string(), "Invalid WAF configuration: test error");
    }

    #[test]
    fn test_waf_error_display() {
        let err = WafError::RuleError("rule failed".to_string());
        assert_eq!(err.to_string(), "Rule error: rule failed");

        let err = WafError::AuditLogError("log failed".to_string());
        assert_eq!(err.to_string(), "Audit log error: log failed");
    }

    // ===== Rule Management Tests (Step 2) =====

    #[test]
    fn test_waf_add_rule() {
        let mut waf = Waf::default();

        let rule = Rule::new().with_id(1);
        waf.add_rule(rule).unwrap();

        assert_eq!(waf.rule_count(), 1);
    }

    #[test]
    fn test_waf_add_rule_duplicate_id() {
        let mut waf = Waf::default();

        waf.add_rule(Rule::new().with_id(1)).unwrap();
        let result = waf.add_rule(Rule::new().with_id(1));

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("duplicated"));
    }

    #[test]
    fn test_waf_remove_rule_by_id() {
        let mut waf = Waf::default();

        waf.add_rule(Rule::new().with_id(1)).unwrap();
        waf.add_rule(Rule::new().with_id(2)).unwrap();
        waf.add_rule(Rule::new().with_id(3)).unwrap();

        waf.remove_rule_by_id(2);

        assert_eq!(waf.rule_count(), 2);
        assert!(waf.find_rule_by_id(1).is_some());
        assert!(waf.find_rule_by_id(2).is_none());
        assert!(waf.find_rule_by_id(3).is_some());
    }

    #[test]
    fn test_waf_remove_rules_by_id_range() {
        let mut waf = Waf::default();

        for id in 1..=10 {
            waf.add_rule(Rule::new().with_id(id)).unwrap();
        }

        waf.remove_rules_by_id_range(3, 7);

        assert_eq!(waf.rule_count(), 5); // 1, 2, 8, 9, 10 remain
        assert!(waf.find_rule_by_id(1).is_some());
        assert!(waf.find_rule_by_id(3).is_none());
        assert!(waf.find_rule_by_id(5).is_none());
        assert!(waf.find_rule_by_id(7).is_none());
        assert!(waf.find_rule_by_id(8).is_some());
    }

    #[test]
    fn test_waf_remove_rules_by_tag() {
        let mut waf = Waf::default();

        let mut rule1 = Rule::new().with_id(1);
        rule1.metadata_mut().tags.push("attack-sqli".to_string());
        waf.add_rule(rule1).unwrap();

        let mut rule2 = Rule::new().with_id(2);
        rule2.metadata_mut().tags.push("attack-xss".to_string());
        waf.add_rule(rule2).unwrap();

        let mut rule3 = Rule::new().with_id(3);
        rule3.metadata_mut().tags.push("attack-sqli".to_string());
        waf.add_rule(rule3).unwrap();

        waf.remove_rules_by_tag("attack-sqli");

        assert_eq!(waf.rule_count(), 1);
        assert!(waf.find_rule_by_id(2).is_some());
    }

    #[test]
    fn test_waf_remove_rules_by_msg() {
        use crate::operators::Macro;

        let mut waf = Waf::default();

        let mut rule1 = Rule::new().with_id(1);
        rule1.metadata_mut().msg = Some(Macro::new("SQL Injection detected").unwrap());
        waf.add_rule(rule1).unwrap();

        let mut rule2 = Rule::new().with_id(2);
        rule2.metadata_mut().msg = Some(Macro::new("XSS Attack detected").unwrap());
        waf.add_rule(rule2).unwrap();

        let mut rule3 = Rule::new().with_id(3);
        rule3.metadata_mut().msg = Some(Macro::new("SQL Injection detected").unwrap());
        waf.add_rule(rule3).unwrap();

        waf.remove_rules_by_msg("SQL Injection detected");

        assert_eq!(waf.rule_count(), 1);
        assert!(waf.find_rule_by_id(2).is_some());
    }

    #[test]
    fn test_waf_find_rule_by_id() {
        let mut waf = Waf::default();

        waf.add_rule(Rule::new().with_id(100)).unwrap();
        waf.add_rule(Rule::new().with_id(200)).unwrap();

        assert!(waf.find_rule_by_id(100).is_some());
        assert!(waf.find_rule_by_id(200).is_some());
        assert!(waf.find_rule_by_id(300).is_none());

        let rule = waf.find_rule_by_id(100).unwrap();
        assert_eq!(rule.metadata().id, 100);
    }

    #[test]
    fn test_waf_rule_count() {
        let mut waf = Waf::default();

        assert_eq!(waf.rule_count(), 0);

        waf.add_rule(Rule::new().with_id(1)).unwrap();
        assert_eq!(waf.rule_count(), 1);

        waf.add_rule(Rule::new().with_id(2)).unwrap();
        assert_eq!(waf.rule_count(), 2);

        waf.remove_rule_by_id(1);
        assert_eq!(waf.rule_count(), 1);
    }

    #[test]
    fn test_waf_multiple_rule_operations() {
        let mut waf = Waf::default();

        // Add several rules with different metadata
        for id in 1..=5 {
            let mut rule = Rule::new().with_id(id);
            if id % 2 == 0 {
                rule.metadata_mut().tags.push("even".to_string());
            }
            waf.add_rule(rule).unwrap();
        }

        assert_eq!(waf.rule_count(), 5);

        // Remove even-tagged rules
        waf.remove_rules_by_tag("even");
        assert_eq!(waf.rule_count(), 3); // 1, 3, 5 remain

        // Remove by ID
        waf.remove_rule_by_id(3);
        assert_eq!(waf.rule_count(), 2); // 1, 5 remain

        // Verify remaining rules
        assert!(waf.find_rule_by_id(1).is_some());
        assert!(waf.find_rule_by_id(5).is_some());
        assert!(waf.find_rule_by_id(2).is_none());
        assert!(waf.find_rule_by_id(3).is_none());
        assert!(waf.find_rule_by_id(4).is_none());
    }

    #[test]
    fn test_waf_default_actions() {
        use crate::RulePhase;

        let mut waf = Waf::default();

        // Initially no default actions
        assert_eq!(waf.get_default_actions(RulePhase::RequestHeaders).len(), 0);

        // Set default actions for phase 1 (empty for now since RuleAction can't be easily constructed in tests)
        waf.set_default_actions(RulePhase::RequestHeaders, vec![]);

        // Verify they're stored
        assert_eq!(waf.get_default_actions(RulePhase::RequestHeaders).len(), 0);

        // Other phases still empty
        assert_eq!(waf.get_default_actions(RulePhase::RequestBody).len(), 0);
    }

    #[test]
    fn test_waf_update_rule_variables_by_id() {
        use crate::RuleVariable;
        use crate::rules::VariableSpec;

        let mut waf = Waf::default();

        // Add rule with no variables
        waf.add_rule(Rule::new().with_id(1)).unwrap();

        // Update its variables
        let new_vars = vec![
            VariableSpec::new(RuleVariable::Args),
            VariableSpec::new(RuleVariable::RequestHeaders),
        ];
        waf.update_rule_variables_by_id(1, new_vars).unwrap();

        // Verify rule was found and updated (we can't directly inspect variables,
        // but we can verify the operation succeeded)
        assert!(waf.find_rule_by_id(1).is_some());

        // Try updating non-existent rule
        let result = waf.update_rule_variables_by_id(999, vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_waf_update_rule_actions_by_id() {
        let mut waf = Waf::default();

        // Add rule with no actions
        waf.add_rule(Rule::new().with_id(1)).unwrap();

        // Update its actions
        let new_actions = vec![]; // Would contain actual actions in practice
        waf.update_rule_actions_by_id(1, new_actions).unwrap();

        // Verify rule was found and updated
        assert!(waf.find_rule_by_id(1).is_some());

        // Try updating non-existent rule
        let result = waf.update_rule_actions_by_id(999, vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_waf_update_rule_variables_by_tag() {
        use crate::RuleVariable;
        use crate::rules::VariableSpec;

        let mut waf = Waf::default();

        // Add multiple rules with the same tag
        let mut rule1 = Rule::new().with_id(1);
        rule1.metadata_mut().tags.push("attack".to_string());
        waf.add_rule(rule1).unwrap();

        let mut rule2 = Rule::new().with_id(2);
        rule2.metadata_mut().tags.push("attack".to_string());
        waf.add_rule(rule2).unwrap();

        let mut rule3 = Rule::new().with_id(3);
        rule3.metadata_mut().tags.push("other".to_string());
        waf.add_rule(rule3).unwrap();

        // Update variables for all "attack" tagged rules
        let new_vars = vec![VariableSpec::new(RuleVariable::Args)];
        let count = waf
            .update_rule_variables_by_tag("attack", new_vars)
            .unwrap();

        // Should have updated 2 rules
        assert_eq!(count, 2);

        // Update non-existent tag
        let count = waf
            .update_rule_variables_by_tag("nonexistent", vec![])
            .unwrap();
        assert_eq!(count, 0);
    }
}
