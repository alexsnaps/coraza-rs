// Copyright 2024 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

//! WAF instance management.
//!
//! This module provides the main WAF struct that manages configuration,
//! rule storage, and transaction creation.

use crate::config::WafConfig;
use crate::rules::RuleGroup;
use crate::transaction::Transaction;
use crate::utils::strings::random_string;
use std::sync::Arc;

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

    /// Compiled rules organized by phase
    /// Wrapped in Arc for efficient sharing with transactions
    rules: Arc<RuleGroup>,
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
        let rules = Arc::new(RuleGroup::new());

        Ok(Self { config, rules })
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
}
