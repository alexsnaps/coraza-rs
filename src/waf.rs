// Copyright 2024 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

//! WAF instance management.
//!
//! This module provides the main WAF struct that manages configuration,
//! rule storage, and transaction creation.

use std::sync::Arc;

use crate::audit_log::AuditLogger;
use crate::config::WafConfig;
use crate::rules::RuleGroup;
use crate::transaction::{ErrorLog, Transaction};
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

/// WAF instance that holds configuration and rules, and creates transactions.
///
/// A `Waf` is immutable and thread-safe: share one across threads (e.g. in an `Arc`)
/// to process concurrent requests. Build one from SecLang directives with
/// [`crate::seclang::Parser::into_waf`], or with [`Waf::new`] for a WAF without rules.
///
/// # Examples
///
/// ```
/// use coraza::waf::Waf;
/// use coraza::config::WafConfig;
/// use coraza::RuleEngineStatus;
///
/// let config = WafConfig {
///     rule_engine: RuleEngineStatus::On,
///     request_body_limit: 1048576,
///     ..WafConfig::default()
/// };
///
/// let waf = Waf::new(config).unwrap();
///
/// // Create transactions
/// let tx1 = waf.new_transaction();
/// let tx2 = waf.new_transaction_with_id("custom-id".to_string());
/// ```
#[derive(Debug)]
pub struct Waf {
    /// Configuration settings, shared with transactions
    config: Arc<WafConfig>,

    /// Rules in evaluation order, shared with transactions for CTL rule exclusion
    rules: Arc<RuleGroup>,

    /// Where transactions write their audit log entries
    audit_logger: Arc<AuditLogger>,

    /// Where transactions hand each matched rule with `log`, if anywhere
    error_log: Option<ErrorLog>,
}

impl Waf {
    /// Creates a WAF without rules.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if configuration validation fails:
    /// - Negative body limits or timeout values
    /// - Invalid debug log level (must be 0-9)
    /// - Invalid argument limit (must be > 0)
    /// - Uploads kept (`SecUploadKeepFiles`) without an upload directory (`SecUploadDir`)
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
        Self::with_rules(config, RuleGroup::new(), None)
    }

    /// Creates a WAF with `rules`, as SecLang directives compiled them, and `error_log`.
    ///
    /// # Errors
    ///
    /// As [`Waf::new`], or if the audit log can't be opened.
    pub(crate) fn with_rules(
        config: WafConfig,
        rules: RuleGroup,
        error_log: Option<ErrorLog>,
    ) -> Result<Self, ConfigError> {
        validate_config(&config)?;
        let audit_logger = AuditLogger::open(&config).map_err(ConfigError::new)?;

        Ok(Self {
            audit_logger: Arc::new(audit_logger),
            config: Arc::new(config),
            rules: Arc::new(rules),
            error_log,
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
        let mut tx = Transaction::with_config(id, Arc::clone(&self.config));
        tx.set_audit_logger(Arc::clone(&self.audit_logger));
        if let Some(error_log) = &self.error_log {
            tx.set_error_log(error_log.clone());
        }

        // Share rules reference for CTL tag/msg-based exclusions
        tx.set_rules(Arc::clone(&self.rules));

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
    /// let config = WafConfig {
    ///     rule_engine: RuleEngineStatus::DetectionOnly,
    ///     ..WafConfig::default()
    /// };
    /// let waf = Waf::new(config).unwrap();
    ///
    /// assert_eq!(waf.config().rule_engine, RuleEngineStatus::DetectionOnly);
    /// ```
    pub fn config(&self) -> &WafConfig {
        &self.config
    }

    /// Returns the number of top-level rules; chained rules count with their parent.
    pub fn rule_count(&self) -> usize {
        self.rules.count()
    }

    /// Finds a top-level rule by its ID, for tests to check how directives compiled.
    #[cfg(test)]
    pub(crate) fn find_rule_by_id(&self, id: i32) -> Option<&crate::rules::Rule> {
        self.rules.find_by_id(id)
    }
}

impl Default for Waf {
    /// Creates a new WAF with default configuration.
    fn default() -> Self {
        Self::new(WafConfig::default()).expect("Default config should be valid")
    }
}

/// Validates the WAF configuration.
///
/// Checks for:
/// - Valid body limits (positive, within reasonable bounds)
/// - Valid timeout values
/// - Valid log levels
/// - An upload directory for uploads that are kept
fn validate_config(config: &WafConfig) -> Result<(), ConfigError> {
    // Validate body limits
    if config.request_body_limit < 0 {
        return Err(ConfigError::new("Request body limit must be non-negative"));
    }

    if config.response_body_limit < 0 {
        return Err(ConfigError::new("Response body limit must be non-negative"));
    }

    if config.request_body_in_memory_limit < 0 {
        return Err(ConfigError::new(
            "Request body in-memory limit must be non-negative",
        ));
    }

    // Validate collection timeout
    if config.collection_timeout < 0 {
        return Err(ConfigError::new("Collection timeout must be non-negative"));
    }

    // Validate debug log level
    if config.debug_log_level > 9 {
        return Err(ConfigError::new("Debug log level must be between 0 and 9"));
    }

    // Validate argument limit
    if config.argument_limit == 0 {
        return Err(ConfigError::new("Argument limit must be greater than 0"));
    }

    // As in Go Coraza: kept files would otherwise pile up in the temporary directory
    if config.upload_keep_files && config.upload_dir.is_empty() {
        return Err(ConfigError::new(
            "SecUploadDir is required when SecUploadKeepFiles is enabled",
        ));
    }

    Ok(())
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
        assert_eq!(waf.config().rule_engine, RuleEngineStatus::On);
    }

    #[test]
    fn test_waf_config_access() {
        let config = WafConfig {
            rule_engine: RuleEngineStatus::DetectionOnly,
            request_body_limit: 2097152,
            ..WafConfig::default()
        };

        let waf = Waf::new(config).unwrap();

        assert_eq!(waf.config().rule_engine, RuleEngineStatus::DetectionOnly);
        assert_eq!(waf.config().request_body_limit, 2097152);
    }

    #[test]
    fn test_waf_new_transaction() {
        let waf = Waf::default();
        let tx = waf.new_transaction();

        // Transaction should inherit WAF config
        assert_eq!(tx.rule_engine(), waf.config().rule_engine);
    }

    #[test]
    fn test_waf_new_transaction_with_id() {
        let waf = Waf::default();
        let tx = waf.new_transaction_with_id("custom-123".to_string());

        assert_eq!(tx.id(), "custom-123");
    }

    #[test]
    fn test_waf_transaction_inherits_config() {
        let config = WafConfig {
            rule_engine: RuleEngineStatus::DetectionOnly,
            request_body_access: true,
            request_body_limit: 1048576,
            response_body_access: true,
            response_body_limit: 2097152,
            ..WafConfig::default()
        };

        let waf = Waf::new(config).unwrap();
        let tx = waf.new_transaction();

        assert_eq!(tx.rule_engine(), RuleEngineStatus::DetectionOnly);
        assert!(tx.request_body_access());
        assert_eq!(tx.settings.request_body_limit, 1048576);
        assert!(tx.response_body_access());
        assert_eq!(tx.settings.response_body_limit, 2097152);
    }

    #[test]
    fn test_waf_rule_count_initially_zero() {
        let waf = Waf::default();
        assert_eq!(waf.rule_count(), 0);
    }

    #[test]
    fn test_waf_validate_negative_request_body_limit() {
        let config = WafConfig {
            request_body_limit: -1,
            ..WafConfig::default()
        };
        let result = Waf::new(config);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid WAF configuration: Request body limit must be non-negative"
        );
    }

    #[test]
    fn test_waf_validate_negative_response_body_limit() {
        let config = WafConfig {
            response_body_limit: -1,
            ..WafConfig::default()
        };
        let result = Waf::new(config);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid WAF configuration: Response body limit must be non-negative"
        );
    }

    #[test]
    fn test_waf_validate_negative_collection_timeout() {
        let config = WafConfig {
            collection_timeout: -1,
            ..WafConfig::default()
        };
        let result = Waf::new(config);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid WAF configuration: Collection timeout must be non-negative"
        );
    }

    #[test]
    fn test_waf_validate_invalid_debug_log_level() {
        let config = WafConfig {
            debug_log_level: 10,
            ..WafConfig::default()
        };
        let result = Waf::new(config);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid WAF configuration: Debug log level must be between 0 and 9"
        );
    }

    #[test]
    fn test_waf_validate_zero_argument_limit() {
        let config = WafConfig {
            argument_limit: 0,
            ..WafConfig::default()
        };
        let result = Waf::new(config);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid WAF configuration: Argument limit must be greater than 0"
        );
    }

    #[test]
    fn test_waf_validate_valid_config() {
        let config = WafConfig {
            request_body_limit: 1048576,
            response_body_limit: 524288,
            collection_timeout: 3600,
            debug_log_level: 5,
            argument_limit: 500,
            ..WafConfig::default()
        };

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
}
