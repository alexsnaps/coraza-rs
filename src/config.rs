// Copyright 2024 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

//! WAF configuration builder.
//!
//! This module provides the configuration system for the WAF instance.
//! The configuration is immutable - each `with_*` method returns a new
//! configuration instance with the updated value.

use crate::types::{AuditEngineStatus, AuditLogParts, BodyLimitAction, RuleEngineStatus};

/// Configuration for a WAF instance.
///
/// WafConfig uses the builder pattern and is immutable. Each `with_*` method
/// returns a new instance with the updated configuration.
///
/// # Examples
///
/// ```
/// use coraza::config::WafConfig;
/// use coraza::RuleEngineStatus;
///
/// let config = WafConfig::new()
///     .with_rule_engine(RuleEngineStatus::On)
///     .with_request_body_limit(1048576)
///     .with_request_body_access(true);
///
/// assert_eq!(config.rule_engine(), RuleEngineStatus::On);
/// assert_eq!(config.request_body_limit(), 1048576);
/// ```
#[derive(Debug, Clone)]
pub struct WafConfig {
    /// Rule engine status (on, off, detection_only)
    rule_engine: RuleEngineStatus,

    /// Enable access to request body
    request_body_access: bool,

    /// Maximum request body size (bytes)
    request_body_limit: i64,

    /// Maximum request body in-memory size (bytes)
    request_body_in_memory_limit: i64,

    /// Action to take when request body limit is exceeded
    request_body_limit_action: BodyLimitAction,

    /// Enable access to response body
    response_body_access: bool,

    /// Maximum response body size (bytes)
    response_body_limit: i64,

    /// Action to take when response body limit is exceeded
    response_body_limit_action: BodyLimitAction,

    /// MIME types to process for response body
    response_body_mime_types: Vec<String>,

    /// Audit logging engine status
    audit_engine: AuditEngineStatus,

    /// Parts of the transaction to include in audit logs
    audit_log_parts: AuditLogParts,

    /// Audit log format (Native, JSON, etc.)
    audit_log_format: String,

    /// Path for audit log files
    audit_log_path: String,

    /// Collection timeout in seconds
    collection_timeout: i64,

    /// Debug log level (0-9)
    debug_log_level: i32,

    /// Temporary directory for file uploads
    tmp_dir: String,

    /// Argument separator character
    argument_separator: String,

    /// Maximum number of arguments to process
    argument_limit: usize,

    /// Web application ID (for persistent collections)
    web_app_id: String,

    /// Sensor ID (for clustering)
    sensor_id: String,
}

impl Default for WafConfig {
    /// Creates a new WafConfig with default values.
    ///
    /// Defaults match the Go implementation:
    /// - Rule engine: On
    /// - Request body limit: 128 MB
    /// - Response body limit: 512 KB
    /// - Audit engine: Off
    /// - Argument limit: 1000
    fn default() -> Self {
        Self {
            rule_engine: RuleEngineStatus::On,
            request_body_access: false,
            request_body_limit: 134217728, // 128 MB
            request_body_in_memory_limit: 134217728,
            request_body_limit_action: BodyLimitAction::Reject,
            response_body_access: false,
            response_body_limit: 524288, // 512 KB
            response_body_limit_action: BodyLimitAction::Reject,
            response_body_mime_types: Vec::new(),
            audit_engine: AuditEngineStatus::Off,
            audit_log_parts: AuditLogParts::default(),
            audit_log_format: "Native".to_string(),
            audit_log_path: String::new(),
            collection_timeout: 3600, // 1 hour
            debug_log_level: 0,
            tmp_dir: std::env::temp_dir().to_string_lossy().to_string(),
            argument_separator: "&".to_string(),
            argument_limit: 1000,
            web_app_id: String::new(),
            sensor_id: String::new(),
        }
    }
}

impl WafConfig {
    /// Creates a new WafConfig with default values.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::config::WafConfig;
    ///
    /// let config = WafConfig::new();
    /// assert_eq!(config.request_body_limit(), 134217728);
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    // ===== Builder methods =====

    /// Sets the rule engine status.
    pub fn with_rule_engine(mut self, status: RuleEngineStatus) -> Self {
        self.rule_engine = status;
        self
    }

    /// Enables request body access.
    pub fn with_request_body_access(mut self, enabled: bool) -> Self {
        self.request_body_access = enabled;
        self
    }

    /// Sets the request body size limit in bytes.
    pub fn with_request_body_limit(mut self, limit: i64) -> Self {
        self.request_body_limit = limit;
        self
    }

    /// Sets the request body in-memory size limit in bytes.
    pub fn with_request_body_in_memory_limit(mut self, limit: i64) -> Self {
        self.request_body_in_memory_limit = limit;
        self
    }

    /// Sets the action to take when request body limit is exceeded.
    pub fn with_request_body_limit_action(mut self, action: BodyLimitAction) -> Self {
        self.request_body_limit_action = action;
        self
    }

    /// Enables response body access.
    pub fn with_response_body_access(mut self, enabled: bool) -> Self {
        self.response_body_access = enabled;
        self
    }

    /// Sets the response body size limit in bytes.
    pub fn with_response_body_limit(mut self, limit: i64) -> Self {
        self.response_body_limit = limit;
        self
    }

    /// Sets the action to take when response body limit is exceeded.
    pub fn with_response_body_limit_action(mut self, action: BodyLimitAction) -> Self {
        self.response_body_limit_action = action;
        self
    }

    /// Sets the MIME types to process for response body.
    pub fn with_response_body_mime_types(mut self, mime_types: Vec<String>) -> Self {
        self.response_body_mime_types = mime_types;
        self
    }

    /// Sets the audit engine status.
    pub fn with_audit_engine(mut self, status: AuditEngineStatus) -> Self {
        self.audit_engine = status;
        self
    }

    /// Sets the parts of the transaction to include in audit logs.
    pub fn with_audit_log_parts(mut self, parts: AuditLogParts) -> Self {
        self.audit_log_parts = parts;
        self
    }

    /// Sets the audit log format.
    pub fn with_audit_log_format(mut self, format: String) -> Self {
        self.audit_log_format = format;
        self
    }

    /// Sets the audit log file path.
    pub fn with_audit_log_path(mut self, path: String) -> Self {
        self.audit_log_path = path;
        self
    }

    /// Sets the collection timeout in seconds.
    pub fn with_collection_timeout(mut self, timeout: i64) -> Self {
        self.collection_timeout = timeout;
        self
    }

    /// Sets the debug log level (0-9).
    pub fn with_debug_log_level(mut self, level: i32) -> Self {
        self.debug_log_level = level;
        self
    }

    /// Sets the temporary directory for file uploads.
    pub fn with_tmp_dir(mut self, dir: String) -> Self {
        self.tmp_dir = dir;
        self
    }

    /// Sets the argument separator character.
    pub fn with_argument_separator(mut self, separator: String) -> Self {
        self.argument_separator = separator;
        self
    }

    /// Sets the maximum number of arguments to process.
    pub fn with_argument_limit(mut self, limit: usize) -> Self {
        self.argument_limit = limit;
        self
    }

    /// Sets the web application ID.
    pub fn with_web_app_id(mut self, id: String) -> Self {
        self.web_app_id = id;
        self
    }

    /// Sets the sensor ID.
    pub fn with_sensor_id(mut self, id: String) -> Self {
        self.sensor_id = id;
        self
    }

    // ===== Getter methods =====

    pub fn rule_engine(&self) -> RuleEngineStatus {
        self.rule_engine
    }

    pub fn request_body_access(&self) -> bool {
        self.request_body_access
    }

    pub fn request_body_limit(&self) -> i64 {
        self.request_body_limit
    }

    pub fn request_body_in_memory_limit(&self) -> i64 {
        self.request_body_in_memory_limit
    }

    pub fn request_body_limit_action(&self) -> BodyLimitAction {
        self.request_body_limit_action
    }

    pub fn response_body_access(&self) -> bool {
        self.response_body_access
    }

    pub fn response_body_limit(&self) -> i64 {
        self.response_body_limit
    }

    pub fn response_body_limit_action(&self) -> BodyLimitAction {
        self.response_body_limit_action
    }

    pub fn response_body_mime_types(&self) -> &[String] {
        &self.response_body_mime_types
    }

    pub fn audit_engine(&self) -> AuditEngineStatus {
        self.audit_engine
    }

    pub fn audit_log_parts(&self) -> &AuditLogParts {
        &self.audit_log_parts
    }

    pub fn audit_log_format(&self) -> &str {
        &self.audit_log_format
    }

    pub fn audit_log_path(&self) -> &str {
        &self.audit_log_path
    }

    pub fn collection_timeout(&self) -> i64 {
        self.collection_timeout
    }

    pub fn debug_log_level(&self) -> i32 {
        self.debug_log_level
    }

    pub fn tmp_dir(&self) -> &str {
        &self.tmp_dir
    }

    pub fn argument_separator(&self) -> &str {
        &self.argument_separator
    }

    pub fn argument_limit(&self) -> usize {
        self.argument_limit
    }

    pub fn web_app_id(&self) -> &str {
        &self.web_app_id
    }

    pub fn sensor_id(&self) -> &str {
        &self.sensor_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = WafConfig::default();
        assert_eq!(config.rule_engine(), RuleEngineStatus::On);
        assert_eq!(config.request_body_limit(), 134217728);
        assert_eq!(config.response_body_limit(), 524288);
        assert_eq!(config.audit_engine(), AuditEngineStatus::Off);
        assert_eq!(config.argument_limit(), 1000);
    }

    #[test]
    fn test_config_new() {
        let config = WafConfig::new();
        assert_eq!(config.rule_engine(), RuleEngineStatus::On);
    }

    #[test]
    fn test_config_builder() {
        let config = WafConfig::new()
            .with_rule_engine(RuleEngineStatus::DetectionOnly)
            .with_request_body_limit(1048576)
            .with_response_body_limit(2097152)
            .with_audit_engine(AuditEngineStatus::On);

        assert_eq!(config.rule_engine(), RuleEngineStatus::DetectionOnly);
        assert_eq!(config.request_body_limit(), 1048576);
        assert_eq!(config.response_body_limit(), 2097152);
        assert_eq!(config.audit_engine(), AuditEngineStatus::On);
    }

    #[test]
    fn test_config_request_body_access() {
        let config = WafConfig::new().with_request_body_access(true);
        assert!(config.request_body_access());
    }

    #[test]
    fn test_config_response_body_access() {
        let config = WafConfig::new().with_response_body_access(true);
        assert!(config.response_body_access());
    }

    #[test]
    fn test_config_mime_types() {
        let mime_types = vec!["text/html".to_string(), "application/json".to_string()];
        let config = WafConfig::new().with_response_body_mime_types(mime_types.clone());
        assert_eq!(config.response_body_mime_types(), &mime_types);
    }

    #[test]
    fn test_config_collection_timeout() {
        let config = WafConfig::new().with_collection_timeout(7200);
        assert_eq!(config.collection_timeout(), 7200);
    }

    #[test]
    fn test_config_debug_log_level() {
        let config = WafConfig::new().with_debug_log_level(5);
        assert_eq!(config.debug_log_level(), 5);
    }

    #[test]
    fn test_config_tmp_dir() {
        let config = WafConfig::new().with_tmp_dir("/custom/tmp".to_string());
        assert_eq!(config.tmp_dir(), "/custom/tmp");
    }

    #[test]
    fn test_config_argument_limit() {
        let config = WafConfig::new().with_argument_limit(500);
        assert_eq!(config.argument_limit(), 500);
    }

    #[test]
    fn test_config_web_app_id() {
        let config = WafConfig::new().with_web_app_id("my-app".to_string());
        assert_eq!(config.web_app_id(), "my-app");
    }

    #[test]
    fn test_config_sensor_id() {
        let config = WafConfig::new().with_sensor_id("sensor-1".to_string());
        assert_eq!(config.sensor_id(), "sensor-1");
    }

    #[test]
    fn test_config_chaining() {
        let config = WafConfig::new()
            .with_rule_engine(RuleEngineStatus::On)
            .with_request_body_access(true)
            .with_request_body_limit(2097152)
            .with_response_body_access(true)
            .with_response_body_limit(1048576)
            .with_audit_engine(AuditEngineStatus::RelevantOnly)
            .with_debug_log_level(3);

        assert_eq!(config.rule_engine(), RuleEngineStatus::On);
        assert!(config.request_body_access());
        assert_eq!(config.request_body_limit(), 2097152);
        assert!(config.response_body_access());
        assert_eq!(config.response_body_limit(), 1048576);
        assert_eq!(config.audit_engine(), AuditEngineStatus::RelevantOnly);
        assert_eq!(config.debug_log_level(), 3);
    }
}
