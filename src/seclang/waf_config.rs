// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! WAF configuration managed by SecLang parser.
//!
//! This module provides the WafConfig struct that holds all configuration
//! set by SecLang directives. During parsing, directives modify this config
//! which is then used to create the final WAF instance.

use crate::types::{BodyLimitAction, RuleEngineStatus};

/// Audit engine status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEngineStatus {
    /// Audit logging is disabled
    Off,
    /// Audit logging is enabled for all transactions
    On,
    /// Audit logging is enabled only for relevant transactions (those that trigger rules)
    RelevantOnly,
}

/// WAF configuration
///
/// Holds all configuration options that can be set via SecLang directives.
/// This is a mutable config object that gets populated during parsing.
///
/// # Example
///
/// ```
/// use coraza::seclang::WafConfig;
/// use coraza::RuleEngineStatus;
///
/// let mut config = WafConfig::new();
/// config.rule_engine = RuleEngineStatus::On;
/// config.request_body_access = true;
/// ```
#[derive(Debug, Clone)]
pub struct WafConfig {
    /// Defines if rules are going to be evaluated
    pub rule_engine: RuleEngineStatus,

    /// If true, transactions will have access to the request body
    pub request_body_access: bool,

    /// Request body page file limit (in bytes)
    pub request_body_limit: i64,

    /// If true, transactions will have access to the response body
    pub response_body_access: bool,

    /// Response body memory limit (in bytes)
    pub response_body_limit: i64,

    /// Request body limit action (Reject or ProcessPartial)
    pub request_body_limit_action: BodyLimitAction,

    /// Response body limit action (Reject or ProcessPartial)
    pub response_body_limit_action: BodyLimitAction,

    /// Web Application id, apps sharing the same id will share persistent collections
    pub web_app_id: String,

    /// Add significant rule components to audit log
    pub component_names: Vec<String>,

    /// Debug log level (0-9)
    pub debug_log_level: u8,

    /// Instructs the waf to change the Server response header
    pub server_signature: String,

    /// Sensor ID identifies the sensor in a cluster
    pub sensor_id: String,

    /// Path to store data files (ex. cache)
    pub data_dir: String,

    /// Maximum number of ARGS that will be accepted for processing
    pub argument_limit: usize,

    /// Request body in-memory limit (bytes stored in memory before writing to disk)
    pub request_body_in_memory_limit: i64,

    /// Request body limit excluding files (bytes for non-file fields)
    pub request_body_no_files_limit: i64,

    /// Directory where uploaded files will be stored
    pub upload_dir: String,

    /// Maximum number of uploaded files that will be processed
    pub upload_file_limit: usize,

    /// File mode (permissions) for uploaded files (e.g., 0600)
    pub upload_file_mode: u32,

    /// If On, uploaded files will be kept after transaction
    pub upload_keep_files: bool,

    /// Audit engine status (On/Off/RelevantOnly)
    pub audit_engine: AuditEngineStatus,

    /// Path to audit log file
    pub audit_log: String,

    /// Collection timeout in seconds (for IP/SESSION/USER collections)
    pub collection_timeout: i64,
}

impl WafConfig {
    /// Create a new WAF configuration with default values
    pub fn new() -> Self {
        Self {
            rule_engine: RuleEngineStatus::Off,
            request_body_access: false,
            request_body_limit: 128 * 1024 * 1024, // 128 MiB
            response_body_access: false,
            response_body_limit: 512 * 1024, // 512 KiB
            request_body_limit_action: BodyLimitAction::Reject,
            response_body_limit_action: BodyLimitAction::Reject,
            web_app_id: String::new(),
            component_names: Vec::new(),
            debug_log_level: 0,
            server_signature: String::new(),
            sensor_id: String::new(),
            data_dir: String::new(),
            argument_limit: 1000,
            request_body_in_memory_limit: 128 * 1024, // 128 KiB
            request_body_no_files_limit: 64 * 1024,   // 64 KiB
            upload_dir: "/tmp".to_string(),
            upload_file_limit: 100,
            upload_file_mode: 0o600,
            upload_keep_files: false,
            audit_engine: AuditEngineStatus::Off,
            audit_log: String::new(),
            collection_timeout: 3600, // 1 hour
        }
    }

    /// Set debug log level (0-9)
    ///
    /// Returns error if level is out of range.
    pub fn set_debug_log_level(&mut self, level: u8) -> Result<(), String> {
        if level > 9 {
            return Err(format!("debug log level must be 0-9, got {}", level));
        }
        self.debug_log_level = level;
        Ok(())
    }
}

impl Default for WafConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_waf_config_new() {
        let config = WafConfig::new();
        assert_eq!(config.rule_engine, RuleEngineStatus::Off);
        assert!(!config.request_body_access);
        assert_eq!(config.request_body_limit, 128 * 1024 * 1024);
        assert!(!config.response_body_access);
        assert_eq!(config.response_body_limit, 512 * 1024);
        assert_eq!(config.web_app_id, "");
        assert_eq!(config.debug_log_level, 0);
    }

    #[test]
    fn test_waf_config_default() {
        let config = WafConfig::default();
        assert_eq!(config.rule_engine, RuleEngineStatus::Off);
    }

    #[test]
    fn test_set_debug_log_level_valid() {
        let mut config = WafConfig::new();
        assert!(config.set_debug_log_level(0).is_ok());
        assert_eq!(config.debug_log_level, 0);

        assert!(config.set_debug_log_level(5).is_ok());
        assert_eq!(config.debug_log_level, 5);

        assert!(config.set_debug_log_level(9).is_ok());
        assert_eq!(config.debug_log_level, 9);
    }

    #[test]
    fn test_set_debug_log_level_invalid() {
        let mut config = WafConfig::new();
        let result = config.set_debug_log_level(10);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be 0-9"));
    }
}
