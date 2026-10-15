// Copyright 2024 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

//! WAF configuration.
//!
//! [`WafConfig`] holds every setting a WAF instance can be configured with, whether
//! set programmatically or by SecLang directives through [`crate::seclang::Parser`].

use crate::types::{
    AuditEngineStatus, AuditLogFormat, AuditLogPart, AuditLogParts, AuditLogType, BodyLimitAction,
    RuleEngineStatus,
};

/// Default maximum number of arguments per collection (`SecArgumentsLimit`), as in Go
/// Coraza.
pub const DEFAULT_ARGUMENT_LIMIT: usize = 1000;

/// Default deepest nesting of a JSON body (`SecRequestBodyJsonDepthLimit` and
/// `SecResponseBodyJsonDepthLimit`), as in Go Coraza.
pub const DEFAULT_JSON_DEPTH_LIMIT: usize = 1024;

/// Configuration for a WAF instance.
///
/// A plain set of settings: build one with struct-update syntax over [`Default`], or let
/// the SecLang parser fill it in. Values are validated when the WAF is created
/// ([`crate::waf::Waf::new`]).
///
/// # Examples
///
/// ```
/// use coraza::config::WafConfig;
/// use coraza::RuleEngineStatus;
///
/// let config = WafConfig {
///     rule_engine: RuleEngineStatus::DetectionOnly,
///     request_body_access: true,
///     request_body_limit: 1048576,
///     ..WafConfig::default()
/// };
///
/// assert_eq!(config.rule_engine, RuleEngineStatus::DetectionOnly);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WafConfig {
    /// Whether rules are evaluated, and whether disruptive actions apply (`SecRuleEngine`).
    pub rule_engine: RuleEngineStatus,

    /// Whether transactions buffer and inspect the request body (`SecRequestBodyAccess`).
    pub request_body_access: bool,

    /// Maximum request body size, in bytes (`SecRequestBodyLimit`).
    pub request_body_limit: i64,

    /// Request body bytes kept in memory before spilling to disk (`SecRequestBodyInMemoryLimit`).
    pub request_body_in_memory_limit: i64,

    /// Maximum request body size excluding uploaded files, in bytes (`SecRequestBodyNoFilesLimit`).
    pub request_body_no_files_limit: i64,

    /// What happens when the request body exceeds its limit (`SecRequestBodyLimitAction`).
    pub request_body_limit_action: BodyLimitAction,

    /// Whether transactions buffer and inspect the response body (`SecResponseBodyAccess`).
    pub response_body_access: bool,

    /// Maximum response body size, in bytes (`SecResponseBodyLimit`).
    pub response_body_limit: i64,

    /// What happens when the response body exceeds its limit (`SecResponseBodyLimitAction`).
    pub response_body_limit_action: BodyLimitAction,

    /// Response content types, without parameters, whose body is inspected; none by
    /// default, as in Go Coraza (`SecResponseBodyMimeType`). See
    /// [`crate::transaction::Transaction::is_response_body_processable`].
    pub response_body_mime_types: Vec<String>,

    /// Deepest nesting of objects and arrays a JSON request body may have
    /// (`SecRequestBodyJsonDepthLimit`).
    pub request_body_json_depth_limit: usize,

    /// Deepest nesting of objects and arrays a JSON response body may have
    /// (`SecResponseBodyJsonDepthLimit`).
    pub response_body_json_depth_limit: usize,

    /// Audit logging mode (`SecAuditEngine`).
    pub audit_engine: AuditEngineStatus,

    /// Path of the audit log file; empty when unset (`SecAuditLog`).
    pub audit_log: String,

    // The library writes no audit log: the audit log settings are for the embedder.
    /// Format of audit log entries (`SecAuditLogFormat`).
    pub audit_log_format: AuditLogFormat,

    /// Parts each audit log entry holds, `A` and `Z` included (`SecAuditLogParts`).
    pub audit_log_parts: AuditLogParts,

    /// Where audit log entries are written (`SecAuditLogType`).
    pub audit_log_type: AuditLogType,

    /// Regular expression of the response statuses that make a transaction relevant to
    /// `SecAuditEngine RelevantOnly`; empty for none (`SecAuditLogRelevantStatus`).
    pub audit_log_relevant_status: String,

    /// Lifetime of persistent collection entries, in seconds (`SecCollectionTimeout`).
    pub collection_timeout: i64,

    /// Debug log verbosity, 0 to 9 inclusive (`SecDebugLogLevel`).
    pub debug_log_level: u8,

    /// Maximum number of ARGS processed per transaction (`SecArgumentsLimit`).
    pub argument_limit: usize,

    /// Application id; apps sharing it share persistent collections (`SecWebAppId`).
    pub web_app_id: String,

    /// Identifies this sensor in a cluster (`SecSensorId`).
    pub sensor_id: String,

    /// Value for the `Server` response header; empty leaves it untouched (`SecServerSignature`).
    pub server_signature: String,

    /// Component signatures appended to the WAF signature (`SecComponentSignature`).
    pub component_names: Vec<String>,

    /// Directory for persistent data (`SecDataDir`).
    pub data_dir: String,

    /// Directory where uploaded files are stored (`SecUploadDir`).
    pub upload_dir: String,

    /// Maximum number of uploaded files processed per transaction (`SecUploadFileLimit`).
    pub upload_file_limit: usize,

    /// Permission bits for stored uploaded files, e.g. `0o600` (`SecUploadFileMode`).
    pub upload_file_mode: u32,

    /// Whether uploaded files are kept after the transaction ends (`SecUploadKeepFiles`).
    pub upload_keep_files: bool,
}

impl Default for WafConfig {
    /// Defaults match the Go implementation.
    fn default() -> Self {
        Self {
            rule_engine: RuleEngineStatus::On,
            request_body_access: false,
            request_body_limit: 128 * 1024 * 1024,
            request_body_in_memory_limit: 128 * 1024,
            request_body_no_files_limit: 64 * 1024,
            request_body_limit_action: BodyLimitAction::Reject,
            response_body_access: false,
            response_body_limit: 512 * 1024,
            response_body_limit_action: BodyLimitAction::Reject,
            response_body_mime_types: Vec::new(),
            request_body_json_depth_limit: DEFAULT_JSON_DEPTH_LIMIT,
            response_body_json_depth_limit: DEFAULT_JSON_DEPTH_LIMIT,
            audit_engine: AuditEngineStatus::Off,
            audit_log: String::new(),
            audit_log_format: AuditLogFormat::Native,
            audit_log_parts: vec![
                AuditLogPart::Header,
                AuditLogPart::RequestHeaders,
                AuditLogPart::RequestBody,
                AuditLogPart::ResponseHeaders,
                AuditLogPart::Trailer,
                AuditLogPart::EndMarker,
            ],
            audit_log_type: AuditLogType::Serial,
            audit_log_relevant_status: String::new(),
            collection_timeout: 3600,
            debug_log_level: 0,
            argument_limit: DEFAULT_ARGUMENT_LIMIT,
            web_app_id: String::new(),
            sensor_id: String::new(),
            server_signature: String::new(),
            component_names: Vec::new(),
            data_dir: String::new(),
            upload_dir: "/tmp".to_string(),
            upload_file_limit: 100,
            upload_file_mode: 0o600,
            upload_keep_files: false,
        }
    }
}

impl WafConfig {
    /// Creates a configuration with default values; same as [`WafConfig::default`].
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = WafConfig::default();
        assert_eq!(config.rule_engine, RuleEngineStatus::On);
        assert_eq!(config.request_body_limit, 134217728);
        assert_eq!(config.response_body_limit, 524288);
        assert_eq!(config.audit_engine, AuditEngineStatus::Off);
        assert_eq!(config.argument_limit, 1000);
    }

    #[test]
    fn test_config_new_is_default() {
        assert_eq!(WafConfig::new(), WafConfig::default());
    }
}
