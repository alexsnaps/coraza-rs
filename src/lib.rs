// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Coraza - Web Application Firewall
//!
//! Coraza is a Rust port of the OWASP Coraza Web Application Firewall.
//! It is an enterprise-grade, high-performance WAF that supports ModSecurity
//! SecLang rulesets and is 100% compatible with the OWASP Core Rule Set v4.

pub mod collection;
pub mod operators;
pub mod transaction;
pub mod transformations;
pub mod types;
pub mod utils;

// Re-export commonly used types
pub use types::{
    AuditEngineStatus, AuditLogPart, AuditLogParts, BodyLimitAction, RuleEngineStatus, RulePhase,
    RuleSeverity, RuleVariable, apply_audit_log_parts, parse_audit_log_parts,
};

// Re-export operator trait and functions
pub use operators::{
    Operator,
    // Simple operators
    eq, gt, ge, lt, le, streq, contains, begins_with, ends_with,
    // Pattern operators
    rx, pm, within, strmatch,
    // IP operators
    ip_match,
};
