// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Coraza - Web Application Firewall
//!
//! Coraza is a Rust port of the OWASP Coraza Web Application Firewall.
//! It is an enterprise-grade, high-performance WAF that supports ModSecurity
//! SecLang rulesets and is 100% compatible with the OWASP Core Rule Set v4.

pub mod actions;
pub mod body_processors;
pub mod collection;
pub mod config;
pub mod operators;
pub mod rules;
pub mod seclang;
pub mod transaction;
pub mod transformations;
pub mod types;
pub mod utils;
pub mod waf;

// Re-export commonly used types
pub use types::{
    AuditEngineStatus, AuditLogPart, AuditLogParts, BodyLimitAction, RuleEngineStatus, RulePhase,
    RuleSeverity, RuleVariable, apply_audit_log_parts, parse_audit_log_parts,
};

// Re-export operator trait and functions
pub use operators::{
    Operator,
    begins_with,
    contains,
    ends_with,
    // Simple operators
    eq,
    ge,
    gt,
    // IP operators
    ip_match,
    le,
    lt,
    pm,
    // Pattern operators
    rx,
    streq,
    strmatch,
    within,
};
