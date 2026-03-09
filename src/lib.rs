// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Coraza - Web Application Firewall
//!
//! Coraza is a Rust port of the OWASP Coraza Web Application Firewall.
//! It is an enterprise-grade, high-performance WAF that supports ModSecurity
//! SecLang rulesets and is 100% compatible with the OWASP Core Rule Set v4.

pub mod types;

// Re-export commonly used types
pub use types::{
    AuditEngineStatus, AuditLogPart, BodyLimitAction, RuleEngineStatus, RulePhase, RuleSeverity,
    RuleVariable,
};
