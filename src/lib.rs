// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Coraza - Web Application Firewall
//!
//! Coraza is a Rust port of the OWASP Coraza Web Application Firewall.
//! It is an enterprise-grade, high-performance WAF that supports ModSecurity
//! SecLang rulesets and is 100% compatible with the OWASP Core Rule Set v4.

mod actions;
pub mod audit_log;
mod body_processors;
pub mod collection;
pub mod config;
mod operators;
mod rules;
pub mod seclang;
pub mod transaction;
mod transformations;
pub mod types;
mod utils;
pub mod waf;

// Re-export commonly used types
pub use types::{
    AuditEngineStatus, AuditLogPart, AuditLogParts, BodyLimitAction, RuleEngineStatus, RulePhase,
    RuleSeverity, RuleVariable,
};
