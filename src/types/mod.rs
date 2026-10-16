// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Core type definitions for Coraza WAF.
//!
//! This module contains fundamental types used throughout the WAF including
//! severity levels, processing phases, variable identifiers, and engine configuration.

mod phase;
mod severity;
mod variables;
mod waf;

use std::fmt;

pub use phase::RulePhase;
pub use severity::RuleSeverity;
pub use variables::RuleVariable;
pub use waf::{
    AuditEngineStatus, AuditLogFormat, AuditLogPart, AuditLogParts, AuditLogType, BodyLimitAction,
    RuleEngineStatus,
};
pub(crate) use waf::{apply_audit_log_parts, parse_audit_log_parts};

/// A string (or character) that names none of a type's values: a phase, severity,
/// variable, engine status or audit log part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseValueError {
    /// What was being parsed, as the message names it (e.g. `"invalid phase"`)
    expected: &'static str,
    input: String,
}

impl ParseValueError {
    pub(crate) fn new(expected: &'static str, input: impl Into<String>) -> Self {
        Self {
            expected,
            input: input.into(),
        }
    }
}

impl fmt::Display for ParseValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.expected, self.input)
    }
}

impl std::error::Error for ParseValueError {}
