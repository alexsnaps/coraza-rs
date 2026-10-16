// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! SecLang parser for ModSecurity rule language.
//!
//! This module provides parsing and compilation of SecLang directives (ModSecurity
//! configuration language) into executable Rule structures.
//!
//! # Overview
//!
//! The parser processes SecLang directives line-by-line:
//! - Line continuations (`\` at end of line)
//! - Comments (`#` lines)
//! - Multi-line backtick blocks for SecDataset
//! - Rule directives (SecRule, SecAction, SecMarker) and engine configuration directives
//!
//! # Example
//!
//! ```
//! use coraza::seclang::Parser;
//!
//! let mut parser = Parser::new();
//! parser.from_string(r#"
//!     SecRuleEngine On
//!     SecRule ARGS "@rx attack" "id:1,phase:1,deny,log"
//! "#)?;
//! // or: parser.from_file("/etc/coraza/rules.conf")?;
//!
//! let waf = parser.into_waf()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod action_parser;
mod operator_parser;
pub mod parser;
mod rule_compiler;
mod variable_parser;

use crate::actions::ActionError;

pub(crate) use action_parser::parse_actions;
pub use parser::Parser;
/// For tests that compile rules from SecLang, as the parser does but without its context
#[cfg(test)]
pub(crate) use rule_compiler::{compile_sec_action, compile_sec_marker, compile_sec_rule};
pub(crate) use variable_parser::parse_variables;

/// Why a directive's argument could not be compiled (variables, operator, actions or
/// marker); [`crate::seclang::parser::ParseError`] adds where it occurred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    pub message: String,
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CompileError {}

impl CompileError {
    pub(crate) fn new(message: String) -> Self {
        Self { message }
    }
}

impl From<String> for CompileError {
    fn from(message: String) -> Self {
        Self { message }
    }
}

impl From<ActionError> for CompileError {
    fn from(err: ActionError) -> Self {
        Self {
            message: format!("action error: {}", err),
        }
    }
}
