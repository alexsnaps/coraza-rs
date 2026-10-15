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

pub mod action_parser;
pub mod operator_parser;
pub mod parser;
pub mod rule_compiler;
pub mod variable_parser;

pub use action_parser::parse_actions;
pub use operator_parser::parse_operator;
pub use parser::Parser;
pub use rule_compiler::{compile_sec_action, compile_sec_marker, compile_sec_rule};
pub use variable_parser::parse_variables;
