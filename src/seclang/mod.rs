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
//! - 66 different directive types (SecRule, SecAction, SecRuleEngine, etc.)
//!
//! # Example
//!
//! ```
//! use coraza::seclang::Parser;
//!
//! // let waf = Waf::new();
//! // let mut parser = Parser::new(&waf);
//! //
//! // // Parse a SecRule directive
//! // parser.from_string(r#"
//! //     SecRule ARGS "@rx attack" "id:1,deny,log"
//! // "#)?;
//! //
//! // // Parse from file
//! // parser.from_file("/etc/coraza/rules.conf")?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod action_parser;
pub mod operator_parser;
pub mod parser;
pub mod variable_parser;
pub mod waf_config;

pub use action_parser::parse_actions;
pub use operator_parser::parse_operator;
pub use parser::Parser;
pub use variable_parser::parse_variables;
pub use waf_config::WafConfig;
