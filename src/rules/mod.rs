// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Rule engine for evaluating WAF rules.
//!
//! The rule engine implements the core evaluation logic that ties together:
//! - Variable extraction from transaction state
//! - Transformation pipelines
//! - Operator matching
//! - Action execution
//! - Rule chaining
//!
//! # Rule Evaluation Flow
//!
//! 1. **Variable Extraction** - Extract values from transaction collections based on
//!    variable specifications (with support for regex keys, exceptions, and count mode)
//! 2. **Transformations** - Apply transformation chain to each extracted value
//! 3. **Operator Matching** - Test transformed values against the operator
//! 4. **Action Execution** - Execute actions if the operator matches
//! 5. **Chain Evaluation** - Recursively evaluate chained rules (AND logic)
//!
//! # Example
//!
//! ```text
//! SecRule ARGS "@rx attack" "id:1,deny,log,msg:'Attack detected'"
//!
//! Flow:
//! 1. Extract ARGS values
//! 2. Apply transformations (if any)
//! 3. Test against @rx operator
//! 4. If match: execute deny, log, and msg actions
//! ```

pub mod variable;

pub use variable::{VariableException, VariableKey, VariableSpec};
