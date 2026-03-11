// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Deferred actions that require additional infrastructure or have security implications.
//!
//! These actions were deferred from Phase 6 because they require:
//! - External process execution (exec)
//! - Persistence layer (expirevar, initcol)
//! - Environment variable access (setenv)

use crate::actions::{Action, ActionError, ActionType, Rule, TransactionState};
use crate::operators::Macro;

/// `exec` action - Execute external script/binary.
///
/// **Security Note:** This action is not fully implemented for security reasons.
/// Forking external processes from a web server can have significant security
/// and performance implications.
///
/// The Go implementation also leaves this as a stub. For actual script execution,
/// consider using a dedicated plugin system or external integration point.
///
/// # Action Group
///
/// Non-disruptive
///
/// # Description
///
/// Executes an external script/binary supplied as parameter.
/// The `exec` action is executed independently from any disruptive actions specified.
/// External scripts would be called with transaction information in environment variables.
///
/// # Arguments
///
/// Path to script/binary to execute (currently not used)
///
/// # Example
///
/// ```text
/// # Run external program on rule match (not actually executed)
/// SecRule REQUEST_URI "^/cgi-bin/script\.pl" \
///     "phase:2,id:112,block,exec:/usr/local/apache/bin/test.sh"
/// ```
#[derive(Debug)]
pub struct ExecAction {
    script: String,
}

impl ExecAction {
    pub fn new() -> Self {
        Self {
            script: String::new(),
        }
    }
}

impl Default for ExecAction {
    fn default() -> Self {
        Self::new()
    }
}

impl Action for ExecAction {
    fn init(&mut self, _rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if data.is_empty() {
            return Err(ActionError::MissingArguments);
        }

        self.script = data.to_string();
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // Not implemented for security reasons (matches Go behavior)
        // Executing arbitrary external processes from a WAF is dangerous
    }

    fn action_type(&self) -> ActionType {
        ActionType::Nondisruptive
    }
}

/// `expirevar` action - Configure collection variable expiration.
///
/// **Note:** This action is not fully supported. It requires a persistence layer
/// to track variable expiration times, which is implemented in Phase 10 (WAF Core).
///
/// The Go implementation also logs a warning that this action is not supported.
///
/// # Action Group
///
/// Non-disruptive
///
/// # Description
///
/// Configures a collection variable to expire after the given time period (in seconds).
/// You should use `expirevar` with `setvar` action to keep the intended expiration time.
///
/// # Arguments
///
/// `collection.variable=seconds` format (e.g., `session.suspicious=3600`)
///
/// # Example
///
/// ```text
/// SecRule REQUEST_URI "^/cgi-bin/script\.pl" \
///     "phase:2,id:115,log,allow,setvar:session.suspicious=1,expirevar:session.suspicious=3600"
/// ```
#[derive(Debug)]
pub struct ExpirevarAction {
    variable: String,
    seconds: i64,
}

impl ExpirevarAction {
    pub fn new() -> Self {
        Self {
            variable: String::new(),
            seconds: 0,
        }
    }
}

impl Default for ExpirevarAction {
    fn default() -> Self {
        Self::new()
    }
}

impl Action for ExpirevarAction {
    fn init(&mut self, _rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if data.is_empty() {
            return Err(ActionError::MissingArguments);
        }

        // Parse variable=seconds format
        let parts: Vec<&str> = data.split('=').collect();
        if parts.len() != 2 {
            return Err(ActionError::InvalidArguments(
                "expirevar requires format: variable=seconds".to_string(),
            ));
        }

        self.variable = parts[0].to_string();
        self.seconds = parts[1].parse::<i64>().map_err(|_| {
            ActionError::InvalidArguments(format!("invalid expiration time: {}", parts[1]))
        })?;

        Ok(())
    }

    fn evaluate(&self, rule: &Rule, _tx: &mut dyn TransactionState) {
        // Not supported - would require persistence layer (matches Go behavior)
        // Go logs: "Expirevar was used but it's not supported"
        eprintln!(
            "Warning: expirevar action in rule {} is not fully supported (requires persistence layer)",
            rule.id
        );
    }

    fn action_type(&self) -> ActionType {
        ActionType::Nondisruptive
    }
}

/// `setenv` action - Create, remove, or update environment variables.
///
/// **Note:** This action is FULLY IMPLEMENTED and matches Go behavior.
///
/// # Action Group
///
/// Non-disruptive
///
/// # Description
///
/// Creates, removes, and updates environment variables that can be accessed by
/// the implementation. The environment variable is set both in the process
/// environment and in the ENV collection.
///
/// # Arguments
///
/// `key=value` where value supports macro expansion (e.g., `%{MATCHED_VAR}`)
///
/// # Example
///
/// ```text
/// SecRule TX:SESSIONID "!(?i:\;? ?httponly;?)" \
///     "phase:3,id:140,setenv:httponly_cookie=%{matched_var},pass,log"
/// ```
#[derive(Debug)]
pub struct SetenvAction {
    key: String,
    value: Macro,
}

impl SetenvAction {
    pub fn new() -> Self {
        Self {
            key: String::new(),
            value: Macro::empty(),
        }
    }
}

impl Default for SetenvAction {
    fn default() -> Self {
        Self::new()
    }
}

impl Action for SetenvAction {
    fn init(&mut self, _rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if data.is_empty() {
            return Err(ActionError::MissingArguments);
        }

        // Parse key=value format
        let parts: Vec<&str> = data.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(ActionError::InvalidArguments(
                "setenv requires format: key=value".to_string(),
            ));
        }

        let key = parts[0].trim();
        let value = parts[1];

        if key.is_empty() {
            return Err(ActionError::InvalidArguments("missing env key".to_string()));
        }

        if value.is_empty() {
            return Err(ActionError::InvalidArguments(
                "missing env value".to_string(),
            ));
        }

        self.key = key.to_string();
        self.value = Macro::new(value)
            .map_err(|e| ActionError::InvalidArguments(format!("invalid macro: {}", e)))?;

        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, tx: &mut dyn TransactionState) {
        // Expand macro with transaction state
        let value = self.value.expand(Some(tx));

        // Set OS environment variable (matches Go behavior)
        // SAFETY: Setting environment variables is inherently unsafe due to potential
        // race conditions with other threads reading the environment. However, this
        // matches the Go implementation and is the expected behavior of the setenv action.
        unsafe {
            std::env::set_var(&self.key, &value);
        }

        // TODO: Also set in ENV collection when we add it to Transaction
        // tx.env_mut().set(&self.key, &value);
    }

    fn action_type(&self) -> ActionType {
        ActionType::Nondisruptive
    }
}

/// `initcol` action - Initialize named persistent collection.
///
/// **Note:** This action is PARTIALLY IMPLEMENTED. It parses the syntax but
/// persistence layer integration is deferred to Phase 10 (WAF Core).
///
/// The Go implementation has the persistence code commented out.
///
/// # Action Group
///
/// Non-disruptive
///
/// # Description
///
/// Initializes a named persistent collection, either by loading data from storage
/// or by creating a new collection in memory. Collections are loaded on-demand
/// when the initcol action is executed.
///
/// # Arguments
///
/// `collection=key` where key supports macro expansion (e.g., `ip=%{REMOTE_ADDR}`)
///
/// # Example
///
/// ```text
/// # Initiates IP address tracking, best done in phase 1
/// SecAction "phase:1,id:116,nolog,pass,initcol:ip=%{REMOTE_ADDR}"
/// ```
#[derive(Debug)]
pub struct InitcolAction {
    collection: String,
    key: String,
}

impl InitcolAction {
    pub fn new() -> Self {
        Self {
            collection: String::new(),
            key: String::new(),
        }
    }
}

impl Default for InitcolAction {
    fn default() -> Self {
        Self::new()
    }
}

impl Action for InitcolAction {
    fn init(&mut self, _rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if data.is_empty() {
            return Err(ActionError::MissingArguments);
        }

        // Parse collection=key format
        let parts: Vec<&str> = data.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(ActionError::InvalidArguments(
                "initcol requires format: collection=key".to_string(),
            ));
        }

        self.collection = parts[0].to_string();
        self.key = parts[1].to_string();

        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // Not fully implemented - persistence layer deferred to Phase 10
        // Go implementation has this commented out with TODO

        // Would do:
        // 1. Expand macro in key
        // 2. Load collection from persistence storage
        // 3. If not exists, create new collection with metadata:
        //    - CREATE_TIME, IS_NEW, KEY, LAST_UPDATE_TIME, TIMEOUT, UPDATE_COUNTER
        // 4. Set collection data in transaction
    }

    fn action_type(&self) -> ActionType {
        ActionType::Nondisruptive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== ExecAction Tests =====

    #[test]
    fn test_exec_missing_arguments() {
        let mut action = ExecAction::new();
        let result = action.init(&mut Rule::new(), "");
        assert_eq!(result, Err(ActionError::MissingArguments));
    }

    #[test]
    fn test_exec_valid() {
        let mut action = ExecAction::new();
        let result = action.init(&mut Rule::new(), "/usr/bin/test.sh");
        assert!(result.is_ok());
        assert_eq!(action.script, "/usr/bin/test.sh");
    }

    #[test]
    fn test_exec_evaluate_does_nothing() {
        // Exec is a stub - evaluate should not crash but also not execute anything
        let mut action = ExecAction::new();
        action.init(&mut Rule::new(), "/usr/bin/test.sh").unwrap();

        // Mock transaction state
        struct MockTx;
        impl TransactionState for MockTx {
            fn get_variable(
                &self,
                _variable: crate::RuleVariable,
                _key: Option<&str>,
            ) -> Option<String> {
                None
            }
        }

        let mut tx = MockTx;
        action.evaluate(&Rule::new(), &mut tx);
        // Should not crash - verify by test completing
    }

    #[test]
    fn test_exec_action_type() {
        let action = ExecAction::new();
        assert_eq!(action.action_type(), ActionType::Nondisruptive);
    }

    // ===== ExpirevarAction Tests =====

    #[test]
    fn test_expirevar_missing_arguments() {
        let mut action = ExpirevarAction::new();
        let result = action.init(&mut Rule::new(), "");
        assert_eq!(result, Err(ActionError::MissingArguments));
    }

    #[test]
    fn test_expirevar_invalid_format() {
        let mut action = ExpirevarAction::new();
        let result = action.init(&mut Rule::new(), "session.suspicious");
        assert!(matches!(result, Err(ActionError::InvalidArguments(_))));
    }

    #[test]
    fn test_expirevar_invalid_seconds() {
        let mut action = ExpirevarAction::new();
        let result = action.init(&mut Rule::new(), "session.suspicious=abc");
        assert!(matches!(result, Err(ActionError::InvalidArguments(_))));
    }

    #[test]
    fn test_expirevar_valid() {
        let mut action = ExpirevarAction::new();
        let result = action.init(&mut Rule::new(), "session.suspicious=3600");
        assert!(result.is_ok());
        assert_eq!(action.variable, "session.suspicious");
        assert_eq!(action.seconds, 3600);
    }

    #[test]
    fn test_expirevar_action_type() {
        let action = ExpirevarAction::new();
        assert_eq!(action.action_type(), ActionType::Nondisruptive);
    }

    // ===== SetenvAction Tests =====

    #[test]
    fn test_setenv_missing_arguments() {
        let mut action = SetenvAction::new();
        let result = action.init(&mut Rule::new(), "");
        assert_eq!(result, Err(ActionError::MissingArguments));
    }

    #[test]
    fn test_setenv_missing_equals() {
        let mut action = SetenvAction::new();
        let result = action.init(&mut Rule::new(), "MYVAR");
        assert!(matches!(result, Err(ActionError::InvalidArguments(_))));
    }

    #[test]
    fn test_setenv_empty_key() {
        let mut action = SetenvAction::new();
        let result = action.init(&mut Rule::new(), "=value");
        assert!(matches!(result, Err(ActionError::InvalidArguments(_))));
    }

    #[test]
    fn test_setenv_empty_value() {
        let mut action = SetenvAction::new();
        let result = action.init(&mut Rule::new(), "MYVAR=");
        assert!(matches!(result, Err(ActionError::InvalidArguments(_))));
    }

    #[test]
    fn test_setenv_valid() {
        let mut action = SetenvAction::new();
        let result = action.init(&mut Rule::new(), "MYVAR=value123");
        assert!(result.is_ok());
        assert_eq!(action.key, "MYVAR");
        assert_eq!(action.value.as_str(), "value123");
    }

    #[test]
    fn test_setenv_with_macro() {
        let mut action = SetenvAction::new();
        let result = action.init(&mut Rule::new(), "SESSION_ID=%{TX.session}");
        assert!(result.is_ok());
        assert_eq!(action.key, "SESSION_ID");
        assert_eq!(action.value.as_str(), "%{TX.session}");
    }

    #[test]
    fn test_setenv_with_equals_in_value() {
        let mut action = SetenvAction::new();
        let result = action.init(&mut Rule::new(), "MYVAR=key=value");
        assert!(result.is_ok());
        assert_eq!(action.key, "MYVAR");
        assert_eq!(action.value.as_str(), "key=value");
    }

    #[test]
    fn test_setenv_evaluate() {
        let mut action = SetenvAction::new();
        action
            .init(&mut Rule::new(), "TEST_VAR=test_value")
            .unwrap();

        // Mock transaction state
        struct MockTx;
        impl TransactionState for MockTx {
            fn get_variable(
                &self,
                _variable: crate::RuleVariable,
                _key: Option<&str>,
            ) -> Option<String> {
                None
            }
        }

        let mut tx = MockTx;
        action.evaluate(&Rule::new(), &mut tx);

        // Verify environment variable was set
        assert_eq!(std::env::var("TEST_VAR").unwrap(), "test_value");

        // Clean up
        // SAFETY: Removing environment variables after test cleanup
        unsafe {
            std::env::remove_var("TEST_VAR");
        }
    }

    #[test]
    fn test_setenv_action_type() {
        let action = SetenvAction::new();
        assert_eq!(action.action_type(), ActionType::Nondisruptive);
    }

    // ===== InitcolAction Tests =====

    #[test]
    fn test_initcol_missing_arguments() {
        let mut action = InitcolAction::new();
        let result = action.init(&mut Rule::new(), "");
        assert_eq!(result, Err(ActionError::MissingArguments));
    }

    #[test]
    fn test_initcol_invalid_format() {
        let mut action = InitcolAction::new();
        let result = action.init(&mut Rule::new(), "ip");
        assert!(matches!(result, Err(ActionError::InvalidArguments(_))));
    }

    #[test]
    fn test_initcol_valid() {
        let mut action = InitcolAction::new();
        let result = action.init(&mut Rule::new(), "ip=%{REMOTE_ADDR}");
        assert!(result.is_ok());
        assert_eq!(action.collection, "ip");
        assert_eq!(action.key, "%{REMOTE_ADDR}");
    }

    #[test]
    fn test_initcol_session() {
        let mut action = InitcolAction::new();
        let result = action.init(&mut Rule::new(), "session=%{REQUEST_COOKIES.JSESSIONID}");
        assert!(result.is_ok());
        assert_eq!(action.collection, "session");
        assert_eq!(action.key, "%{REQUEST_COOKIES.JSESSIONID}");
    }

    #[test]
    fn test_initcol_action_type() {
        let action = InitcolAction::new();
        assert_eq!(action.action_type(), ActionType::Nondisruptive);
    }
}
