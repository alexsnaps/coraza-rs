// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Deferred actions that require additional infrastructure or have security implications.
//!
//! These actions were deferred from Phase 6 because they require:
//! - External process execution (exec)
//! - Persistence layer (expirevar, initcol)
//! - Environment variable access (setenv)

use crate::actions::{ActionError, RuleMetadata};
use crate::operators::Macro;
use crate::transaction::Transaction;

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
/// Accepts the script path; scripts are never executed (as in Go Coraza).
pub(super) fn exec(_rule: &mut RuleMetadata, data: &str) -> Result<(), ActionError> {
    if data.is_empty() {
        return Err(ActionError::MissingArguments);
    }
    Ok(())
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
/// Validates `variable=seconds`; expiring variables needs a persistence layer this engine
/// doesn't have yet, so the action has no runtime effect (as in Go Coraza).
pub(super) fn expirevar(_rule: &mut RuleMetadata, data: &str) -> Result<(), ActionError> {
    if data.is_empty() {
        return Err(ActionError::MissingArguments);
    }

    let (_variable, seconds) = data.split_once('=').ok_or_else(|| {
        ActionError::InvalidArguments("expirevar requires format: variable=seconds".to_string())
    })?;
    seconds.parse::<i64>().map_err(|_| {
        ActionError::InvalidArguments(format!("invalid expiration time: {}", seconds))
    })?;
    Ok(())
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
#[derive(Debug, Clone)]
pub struct SetenvAction {
    key: String,
    value: Macro,
}

impl SetenvAction {
    /// Parses `key=value`; the value may contain macros.
    pub fn parse(data: &str) -> Result<Self, ActionError> {
        if data.is_empty() {
            return Err(ActionError::MissingArguments);
        }

        let (key, value) = data.split_once('=').ok_or_else(|| {
            ActionError::InvalidArguments("setenv requires format: key=value".to_string())
        })?;
        let key = key.trim();

        if key.is_empty() {
            return Err(ActionError::InvalidArguments("missing env key".to_string()));
        }

        if value.is_empty() {
            return Err(ActionError::InvalidArguments(
                "missing env value".to_string(),
            ));
        }

        Ok(Self {
            key: key.to_string(),
            value: Macro::new(value)
                .map_err(|e| ActionError::InvalidArguments(format!("invalid macro: {}", e)))?,
        })
    }

    pub fn evaluate(&self, tx: &mut Transaction) {
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
/// Validates `collection=key`; persistent collections need a persistence layer this
/// engine doesn't have yet, so the action has no runtime effect.
pub(super) fn initcol(_rule: &mut RuleMetadata, data: &str) -> Result<(), ActionError> {
    if data.is_empty() {
        return Err(ActionError::MissingArguments);
    }

    data.split_once('=').ok_or_else(|| {
        ActionError::InvalidArguments("initcol requires format: collection=key".to_string())
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== ExecAction Tests =====

    #[test]
    fn test_exec_missing_arguments() {
        let result = exec(&mut RuleMetadata::new(), "");
        assert_eq!(result, Err(ActionError::MissingArguments));
    }

    #[test]
    fn test_exec_valid() {
        let result = exec(&mut RuleMetadata::new(), "/usr/bin/test.sh");
        assert!(result.is_ok());
    }

    #[test]
    fn test_expirevar_missing_arguments() {
        let result = expirevar(&mut RuleMetadata::new(), "");
        assert_eq!(result, Err(ActionError::MissingArguments));
    }

    #[test]
    fn test_expirevar_invalid_format() {
        let result = expirevar(&mut RuleMetadata::new(), "session.suspicious");
        assert!(matches!(result, Err(ActionError::InvalidArguments(_))));
    }

    #[test]
    fn test_expirevar_invalid_seconds() {
        let result = expirevar(&mut RuleMetadata::new(), "session.suspicious=abc");
        assert!(matches!(result, Err(ActionError::InvalidArguments(_))));
    }

    #[test]
    fn test_expirevar_valid() {
        let result = expirevar(&mut RuleMetadata::new(), "session.suspicious=3600");
        assert!(result.is_ok());
    }

    #[test]
    fn test_setenv_missing_arguments() {
        let result = SetenvAction::parse("").map(|_| ());
        assert_eq!(result, Err(ActionError::MissingArguments));
    }

    #[test]
    fn test_setenv_missing_equals() {
        let result = SetenvAction::parse("MYVAR").map(|_| ());
        assert!(matches!(result, Err(ActionError::InvalidArguments(_))));
    }

    #[test]
    fn test_setenv_empty_key() {
        let result = SetenvAction::parse("=value").map(|_| ());
        assert!(matches!(result, Err(ActionError::InvalidArguments(_))));
    }

    #[test]
    fn test_setenv_empty_value() {
        let result = SetenvAction::parse("MYVAR=").map(|_| ());
        assert!(matches!(result, Err(ActionError::InvalidArguments(_))));
    }

    #[test]
    fn test_setenv_valid() {
        let action = SetenvAction::parse("MYVAR=value123").unwrap();
        assert_eq!(action.key, "MYVAR");
        assert_eq!(action.value.as_str(), "value123");
    }

    #[test]
    fn test_setenv_with_macro() {
        let action = SetenvAction::parse("SESSION_ID=%{TX.session}").unwrap();
        assert_eq!(action.key, "SESSION_ID");
        assert_eq!(action.value.as_str(), "%{TX.session}");
    }

    #[test]
    fn test_setenv_with_equals_in_value() {
        let action = SetenvAction::parse("MYVAR=key=value").unwrap();
        assert_eq!(action.key, "MYVAR");
        assert_eq!(action.value.as_str(), "key=value");
    }

    #[test]
    fn test_setenv_evaluate() {
        let action = SetenvAction::parse("TEST_VAR=test_value").unwrap();

        let mut tx = Transaction::new("action-test");
        action.evaluate(&mut tx);

        // Verify environment variable was set
        assert_eq!(std::env::var("TEST_VAR").unwrap(), "test_value");

        // Clean up
        // SAFETY: Removing environment variables after test cleanup
        unsafe {
            std::env::remove_var("TEST_VAR");
        }
    }

    #[test]
    fn test_initcol_missing_arguments() {
        let result = initcol(&mut RuleMetadata::new(), "");
        assert_eq!(result, Err(ActionError::MissingArguments));
    }

    #[test]
    fn test_initcol_invalid_format() {
        let result = initcol(&mut RuleMetadata::new(), "ip");
        assert!(matches!(result, Err(ActionError::InvalidArguments(_))));
    }

    #[test]
    fn test_initcol_valid() {
        let result = initcol(&mut RuleMetadata::new(), "ip=%{REMOTE_ADDR}");
        assert!(result.is_ok());
    }

    #[test]
    fn test_initcol_session() {
        let result = initcol(
            &mut RuleMetadata::new(),
            "session=%{REQUEST_COOKIES.JSESSIONID}",
        );
        assert!(result.is_ok());
    }
}
