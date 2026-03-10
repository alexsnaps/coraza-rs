// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Disruptive actions for controlling transaction flow.
//!
//! Disruptive actions stop rule processing and can interrupt transactions.
//! Only one disruptive action per rule applies; if multiple are specified,
//! the last one takes precedence. These actions are NOT executed if
//! SecRuleEngine is set to DetectionOnly.

use crate::actions::{Action, ActionError, ActionType, Rule, TransactionState};

/// Allow type for the `allow` action.
///
/// Determines the scope of what is allowed when the allow action triggers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowType {
    /// Not set (default)
    Unset,
    /// Skip all phases (entire transaction)
    All,
    /// Skip only the current phase
    Phase,
    /// Skip request phases until RESPONSE_HEADERS
    Request,
}

/// `deny` action - Stops rule processing and intercepts the transaction.
///
/// If status action is not used, deny action defaults to status 403.
///
/// # Arguments
///
/// No arguments accepted
///
/// # Examples
///
/// ```text
/// SecRule REQUEST_HEADERS:User-Agent "nikto" "log,deny,id:107,msg:'Nikto Scanners Identified'"
/// ```
#[derive(Debug)]
pub struct DenyAction;

impl Action for DenyAction {
    fn init(&mut self, _rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if !data.is_empty() {
            return Err(ActionError::UnexpectedArguments);
        }
        Ok(())
    }

    fn evaluate(&self, rule: &Rule, tx: &mut dyn TransactionState) {
        let rule_id = if rule.id == 0 {
            rule.parent_id
        } else {
            rule.id
        };

        let status = if rule.status == 0 {
            403 // deny action defaults to status 403
        } else {
            rule.status
        };

        tx.interrupt(rule_id, "deny", status, "");
    }

    fn action_type(&self) -> ActionType {
        ActionType::Disruptive
    }
}

/// `drop` action - Drops the connection immediately.
///
/// Initiates an immediate close of the TCP connection by sending a FIN packet.
/// This action is extremely useful when responding to both Brute Force and
/// Denial of Service attacks, minimizing network bandwidth and data returned
/// to the client.
///
/// # Arguments
///
/// No arguments accepted
///
/// # Examples
///
/// ```text
/// # Track Basic Authentication attempts and drop if exceeding threshold
/// SecAction "phase:1,id:109,initcol:ip=%{REMOTE_ADDR},nolog"
/// SecRule ARGS:login "!^$" "nolog,phase:1,id:110,setvar:ip.auth_attempt=+1"
/// SecRule IP:AUTH_ATTEMPT "@gt 25" "log,drop,phase:1,id:111,msg:'Possible Brute Force Attack'"
/// ```
#[derive(Debug)]
pub struct DropAction;

impl Action for DropAction {
    fn init(&mut self, _rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if !data.is_empty() {
            return Err(ActionError::UnexpectedArguments);
        }
        Ok(())
    }

    fn evaluate(&self, rule: &Rule, tx: &mut dyn TransactionState) {
        let rule_id = if rule.id == 0 {
            rule.parent_id
        } else {
            rule.id
        };

        tx.interrupt(rule_id, "drop", rule.status, "");
    }

    fn action_type(&self) -> ActionType {
        ActionType::Disruptive
    }
}

/// `allow` action - Allows the transaction to proceed.
///
/// Stops rule processing on a successful match and allows a transaction to proceed.
///
/// - Using solely: allow will affect the entire transaction, stopping processing
///   of the current phase and skipping all other phases apart from the logging phase.
/// - Using with parameter `phase`: stops processing the current phase, other phases continue.
/// - Using with parameter `request`: stops processing current phase, next phase will be
///   RESPONSE_HEADERS.
///
/// # Arguments
///
/// Optional: `phase`, `request`, or empty (defaults to entire transaction)
///
/// # Examples
///
/// ```text
/// # Allow unrestricted access from 192.168.1.100
/// SecRule REMOTE_ADDR "^192\.168\.1\.100$" "phase:1,id:95,nolog,allow"
///
/// # Do not process request but process response
/// SecAction "phase:1,allow:request,id:96"
///
/// # Do not process transaction (request and response)
/// SecAction "phase:1,allow,id:97"
/// ```
#[derive(Debug)]
pub struct AllowAction {
    allow_type: AllowType,
}

impl AllowAction {
    pub fn new() -> Self {
        Self {
            allow_type: AllowType::Unset,
        }
    }
}

impl Default for AllowAction {
    fn default() -> Self {
        Self::new()
    }
}

impl Action for AllowAction {
    fn init(&mut self, _rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        self.allow_type = match data {
            "phase" => AllowType::Phase,
            "request" => AllowType::Request,
            "" => AllowType::All,
            _ => {
                return Err(ActionError::InvalidArguments(format!(
                    "invalid argument {:?}",
                    data
                )));
            }
        };
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, tx: &mut dyn TransactionState) {
        tx.set_allow_type(self.allow_type);
    }

    fn action_type(&self) -> ActionType {
        ActionType::Disruptive
    }
}

/// `block` action - Placeholder for blocking using SecDefaultAction.
///
/// Performs the disruptive action defined by the previous `SecDefaultAction`.
/// This action is a placeholder to be used by rule writers to request a blocking
/// action without specifying how the blocking is to be done. The idea is that
/// such decisions are best left to rule users.
///
/// # Arguments
///
/// No arguments accepted
///
/// # Examples
///
/// ```text
/// # Specify how blocking is to be done
/// SecDefaultAction "phase:2,deny,id:101,status:403,log,auditlog"
///
/// # Detect attacks where we want to block
/// SecRule ARGS "@rx attack1" "phase:2,block,id:102"
///
/// # Detect attacks where we want only to warn
/// SecRule ARGS "@rx attack2" "phase:2,pass,id:103"
/// ```
#[derive(Debug)]
pub struct BlockAction;

impl Action for BlockAction {
    fn init(&mut self, _rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if !data.is_empty() {
            return Err(ActionError::UnexpectedArguments);
        }
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // This should never run
        // The block action is replaced by SecDefaultAction during rule compilation
    }

    fn action_type(&self) -> ActionType {
        ActionType::Disruptive
    }
}

/// `redirect` action - Redirects the client to a different location.
///
/// Intercepts transaction by issuing an external (client-visible) redirection
/// to the given location. If the status action is presented on the same rule,
/// and its value can be used for a redirection (301, 302, 303, 307), that value
/// will be used. Otherwise, status code 302 will be used.
///
/// # Arguments
///
/// Redirect target URL (required)
///
/// # Examples
///
/// ```text
/// SecRule REQUEST_HEADERS:User-Agent "@streq Test" \
///   "phase:1,id:130,log,redirect:http://www.example.com/failed.html"
/// ```
#[derive(Debug)]
pub struct RedirectAction {
    target: String,
}

impl RedirectAction {
    pub fn new() -> Self {
        Self {
            target: String::new(),
        }
    }
}

impl Default for RedirectAction {
    fn default() -> Self {
        Self::new()
    }
}

impl Action for RedirectAction {
    fn init(&mut self, _rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if data.is_empty() {
            return Err(ActionError::MissingArguments);
        }
        self.target = data.to_string();
        Ok(())
    }

    fn evaluate(&self, rule: &Rule, tx: &mut dyn TransactionState) {
        let rule_id = if rule.id == 0 {
            rule.parent_id
        } else {
            rule.id
        };

        let status = match rule.status {
            301 | 302 | 303 | 307 => rule.status,
            _ => 302, // default redirect status
        };

        tx.interrupt(rule_id, "redirect", status, &self.target);
    }

    fn action_type(&self) -> ActionType {
        ActionType::Disruptive
    }
}

/// `pass` action - Continues processing with the next rule.
///
/// Continues processing with the next rule in spite of a successful match.
/// This is a non-blocking disruptive action.
///
/// # Arguments
///
/// No arguments accepted
///
/// # Examples
///
/// ```text
/// SecRule REQUEST_HEADERS:User-Agent "@streq Test" "log,pass,id:122"
///
/// # When using pass with a SecRule with multiple targets,
/// # all variables will be inspected and all non-disruptive actions
/// # trigger for every match
/// SecAction "phase:2,nolog,pass,setvar:TX.test=0,id:123"
/// SecRule ARGS "test" "phase:2,log,pass,setvar:TX.test=+1,id:124"
/// ```
#[derive(Debug)]
pub struct PassAction;

impl Action for PassAction {
    fn init(&mut self, _rule: &mut Rule, data: &str) -> Result<(), ActionError> {
        if !data.is_empty() {
            return Err(ActionError::UnexpectedArguments);
        }
        Ok(())
    }

    fn evaluate(&self, _rule: &Rule, _tx: &mut dyn TransactionState) {
        // Pass action doesn't interrupt - it just continues processing
    }

    fn action_type(&self) -> ActionType {
        ActionType::Disruptive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock TransactionState for testing
    struct MockTransaction {
        interrupted: bool,
        interrupt_action: String,
        interrupt_status: i32,
        interrupt_data: String,
        allow_type: AllowType,
    }

    impl MockTransaction {
        fn new() -> Self {
            Self {
                interrupted: false,
                interrupt_action: String::new(),
                interrupt_status: 0,
                interrupt_data: String::new(),
                allow_type: AllowType::Unset,
            }
        }
    }

    impl TransactionState for MockTransaction {
        fn interrupt(&mut self, _rule_id: i32, action: &str, status: i32, data: &str) {
            self.interrupted = true;
            self.interrupt_action = action.to_string();
            self.interrupt_status = status;
            self.interrupt_data = data.to_string();
        }

        fn set_allow_type(&mut self, allow_type: AllowType) {
            self.allow_type = allow_type;
        }

        fn get_variable(
            &self,
            _variable: crate::RuleVariable,
            _key: Option<&str>,
        ) -> Option<String> {
            None
        }
    }

    // DenyAction Tests
    #[test]
    fn test_deny_no_arguments() {
        let mut action = DenyAction;
        assert!(action.init(&mut Rule::new(), "").is_ok());
    }

    #[test]
    fn test_deny_unexpected_arguments() {
        let mut action = DenyAction;
        assert_eq!(
            action.init(&mut Rule::new(), "abc"),
            Err(ActionError::UnexpectedArguments)
        );
    }

    // DropAction Tests
    #[test]
    fn test_drop_no_arguments() {
        let mut action = DropAction;
        assert!(action.init(&mut Rule::new(), "").is_ok());
    }

    #[test]
    fn test_drop_unexpected_arguments() {
        let mut action = DropAction;
        assert_eq!(
            action.init(&mut Rule::new(), "abc"),
            Err(ActionError::UnexpectedArguments)
        );
    }

    // AllowAction Tests
    #[test]
    fn test_allow_empty() {
        let mut action = AllowAction::new();
        assert!(action.init(&mut Rule::new(), "").is_ok());
        assert_eq!(action.allow_type, AllowType::All);
    }

    #[test]
    fn test_allow_phase() {
        let mut action = AllowAction::new();
        assert!(action.init(&mut Rule::new(), "phase").is_ok());
        assert_eq!(action.allow_type, AllowType::Phase);
    }

    #[test]
    fn test_allow_request() {
        let mut action = AllowAction::new();
        assert!(action.init(&mut Rule::new(), "request").is_ok());
        assert_eq!(action.allow_type, AllowType::Request);
    }

    #[test]
    fn test_allow_invalid() {
        let mut action = AllowAction::new();
        assert!(matches!(
            action.init(&mut Rule::new(), "response"),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    // BlockAction Tests
    #[test]
    fn test_block_no_arguments() {
        let mut action = BlockAction;
        assert!(action.init(&mut Rule::new(), "").is_ok());
    }

    #[test]
    fn test_block_unexpected_arguments() {
        let mut action = BlockAction;
        assert_eq!(
            action.init(&mut Rule::new(), "abc"),
            Err(ActionError::UnexpectedArguments)
        );
    }

    // RedirectAction Tests
    #[test]
    fn test_redirect_no_arguments() {
        let mut action = RedirectAction::new();
        assert_eq!(
            action.init(&mut Rule::new(), ""),
            Err(ActionError::MissingArguments)
        );
    }

    #[test]
    fn test_redirect_passed_arguments() {
        let mut action = RedirectAction::new();
        assert!(action.init(&mut Rule::new(), "abc").is_ok());
        assert_eq!(action.target, "abc");
    }

    // PassAction Tests
    #[test]
    fn test_pass_no_arguments() {
        let mut action = PassAction;
        assert!(action.init(&mut Rule::new(), "").is_ok());
    }

    #[test]
    fn test_pass_unexpected_arguments() {
        let mut action = PassAction;
        assert_eq!(
            action.init(&mut Rule::new(), "abc"),
            Err(ActionError::UnexpectedArguments)
        );
    }

    // Action type tests
    #[test]
    fn test_action_types() {
        assert_eq!(DenyAction.action_type(), ActionType::Disruptive);
        assert_eq!(DropAction.action_type(), ActionType::Disruptive);
        assert_eq!(AllowAction::new().action_type(), ActionType::Disruptive);
        assert_eq!(BlockAction.action_type(), ActionType::Disruptive);
        assert_eq!(RedirectAction::new().action_type(), ActionType::Disruptive);
        assert_eq!(PassAction.action_type(), ActionType::Disruptive);
    }

    // Evaluate tests (basic checks)
    #[test]
    fn test_deny_evaluate_default_status() {
        let action = DenyAction;
        let mut tx = MockTransaction::new();
        let mut rule = Rule::new();
        rule.id = 123;
        action.evaluate(&rule, &mut tx);
        assert!(tx.interrupted);
        assert_eq!(tx.interrupt_action, "deny");
        assert_eq!(tx.interrupt_status, 403); // default status
    }

    #[test]
    fn test_deny_evaluate_custom_status() {
        let action = DenyAction;
        let mut tx = MockTransaction::new();
        let mut rule = Rule::new();
        rule.id = 123;
        rule.status = 404;
        action.evaluate(&rule, &mut tx);
        assert!(tx.interrupted);
        assert_eq!(tx.interrupt_status, 404);
    }

    #[test]
    fn test_allow_evaluate() {
        let mut action = AllowAction::new();
        action.init(&mut Rule::new(), "phase").unwrap();
        let mut tx = MockTransaction::new();
        action.evaluate(&Rule::new(), &mut tx);
        assert_eq!(tx.allow_type, AllowType::Phase);
    }

    #[test]
    fn test_redirect_evaluate_default_status() {
        let mut action = RedirectAction::new();
        action.init(&mut Rule::new(), "http://example.com").unwrap();
        let mut tx = MockTransaction::new();
        let mut rule = Rule::new();
        rule.id = 123;
        action.evaluate(&rule, &mut tx);
        assert!(tx.interrupted);
        assert_eq!(tx.interrupt_action, "redirect");
        assert_eq!(tx.interrupt_status, 302); // default redirect status
        assert_eq!(tx.interrupt_data, "http://example.com");
    }

    #[test]
    fn test_redirect_evaluate_custom_status() {
        let mut action = RedirectAction::new();
        action.init(&mut Rule::new(), "http://example.com").unwrap();
        let mut tx = MockTransaction::new();
        let mut rule = Rule::new();
        rule.id = 123;
        rule.status = 301;
        action.evaluate(&rule, &mut tx);
        assert_eq!(tx.interrupt_status, 301);
    }
}
