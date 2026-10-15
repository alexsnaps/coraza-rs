// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Disruptive actions for controlling transaction flow.
//!
//! Disruptive actions stop rule processing and can interrupt transactions.
//! Only one disruptive action per rule applies; if multiple are specified,
//! the last one takes precedence. These actions take effect only if
//! SecRuleEngine is `On`.

use crate::actions::{ActionError, RuleMetadata};
use crate::transaction::Transaction;

/// Which rules an `allow` action skips once it runs.
///
/// The logging phase is never skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowType {
    /// No `allow` action has run
    Unset,
    /// `allow`: the rest of the current phase and every later phase
    All,
    /// `allow:phase`: the rest of the current phase
    Phase,
    /// `allow:request`: the rest of the request phases (REQUEST_HEADERS, REQUEST_BODY)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DenyAction;

impl DenyAction {
    /// Parses the action; it takes no argument.
    pub fn parse(data: &str) -> Result<Self, ActionError> {
        no_argument(data).map(|()| Self)
    }

    pub(crate) fn evaluate(&self, rule: &RuleMetadata, tx: &mut Transaction) {
        let status = if rule.status == 0 {
            403 // deny action defaults to status 403
        } else {
            rule.status
        };
        tx.interrupt(rule.id, "deny", status, "");
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DropAction;

impl DropAction {
    /// Parses the action; it takes no argument.
    pub fn parse(data: &str) -> Result<Self, ActionError> {
        no_argument(data).map(|()| Self)
    }

    pub(crate) fn evaluate(&self, rule: &RuleMetadata, tx: &mut Transaction) {
        tx.interrupt(rule.id, "drop", rule.status, "");
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowAction {
    allow_type: AllowType,
}

impl AllowAction {
    /// Parses the scope: none (the whole transaction), `phase` or `request`.
    pub fn parse(data: &str) -> Result<Self, ActionError> {
        let allow_type = match data {
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
        Ok(Self { allow_type })
    }

    pub(crate) fn evaluate(&self, tx: &mut Transaction) {
        tx.allow(self.allow_type);
    }
}

/// `block` action - Placeholder for blocking using SecDefaultAction.
///
/// Performs the disruptive action defined by the previous `SecDefaultAction`.
/// This action is a placeholder to be used by rule writers to request a blocking
/// action without specifying how the blocking is to be done. The idea is that
/// such decisions are best left to rule users.
///
/// The SecLang compiler replaces it with the disruptive action of the defaults of the
/// rule's phase. Left in a rule, which happens when its phase has no defaults, it does
/// nothing, as in Go Coraza.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockAction;

impl BlockAction {
    /// Parses the action; it takes no argument.
    pub fn parse(data: &str) -> Result<Self, ActionError> {
        no_argument(data).map(|()| Self)
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectAction {
    target: String,
}

impl RedirectAction {
    /// Parses the redirect target URL.
    pub fn parse(data: &str) -> Result<Self, ActionError> {
        if data.is_empty() {
            return Err(ActionError::MissingArguments);
        }
        Ok(Self {
            target: data.to_string(),
        })
    }

    pub(crate) fn evaluate(&self, rule: &RuleMetadata, tx: &mut Transaction) {
        let status = match rule.status {
            301 | 302 | 303 | 307 => rule.status,
            _ => 302, // default redirect status
        };
        tx.interrupt(rule.id, "redirect", status, &self.target);
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
/// Pass doesn't interrupt: it only overrides an earlier disruptive action of the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassAction;

impl PassAction {
    /// Parses the action; it takes no argument.
    pub fn parse(data: &str) -> Result<Self, ActionError> {
        no_argument(data).map(|()| Self)
    }
}

fn no_argument(data: &str) -> Result<(), ActionError> {
    if data.is_empty() {
        Ok(())
    } else {
        Err(ActionError::UnexpectedArguments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interruption(tx: &Transaction) -> &crate::transaction::Interruption {
        tx.interruption()
            .expect("transaction should be interrupted")
    }

    // DenyAction Tests
    #[test]
    fn test_deny_no_arguments() {
        assert!(DenyAction::parse("").is_ok());
    }

    #[test]
    fn test_deny_unexpected_arguments() {
        assert_eq!(
            DenyAction::parse("abc").map(|_| ()),
            Err(ActionError::UnexpectedArguments)
        );
    }

    // DropAction Tests
    #[test]
    fn test_drop_no_arguments() {
        assert!(DropAction::parse("").is_ok());
    }

    #[test]
    fn test_drop_unexpected_arguments() {
        assert_eq!(
            DropAction::parse("abc").map(|_| ()),
            Err(ActionError::UnexpectedArguments)
        );
    }

    // AllowAction Tests
    #[test]
    fn test_allow_empty() {
        let action = AllowAction::parse("").unwrap();
        assert_eq!(action.allow_type, AllowType::All);
    }

    #[test]
    fn test_allow_phase() {
        let action = AllowAction::parse("phase").unwrap();
        assert_eq!(action.allow_type, AllowType::Phase);
    }

    #[test]
    fn test_allow_request() {
        let action = AllowAction::parse("request").unwrap();
        assert_eq!(action.allow_type, AllowType::Request);
    }

    #[test]
    fn test_allow_invalid() {
        assert!(matches!(
            AllowAction::parse("response").map(|_| ()),
            Err(ActionError::InvalidArguments(_))
        ));
    }

    // BlockAction Tests
    #[test]
    fn test_block_no_arguments() {
        assert!(BlockAction::parse("").is_ok());
    }

    #[test]
    fn test_block_unexpected_arguments() {
        assert_eq!(
            BlockAction::parse("abc").map(|_| ()),
            Err(ActionError::UnexpectedArguments)
        );
    }

    // RedirectAction Tests
    #[test]
    fn test_redirect_no_arguments() {
        assert_eq!(
            RedirectAction::parse("").map(|_| ()),
            Err(ActionError::MissingArguments)
        );
    }

    #[test]
    fn test_redirect_passed_arguments() {
        let action = RedirectAction::parse("abc").unwrap();
        assert_eq!(action.target, "abc");
    }

    // PassAction Tests
    #[test]
    fn test_pass_no_arguments() {
        assert!(PassAction::parse("").is_ok());
    }

    #[test]
    fn test_pass_unexpected_arguments() {
        assert_eq!(
            PassAction::parse("abc").map(|_| ()),
            Err(ActionError::UnexpectedArguments)
        );
    }

    // Action type tests
    #[test]
    fn test_deny_evaluate_default_status() {
        let mut tx = Transaction::new("action-test");
        let mut rule = RuleMetadata::new();
        rule.id = 123;
        DenyAction.evaluate(&rule, &mut tx);
        assert_eq!(interruption(&tx).rule_id, 123);
        assert_eq!(interruption(&tx).action, "deny");
        assert_eq!(interruption(&tx).status, 403); // default status
    }

    #[test]
    fn test_deny_evaluate_custom_status() {
        let mut tx = Transaction::new("action-test");
        let mut rule = RuleMetadata::new();
        rule.id = 123;
        rule.status = 404;
        DenyAction.evaluate(&rule, &mut tx);
        assert_eq!(interruption(&tx).status, 404);
    }

    #[test]
    fn test_redirect_evaluate_default_status() {
        let action = RedirectAction::parse("http://example.com").unwrap();
        let mut tx = Transaction::new("action-test");
        let mut rule = RuleMetadata::new();
        rule.id = 123;
        action.evaluate(&rule, &mut tx);
        assert_eq!(interruption(&tx).action, "redirect");
        assert_eq!(interruption(&tx).status, 302); // default redirect status
        assert_eq!(interruption(&tx).data, "http://example.com");
    }

    #[test]
    fn test_redirect_evaluate_custom_status() {
        let action = RedirectAction::parse("http://example.com").unwrap();
        let mut tx = Transaction::new("action-test");
        let mut rule = RuleMetadata::new();
        rule.id = 123;
        rule.status = 301;
        action.evaluate(&rule, &mut tx);
        assert_eq!(interruption(&tx).status, 301);
    }
}
