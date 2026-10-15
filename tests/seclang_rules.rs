// SPDX-License-Identifier: Apache-2.0

//! Behaviour of rules loaded from SecLang, evaluated against real transactions.

use coraza::collection::MapCollection;
use coraza::seclang::Parser;
use coraza::transaction::Transaction;
use coraza::waf::Waf;

fn waf(rules: &str) -> Waf {
    let mut parser = Parser::new();
    parser.from_string(rules).expect("rules should parse");
    parser.into_waf().expect("config should be valid")
}

fn request_with_arg(waf: &Waf, key: &str, value: &str) -> Transaction {
    let mut tx = waf.new_transaction();
    tx.args_mut().add(key, value);
    tx
}

#[test]
fn transformations_are_applied_before_the_operator() {
    let waf = waf(r#"SecRule ARGS "@streq admin" "id:1,phase:1,t:lowercase,deny,status:403""#);

    let mut tx = request_with_arg(&waf, "user", "ADMIN");
    let interruption = tx.process_request_headers();

    assert_eq!(interruption.map(|i| i.rule_id), Some(1));
}

#[test]
fn t_none_clears_earlier_transformations() {
    let waf = waf(r#"SecRule ARGS "@streq admin" "id:1,phase:1,t:lowercase,t:none,deny""#);

    let mut tx = request_with_arg(&waf, "user", "ADMIN");

    assert!(tx.process_request_headers().is_none());
}

#[test]
fn unknown_transformation_is_a_parse_error() {
    let mut parser = Parser::new();
    let err = parser
        .from_string(r#"SecRule ARGS "@streq admin" "id:1,phase:1,t:noSuchThing,deny""#)
        .unwrap_err();

    assert!(err.message.contains("noSuchThing"), "{}", err.message);
}

fn tx_var(tx: &Transaction, key: &str) -> Option<String> {
    use coraza::RuleVariable;
    tx.get_variable(RuleVariable::TX, Some(key))
}

#[test]
fn capture_stores_regex_groups_in_tx() {
    let waf = waf(r#"SecRule ARGS "@rx (ad)(min)" "id:1,phase:1,capture,setvar:tx.got=%{tx.2}""#);

    let mut tx = request_with_arg(&waf, "user", "admin");
    tx.process_request_headers();

    assert_eq!(tx_var(&tx, "1").as_deref(), Some("ad"));
    assert_eq!(tx_var(&tx, "got").as_deref(), Some("min"));
}

#[test]
fn without_capture_regex_groups_are_not_stored() {
    let waf = waf(r#"SecRule ARGS "@rx (ad)min" "id:1,phase:1,pass""#);

    let mut tx = request_with_arg(&waf, "user", "admin");
    tx.process_request_headers();

    assert_eq!(tx_var(&tx, "1"), None);
}

#[test]
fn chain_parent_runs_its_nondisruptive_actions() {
    let waf = waf(r#"
        SecRule ARGS "@contains a" "id:1,phase:1,setvar:tx.parent=1,chain"
            SecRule ARGS "@contains a" "setvar:tx.child=1"
    "#);

    let mut tx = request_with_arg(&waf, "x", "a");
    tx.process_request_headers();

    assert_eq!(tx_var(&tx, "parent").as_deref(), Some("1"));
    assert_eq!(tx_var(&tx, "child").as_deref(), Some("1"));
}

#[test]
fn every_chain_link_is_evaluated_once() {
    let waf = waf(r#"
        SecRule ARGS "@contains a" "id:1,phase:1,pass,chain"
            SecRule ARGS "@contains a" "setvar:tx.middle=+1,chain"
            SecRule ARGS "@contains a" "setvar:tx.last=+1"
    "#);

    let mut tx = request_with_arg(&waf, "x", "a");
    tx.process_request_headers();

    assert_eq!(tx_var(&tx, "middle").as_deref(), Some("1"));
    assert_eq!(tx_var(&tx, "last").as_deref(), Some("1"));
}

#[test]
fn chain_disrupts_only_when_every_link_matches() {
    let waf = waf(r#"
        SecRule ARGS "@contains a" "id:7,phase:1,deny,status:403,chain"
            SecRule ARGS "@contains b" ""
    "#);

    let mut tx = request_with_arg(&waf, "x", "a");
    assert!(tx.process_request_headers().is_none());

    let mut tx = request_with_arg(&waf, "x", "ab");
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(7));
}

#[test]
fn allow_skips_the_rest_of_the_transaction() {
    let waf = waf(r#"
        SecAction "id:1,phase:1,allow"
        SecAction "id:2,phase:1,deny,status:403"
        SecAction "id:3,phase:2,deny,status:403"
    "#);

    let mut tx = waf.new_transaction();
    assert!(tx.process_request_headers().is_none());
    assert_eq!(tx.process_request_body(b"").unwrap(), None);
}

#[test]
fn allow_phase_skips_only_the_current_phase() {
    let waf = waf(r#"
        SecAction "id:1,phase:1,allow:phase"
        SecAction "id:2,phase:1,deny,status:403"
        SecAction "id:3,phase:2,deny,status:403"
    "#);

    let mut tx = waf.new_transaction();
    assert!(tx.process_request_headers().is_none());
    assert_eq!(
        tx.process_request_body(b"").unwrap().map(|i| i.rule_id),
        Some(3)
    );
}

#[test]
fn allow_request_skips_the_request_phases_only() {
    let waf = waf(r#"
        SecAction "id:1,phase:1,allow:request"
        SecAction "id:2,phase:2,deny,status:403"
        SecAction "id:3,phase:3,deny,status:403"
    "#);

    let mut tx = waf.new_transaction();
    assert!(tx.process_request_headers().is_none());
    assert_eq!(tx.process_request_body(b"").unwrap(), None);
    let interruption = tx.process_response_headers(200, "HTTP/1.1");
    assert_eq!(interruption.map(|i| i.rule_id), Some(3));
}
