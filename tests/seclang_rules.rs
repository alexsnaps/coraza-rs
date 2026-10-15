// SPDX-License-Identifier: Apache-2.0

//! Behaviour of rules loaded from SecLang, evaluated against real transactions.
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

#[test]
fn rules_can_inspect_the_request_body() {
    let waf = waf(r#"SecRule REQUEST_BODY "@contains attack" "id:1,phase:2,deny,status:403""#);

    let mut tx = waf.new_transaction();
    tx.process_request_headers();
    let interruption = tx.process_request_body(b"an attack payload").unwrap();

    assert_eq!(interruption.map(|i| i.rule_id), Some(1));
}

#[test]
fn rules_can_inspect_the_response_status() {
    let waf = waf(r#"SecRule RESPONSE_STATUS "@streq 500" "id:1,phase:3,deny,status:403""#);

    let mut tx = waf.new_transaction();
    let interruption = tx.process_response_headers(500, "HTTP/1.1");

    assert_eq!(interruption.map(|i| i.rule_id), Some(1));
}

#[test]
fn invalid_ctl_values_are_parse_errors() {
    let mut parser = Parser::new();
    let err = parser
        .from_string(r#"SecAction "id:1,phase:1,ctl:ruleEngine=bogus""#)
        .unwrap_err();

    assert!(err.message.contains("bogus"), "{}", err.message);
}

#[test]
fn ctl_rule_engine_applies_to_later_phases() {
    let waf = waf(r#"
        SecAction "id:1,phase:1,pass,ctl:ruleEngine=DetectionOnly"
        SecAction "id:2,phase:2,deny,status:403"
    "#);

    let mut tx = waf.new_transaction();
    tx.process_request_headers();

    assert_eq!(tx.process_request_body(b"").unwrap(), None);
}

#[test]
fn malformed_bodies_are_reported_to_rules() {
    let waf = waf(r#"
        SecRule REQBODY_ERROR "@eq 1" "id:1,phase:2,deny,status:400,logdata:'%{REQBODY_ERROR_MSG}'"
    "#);

    let mut tx = waf.new_transaction();
    tx.add_request_header("Content-Type", "application/json");
    tx.process_request_headers();
    let interruption = tx.process_request_body(b"{not json").unwrap();

    assert_eq!(interruption.map(|i| i.rule_id), Some(1));
    assert!(
        tx.get_variable(coraza::RuleVariable::ReqbodyErrorMsg, None)
            .is_some_and(|msg| !msg.is_empty())
    );
}

#[test]
fn well_formed_bodies_raise_no_body_error() {
    let waf = waf(r#"SecRule REQBODY_ERROR "@eq 1" "id:1,phase:2,deny,status:400""#);

    let mut tx = waf.new_transaction();
    tx.add_request_header("Content-Type", "application/json");
    tx.process_request_headers();

    assert_eq!(tx.process_request_body(br#"{"a": 1}"#).unwrap(), None);
}

#[test]
fn multimatch_tests_the_value_before_and_after_each_transformation() {
    let waf = waf(r#"
        SecRule ARGS "@streq ADMIN" "id:1,phase:1,t:lowercase,multiMatch,deny,status:403"
        SecRule ARGS "@streq ADMIN" "id:2,phase:1,t:lowercase,setvar:tx.single=1"
    "#);

    let mut tx = request_with_arg(&waf, "user", "ADMIN");
    let interruption = tx.process_request_headers();

    assert_eq!(interruption.map(|i| i.rule_id), Some(1));
}

#[test]
fn multimatch_runs_actions_once_per_matching_value() {
    let waf =
        waf(r#"SecRule ARGS "@rx a" "id:1,phase:1,t:lowercase,multiMatch,pass,setvar:tx.hits=+1""#);

    let mut tx = request_with_arg(&waf, "x", "Aa");
    tx.process_request_headers();

    // "Aa" and "aa" both match
    assert_eq!(tx_var(&tx, "hits").as_deref(), Some("2"));
}

#[test]
fn detect_sqli_blocks_and_captures_the_fingerprint() {
    // CRS 942100, less its tags and scoring
    let waf = waf(r#"
        SecRule ARGS_NAMES|ARGS "@detectSQLi" "id:942100,phase:2,deny,status:403,capture,\
            t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,multiMatch"
    "#);

    // sqlmap's payload for MySQL's full-text search
    let mut tx = request_with_arg(&waf, "q", "1' IN BOOLEAN MODE) UNION ALL SELECT NULL#");
    tx.process_request_headers();
    let interruption = tx.process_request_body(b"").unwrap();

    assert_eq!(interruption.map(|i| i.rule_id), Some(942100));
    assert_eq!(tx_var(&tx, "0").as_deref(), Some("sk)UE"));
}

#[test]
fn detect_xss_blocks_recent_event_handlers() {
    // CRS 941100, less its tags and scoring
    let waf = waf(r#"
        SecRule ARGS_NAMES|ARGS "@detectXSS" "id:941100,phase:2,deny,status:403,\
            t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,\
            t:removeNulls"
    "#);

    let mut tx = request_with_arg(&waf, "q", "<a onauxclick=alert(1)>");
    tx.process_request_headers();
    let interruption = tx.process_request_body(b"").unwrap();

    assert_eq!(interruption.map(|i| i.rule_id), Some(941100));
}

#[test]
fn data_files_are_found_next_to_the_config_naming_them() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("rules");
    std::fs::create_dir(&sub).unwrap();
    std::fs::write(sub.join("words.data"), "# comment\nevil\n").unwrap();
    std::fs::write(sub.join("ips.data"), "10.0.0.0/8\n").unwrap();
    std::fs::write(
        sub.join("rules.conf"),
        r#"
        SecRule ARGS:q "@pmFromFile words.data" "id:1,phase:1,deny,status:403"
        SecRule ARGS:ip "@ipMatchFromFile ips.data" "id:2,phase:1,deny,status:403"
        "#,
    )
    .unwrap();
    std::fs::write(dir.path().join("main.conf"), "Include rules/rules.conf\n").unwrap();

    let mut parser = Parser::new();
    parser.from_file(dir.path().join("main.conf")).unwrap();
    let waf = parser.into_waf().unwrap();

    let mut tx = request_with_arg(&waf, "q", "some evil input");
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(1));
    let mut tx = request_with_arg(&waf, "ip", "10.1.2.3");
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(2));
}

#[test]
fn negated_variables_exclude_keys_from_the_rest_of_the_rule() {
    let waf = waf(r#"SecRule ARGS|!ARGS:id "@streq x" "id:1,phase:1,deny,status:403""#);

    let mut tx = request_with_arg(&waf, "id", "x");
    assert!(tx.process_request_headers().is_none());

    let mut tx = request_with_arg(&waf, "other", "x");
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(1));
}
