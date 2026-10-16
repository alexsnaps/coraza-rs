// SPDX-License-Identifier: Apache-2.0

//! Behaviour of rules loaded from SecLang, evaluated against real transactions.
use coraza::RuleVariable;
use coraza::seclang::Parser;
use coraza::transaction::{Transaction, VariableCollection};
use coraza::waf::Waf;

fn waf(rules: &str) -> Waf {
    let mut parser = Parser::new();
    parser.from_string(rules).expect("rules should parse");
    parser.into_waf().expect("config should be valid")
}

/// Coraza's rule 200001 (`coraza.conf-recommended`): as in Go, JSON bodies are parsed only
/// once a rule selects the JSON body processor.
const JSON_PROCESSOR: &str = r#"SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON""#;

fn request_with_arg(waf: &Waf, key: &str, value: &str) -> Transaction {
    let mut tx = waf.new_transaction();
    tx.add_get_argument(key, value);
    tx
}

/// The values of `key` in `variable`, as rules read them; empty if none.
fn values(tx: &Transaction, variable: RuleVariable, key: &str) -> Vec<String> {
    match tx.collection(variable) {
        Some(VariableCollection::Map(map)) => map.get(key),
        _ => Vec::new(),
    }
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

/// The keys of the values rule `id` matched in `tx`, sorted.
fn matched_keys(tx: &Transaction, id: i32) -> Vec<String> {
    let mut keys: Vec<String> = tx
        .matched_rules()
        .iter()
        .filter(|matched| matched.rule.id() == id)
        .flat_map(|matched| matched.matches.iter().map(|data| data.key.clone()))
        .collect();
    keys.sort();
    keys
}

fn get_request(waf: &Waf, uri: &str) -> Transaction {
    let mut tx = waf.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1");
    tx
}

// Ported from: coraza/internal/corazawaf/rule_test.go::TestMatchEvaluate
#[test]
fn a_rule_matches_a_value_its_operator_accepts() {
    let waf = waf(r#"SecRule ARGS_GET:test "@eq 0" "id:1,phase:1,pass,nolog""#);

    let mut tx = get_request(&waf, "/?test=0");
    tx.process_request_headers();

    let matches = &tx.matched_rules()[0].matches;
    assert_eq!(matches.len(), 1);
    assert_eq!(
        (matches[0].key.as_str(), matches[0].value.as_slice()),
        ("test", &b"0"[..])
    );
}

// Ported from: coraza/internal/corazawaf/rule_test.go::TestNoMatchEvaluate
#[test]
fn a_rule_does_not_match_a_value_its_operator_rejects() {
    let waf = waf(r#"SecRule ARGS_GET:test "@eq 1" "id:1,phase:1,pass,nolog""#);

    let mut tx = get_request(&waf, "/?test=999");
    tx.process_request_headers();

    assert!(tx.matched_rules().is_empty());
}

// Ported from: coraza/internal/corazawaf/rule_test.go::TestNoMatchEvaluateBecauseOfException
#[test]
fn a_rule_does_not_match_a_key_it_excludes() {
    let waf = waf(r#"SecRule ARGS_GET|!ARGS_GET:test "@eq 0" "id:1,phase:1,pass,nolog""#);

    let mut tx = get_request(&waf, "/?test=0");
    tx.process_request_headers();

    assert!(tx.matched_rules().is_empty());
}

#[test]
fn transformations_are_applied_in_turn() {
    let waf = waf(
        r#"SecRule ARGS_GET:data "@streq HELLO" "id:1,phase:1,t:lowercase,t:uppercase,pass,nolog""#,
    );

    let mut tx = get_request(&waf, "/?data=HeLLo");
    tx.process_request_headers();

    let matches = &tx.matched_rules()[0].matches;
    assert_eq!(matches[0].value, b"HELLO");
}

#[test]
fn a_chain_does_not_match_when_its_first_rule_does_not() {
    let waf = waf(r#"
        SecRule ARGS_GET:username "@streq admin" "id:1,phase:1,deny,status:403,chain"
            SecRule ARGS_GET:password "@streq secret" ""
    "#);

    let mut tx = get_request(&waf, "/?username=user&password=secret");

    assert!(tx.process_request_headers().is_none());
    assert!(tx.matched_rules().is_empty());
}

#[test]
fn a_variable_without_a_key_matches_each_of_its_values() {
    let waf = waf(r#"SecRule ARGS_GET "@streq attack" "id:1,phase:1,pass,nolog""#);

    let mut tx = get_request(&waf, "/?param1=safe&param2=attack&param3=safe");
    tx.process_request_headers();

    assert_eq!(matched_keys(&tx, 1), ["param2"]);
}

#[test]
fn a_regex_key_selects_the_keys_it_matches() {
    let waf = waf(r#"SecRule ARGS_GET:/id.*/ "@eq 123" "id:1,phase:1,pass,nolog""#);

    let mut tx = get_request(&waf, "/?id=123&id_number=123&name=123");
    tx.process_request_headers();

    assert_eq!(matched_keys(&tx, 1), ["id", "id_number"]);
}

#[test]
fn each_link_of_a_chain_applies_its_own_transformations() {
    let waf = waf(r#"
        SecRule ARGS_GET:action "@streq delete" "id:1,phase:1,t:lowercase,deny,status:403,chain"
            SecRule REQUEST_HEADERS:User-Agent "@streq bot" "t:lowercase"
    "#);

    let mut tx = get_request(&waf, "/?action=DELETE");
    tx.add_request_header("User-Agent", "BOT");

    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(1));
    assert_eq!(tx.matched_rules()[0].matches.len(), 2);
}

#[test]
fn a_negated_operator_matches_what_the_operator_rejects() {
    let waf = waf(r#"SecRule ARGS_GET:user "!@streq admin" "id:1,phase:1,deny,status:403""#);

    let mut tx = get_request(&waf, "/?user=guest");
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(1));

    let mut tx = get_request(&waf, "/?user=admin");
    assert!(tx.process_request_headers().is_none());
}

#[test]
fn argument_values_keep_the_bytes_the_request_sent() {
    let waf = waf(r#"SecRule ARGS "@validateUtf8Encoding" "id:1,phase:1,deny,status:403""#);

    // As in Go Coraza, `%c0%af` decodes to the bytes C0 AF, which aren't UTF-8 (CRS 920250-1)
    let mut tx = get_request(&waf, "/?param=%c0%af");

    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(1));
}

#[test]
fn body_argument_values_keep_the_bytes_the_request_sent() {
    let waf = waf(r#"
        SecRequestBodyAccess On
        SecRule ARGS_POST "@validateUtf8Encoding" "id:1,phase:2,deny,status:403"
    "#);
    let post = |content_type: &str, body: &[u8]| {
        let mut tx = waf.new_transaction();
        tx.process_uri("/post", "POST", "HTTP/1.1");
        tx.add_request_header("Content-Type", content_type);
        tx.process_request_headers();
        tx.process_request_body(body).map(|i| i.rule_id)
    };

    // CRS 941310-1 sends `\xbc` and `\xbe` raw in a urlencoded body
    let urlencoded = post("application/x-www-form-urlencoded", b"var=\xbcscript\xbe");
    assert_eq!(urlencoded, Some(1));
    let multipart = b"--b\r\nContent-Disposition: form-data; name=\"var\"\r\n\r\n\xbc\r\n--b--\r\n";
    assert_eq!(post("multipart/form-data; boundary=b", multipart), Some(1));
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
    assert_eq!(tx.process_request_body(b""), None);
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
    assert_eq!(tx.process_request_body(b"").map(|i| i.rule_id), Some(3));
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
    assert_eq!(tx.process_request_body(b""), None);
    let interruption = tx.process_response_headers(200, "HTTP/1.1");
    assert_eq!(interruption.map(|i| i.rule_id), Some(3));
}

#[test]
fn rules_run_only_in_their_own_phase() {
    let waf = waf(r#"
        SecAction "id:1,phase:2,pass,nolog,setvar:tx.phase2=1"
        SecAction "id:2,phase:1,pass,nolog,setvar:tx.phase1=1"
    "#);

    let mut tx = waf.new_transaction();
    tx.process_request_headers();

    assert_eq!(tx_var(&tx, "phase1").as_deref(), Some("1"));
    assert_eq!(tx_var(&tx, "phase2"), None);
}

#[test]
fn skip_skips_the_next_rules_of_the_phase() {
    let waf = waf(r#"
        SecAction "id:1,phase:1,pass,nolog,skip:2"
        SecAction "id:2,phase:2,pass,nolog,setvar:tx.other_phase=1"
        SecAction "id:3,phase:1,pass,nolog,setvar:tx.three=1"
        SecAction "id:4,phase:1,pass,nolog,setvar:tx.four=1"
        SecAction "id:5,phase:1,pass,nolog,setvar:tx.five=1"
    "#);

    let mut tx = waf.new_transaction();
    tx.process_request_headers();

    // Rules of other phases don't count
    assert_eq!(tx_var(&tx, "three"), None);
    assert_eq!(tx_var(&tx, "four"), None);
    assert_eq!(tx_var(&tx, "five").as_deref(), Some("1"));
}

#[test]
fn skip_ends_with_its_phase() {
    let waf = waf(r#"
        SecAction "id:1,phase:1,pass,nolog,skip:1"
        SecAction "id:2,phase:2,pass,nolog,setvar:tx.phase2=1"
    "#);

    let mut tx = waf.new_transaction();
    tx.process_request_headers();
    tx.process_request_body(b"");

    // As in Go Coraza, rules left to skip at the end of a phase aren't skipped in the next
    assert_eq!(tx_var(&tx, "phase2").as_deref(), Some("1"));
}

#[test]
fn skip_after_resumes_after_the_marker() {
    let waf = waf(r#"
        SecAction "id:1,phase:1,pass,nolog,skipAfter:END"
        SecAction "id:2,phase:1,pass,nolog,setvar:tx.skipped=1"
        SecMarker END
        SecAction "id:3,phase:1,pass,nolog,setvar:tx.resumed=1"
    "#);

    let mut tx = waf.new_transaction();
    tx.process_request_headers();

    assert_eq!(tx_var(&tx, "skipped"), None);
    assert_eq!(tx_var(&tx, "resumed").as_deref(), Some("1"));
}

#[test]
fn an_interruption_ends_the_phase_and_the_request() {
    let waf = waf(r#"
        SecAction "id:1,phase:1,deny,status:403"
        SecAction "id:2,phase:1,pass,nolog,setvar:tx.same_phase=1"
        SecAction "id:3,phase:2,pass,nolog,setvar:tx.later_phase=1"
    "#);

    let mut tx = waf.new_transaction();
    let interruption = tx.process_request_headers().expect("rule 1 denies");
    assert_eq!((interruption.rule_id, interruption.status), (1, 403));

    let later = tx.process_request_body(b"");
    assert_eq!(later.map(|i| i.rule_id), Some(1));
    assert_eq!(tx_var(&tx, "same_phase"), None);
    assert_eq!(tx_var(&tx, "later_phase"), None);
    let rule_1 = &tx.matched_rules()[0];
    assert_eq!(
        (rule_1.disruptive_action, rule_1.disruptive),
        (Some("deny"), true)
    );
}

#[test]
fn logging_phase_rules_run_after_an_interruption() {
    let waf = waf(r#"
        SecAction "id:1,phase:1,deny,status:403"
        SecAction "id:2,phase:5,pass,nolog,setvar:tx.logged=1"
    "#);

    let mut tx = waf.new_transaction();
    tx.process_request_headers();
    tx.process_logging().unwrap();

    assert_eq!(tx_var(&tx, "logged").as_deref(), Some("1"));
}

#[test]
fn body_phases_run_only_right_after_their_headers_phase() {
    let waf = waf(r#"
        SecAction "id:1,phase:1,pass,nolog,setvar:tx.request_headers=1"
        SecAction "id:2,phase:2,pass,nolog,setvar:tx.request_body=1"
        SecAction "id:3,phase:3,pass,nolog,setvar:tx.response_headers=1"
        SecAction "id:4,phase:4,pass,nolog,setvar:tx.response_body=1"
    "#);

    // As in Go Coraza, a body phase called too early does nothing, and the phases can
    // still run in order
    let mut tx = waf.new_transaction();
    tx.process_request_body(b"");
    assert_eq!(tx_var(&tx, "request_body"), None);
    tx.process_request_headers();
    tx.process_request_body(b"");
    assert_eq!(tx_var(&tx, "request_headers").as_deref(), Some("1"));
    assert_eq!(tx_var(&tx, "request_body").as_deref(), Some("1"));

    tx.process_response_body(b"");
    assert_eq!(tx_var(&tx, "response_body"), None);
    tx.process_response_headers(200, "HTTP/1.1");
    tx.process_response_body(b"");
    assert_eq!(tx_var(&tx, "response_headers").as_deref(), Some("1"));
    assert_eq!(tx_var(&tx, "response_body").as_deref(), Some("1"));
}

#[test]
fn with_the_rule_engine_off_no_phase_runs() {
    let waf = waf(r#"
        SecRuleEngine Off
        SecRequestBodyAccess On
        SecAction "id:1,phase:1,pass,nolog,setvar:tx.request_headers=1"
        SecAction "id:2,phase:2,pass,nolog,setvar:tx.request_body=1"
        SecAction "id:3,phase:5,pass,nolog,setvar:tx.logging=1"
    "#);

    let mut tx = waf.new_transaction();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
    tx.process_request_headers();
    tx.process_request_body(b"a=1");
    tx.process_logging().unwrap();

    // As in Go Coraza, no rule runs, the logging phase's included, and the body isn't read
    assert_eq!(tx_var(&tx, "request_headers"), None);
    assert_eq!(tx_var(&tx, "request_body"), None);
    assert_eq!(tx_var(&tx, "logging"), None);
    assert_eq!(tx.get_variable(RuleVariable::ArgsPost, Some("a")), None);
}

#[test]
fn a_phase_called_again_returns_the_interruption() {
    let waf = waf(r#"SecAction "id:1,phase:1,deny,status:403""#);

    let mut tx = waf.new_transaction();
    tx.process_request_headers();

    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(1));
}

#[test]
fn an_interrupted_transaction_is_not_inspected_further() {
    let waf = waf(r#"
        SecRequestBodyAccess On
        SecAction "id:1,phase:1,deny,status:403"
    "#);

    let mut tx = waf.new_transaction();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
    tx.process_request_headers();

    // As in Go Coraza, the body isn't read, nor the response status recorded
    assert_eq!(tx.process_request_body(b"a=1").map(|i| i.rule_id), Some(1));
    assert_eq!(tx.get_variable(RuleVariable::ArgsPost, Some("a")), None);
    let response = tx.process_response_headers(200, "HTTP/1.1");
    assert_eq!(response.map(|i| i.rule_id), Some(1));
    let status = tx.get_variable(RuleVariable::ResponseStatus, None);
    assert_eq!(status.as_deref(), Some(""));
}

#[test]
fn ctl_rule_remove_by_id_skips_rules_for_one_transaction() {
    let waf = waf(r#"
        SecRule REQUEST_HEADERS:X-Quiet "@streq yes" "id:1,phase:1,pass,nolog,ctl:ruleRemoveById=10-19"
        SecAction "id:10,phase:1,pass,nolog,setvar:tx.ten=1"
        SecAction "id:20,phase:1,pass,nolog,setvar:tx.twenty=1"
    "#);

    let mut quiet = waf.new_transaction();
    quiet.add_request_header("X-Quiet", "yes");
    quiet.process_request_headers();
    assert_eq!(tx_var(&quiet, "ten"), None);
    assert_eq!(tx_var(&quiet, "twenty").as_deref(), Some("1"));

    let mut other = waf.new_transaction();
    other.process_request_headers();
    assert_eq!(tx_var(&other, "ten").as_deref(), Some("1"));
}

#[test]
fn ctl_rule_remove_by_id_removes_a_wide_range_without_listing_its_ids() {
    // Go keeps the range rather than each id in it ("Ranges avoid expanding all IDs")
    let waf = waf(r#"
        SecAction "id:1,phase:1,pass,nolog,ctl:ruleRemoveById=10-20000000"
        SecAction "id:15000000,phase:1,deny,status:403"
    "#);

    let mut tx = waf.new_transaction();
    let started = std::time::Instant::now();
    let interruption = tx.process_request_headers();
    let took = started.elapsed();

    assert!(interruption.is_none());
    assert!(took < std::time::Duration::from_secs(1), "took {took:?}");
}

#[test]
fn ctl_rule_remove_by_tag_and_msg_skip_the_rules_they_select() {
    let waf = waf(r#"
        SecAction "id:1,phase:1,pass,nolog,ctl:ruleRemoveByTag=noisy,ctl:ruleRemoveByMsg=Chatty"
        SecAction "id:2,phase:1,pass,nolog,tag:noisy,setvar:tx.tagged=1"
        SecAction "id:3,phase:1,pass,nolog,msg:'Chatty',setvar:tx.messaged=1"
        SecAction "id:4,phase:1,pass,nolog,setvar:tx.other=1"
    "#);

    let mut tx = waf.new_transaction();
    tx.process_request_headers();

    assert_eq!(tx_var(&tx, "tagged"), None);
    assert_eq!(tx_var(&tx, "messaged"), None);
    assert_eq!(tx_var(&tx, "other").as_deref(), Some("1"));
}

#[test]
fn detection_only_records_disruptive_actions_without_interrupting() {
    let waf = waf(r#"
        SecRuleEngine DetectionOnly
        SecAction "id:1,phase:1,deny,status:403"
        SecAction "id:2,phase:1,pass,nolog,setvar:tx.after=1"
    "#);

    let mut tx = waf.new_transaction();

    assert_eq!(tx.process_request_headers(), None);
    assert_eq!(tx_var(&tx, "after").as_deref(), Some("1"));
    let rule_1 = &tx.matched_rules()[0];
    assert_eq!(
        (rule_1.disruptive_action, rule_1.disruptive),
        (Some("deny"), false)
    );
}

#[test]
fn detection_only_does_not_enforce_allow() {
    let waf = waf(r#"
        SecRuleEngine DetectionOnly
        SecAction "id:1,phase:1,allow"
        SecAction "id:2,phase:1,pass,nolog,setvar:tx.after=1"
    "#);

    let mut tx = waf.new_transaction();
    tx.process_request_headers();

    assert_eq!(tx_var(&tx, "after").as_deref(), Some("1"));
}

#[test]
fn rules_can_inspect_the_request_body() {
    let waf = waf(r#"
        SecRequestBodyAccess On
        SecRule REQUEST_BODY "@contains attack" "id:1,phase:2,deny,status:403"
    "#);

    let mut tx = waf.new_transaction();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
    tx.process_request_headers();
    let interruption = tx.process_request_body(b"an attack payload");

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

    assert_eq!(tx.process_request_body(b""), None);
}

#[test]
fn a_rule_engine_mode_change_applies_to_the_next_rule_of_the_phase() {
    let waf = waf(r#"
        SecRuleEngine On
        SecAction "id:1,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"
        SecAction "id:2,phase:1,deny,status:403"
    "#);

    let mut tx = waf.new_transaction();

    // As in Go Coraza, rule 2's deny runs in DetectionOnly: it doesn't interrupt, and is
    // recorded as a disruptive action that didn't take effect
    assert_eq!(tx.process_request_headers(), None);
    let rule_2 = tx
        .matched_rules()
        .iter()
        .find(|matched| matched.rule.id() == 2)
        .expect("rule 2 matched");
    assert_eq!(rule_2.disruptive_action, Some("deny"));
    assert!(!rule_2.disruptive);
}

#[test]
fn malformed_bodies_are_reported_to_rules() {
    let waf = waf(&format!(
        r#"
        SecRequestBodyAccess On
        {JSON_PROCESSOR}
        SecRule REQBODY_ERROR "@eq 1" "id:1,phase:2,deny,status:400,logdata:'%{{REQBODY_ERROR_MSG}}'"
        "#
    ));

    let mut tx = waf.new_transaction();
    tx.add_request_header("Content-Type", "application/json");
    tx.process_request_headers();
    let interruption = tx.process_request_body(b"{not json");

    assert_eq!(interruption.map(|i| i.rule_id), Some(1));
    assert!(
        tx.get_variable(coraza::RuleVariable::ReqbodyErrorMsg, None)
            .is_some_and(|msg| msg.starts_with("JSON: "))
    );
    assert_eq!(
        tx.get_variable(coraza::RuleVariable::ReqbodyProcessorError, None)
            .as_deref(),
        Some("1")
    );
}

#[test]
fn well_formed_bodies_raise_no_body_error() {
    let waf = waf(&format!(
        r#"
        SecRequestBodyAccess On
        {JSON_PROCESSOR}
        SecRule REQBODY_ERROR "@eq 1" "id:1,phase:2,deny,status:400"
        "#
    ));

    let mut tx = waf.new_transaction();
    tx.add_request_header("Content-Type", "application/json");
    tx.process_request_headers();

    assert_eq!(tx.process_request_body(br#"{"a": 1}"#), None);
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
    let interruption = tx.process_request_body(b"");

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
    let interruption = tx.process_request_body(b"");

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

#[test]
fn update_target_by_id_excludes_and_adds_variables() {
    let waf = waf(r#"
        SecRule ARGS "@streq x" "id:1,phase:1,deny,status:403"
        SecRule ARGS:a "@streq y" "id:2,phase:1,deny,status:403"
        SecRule ARGS:a "@streq z" "id:3,phase:1,deny,status:403"
        SecRuleUpdateTargetById 1 "!ARGS:skip"
        SecRuleUpdateTargetById 2-3 ARGS:b
    "#);

    let mut tx = request_with_arg(&waf, "skip", "x");
    assert!(tx.process_request_headers().is_none());
    let mut tx = request_with_arg(&waf, "other", "x");
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(1));
    let mut tx = request_with_arg(&waf, "b", "z");
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(3));
}

#[test]
fn update_target_by_tag_adds_variables_to_tagged_rules() {
    let waf = waf(r#"
        SecRule ARGS:a "@streq y" "id:1,phase:1,deny,status:403,tag:'probe'"
        SecRule ARGS:a "@streq z" "id:2,phase:1,deny,status:403"
        SecRuleUpdateTargetByTag "probe" "ARGS:b"
    "#);

    let mut tx = request_with_arg(&waf, "b", "y");
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(1));
    let mut tx = request_with_arg(&waf, "b", "z");
    assert!(tx.process_request_headers().is_none());
}

#[test]
fn update_target_of_an_unknown_rule_is_an_error() {
    let mut parser = Parser::new();
    let err = parser
        .from_string(r#"SecRuleUpdateTargetById 404 "!ARGS:id""#)
        .unwrap_err();

    assert!(err.message.contains("404"), "{}", err.message);
}

#[test]
fn block_takes_the_disruptive_action_of_the_phase_defaults() {
    let waf = waf(r#"
        SecDefaultAction "phase:1,log,auditlog,deny,status:418"
        SecRule ARGS "@streq x" "id:1,phase:1,block"
    "#);

    let mut tx = request_with_arg(&waf, "q", "x");
    let interruption = tx.process_request_headers().unwrap();

    assert_eq!((interruption.rule_id, interruption.status), (1, 418));
}

#[test]
fn block_adds_to_the_anomaly_score_with_crs_defaults() {
    // As crs-setup.conf: rules `block`, and only the score threshold denies
    let waf = waf(r#"
        SecDefaultAction "phase:1,log,auditlog,pass"
        SecRule ARGS "@streq x" "id:1,phase:1,block,setvar:tx.score=+3"
        SecRule TX:score "@ge 5" "id:2,phase:1,deny,status:403"
    "#);

    let mut tx = request_with_arg(&waf, "q", "x");
    assert!(tx.process_request_headers().is_none());
    assert_eq!(tx_var(&tx, "score").as_deref(), Some("3"));

    let mut tx = waf.new_transaction();
    tx.add_get_argument("a", "x");
    tx.add_get_argument("b", "x");
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(2));
}

#[test]
fn block_passes_without_defaults() {
    // Phase 2 has built-in defaults of `log,auditlog,pass`; other phases have none
    let waf = waf(r#"
        SecRule ARGS "@streq x" "id:1,phase:1,block"
        SecRule ARGS "@streq x" "id:2,phase:2,block"
    "#);

    let mut tx = request_with_arg(&waf, "q", "x");
    assert!(tx.process_request_headers().is_none());
    assert_eq!(tx.process_request_body(b""), None);
}

#[test]
fn rules_without_a_disruptive_action_take_the_default_one() {
    let waf = waf(r#"
        SecDefaultAction "phase:1,deny,status:403"
        SecRule ARGS:a "@streq x" "id:1,phase:1"
        SecRule ARGS:b "@streq x" "id:2,phase:1,pass"
    "#);

    let mut tx = request_with_arg(&waf, "b", "x");
    assert!(tx.process_request_headers().is_none());
    let mut tx = request_with_arg(&waf, "a", "x");
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(1));
}

#[test]
fn invalid_default_actions_are_parse_errors() {
    for (defaults, reason) in [
        ("log,pass", "phase"),
        ("phase:1,log", "disruptive"),
        ("phase:1,pass,id:1", "id"),
        ("phase:1,pass,t:lowercase", "t"),
    ] {
        let mut parser = Parser::new();
        let err = parser
            .from_string(&format!("SecDefaultAction \"{defaults}\""))
            .unwrap_err();
        assert!(err.message.contains(reason), "{defaults}: {}", err.message);
    }

    let mut parser = Parser::new();
    let err = parser
        .from_string("SecDefaultAction \"phase:1,pass\"\nSecDefaultAction \"phase:1,deny\"")
        .unwrap_err();
    assert!(err.message.contains("already"), "{}", err.message);
}

#[test]
fn arguments_over_the_limit_are_dropped_and_flagged() {
    let waf = waf(r#"
        SecArgumentsLimit 2
        SecRule ARGUMENTS_LIMIT_REACHED "@eq 1" "id:1,phase:1,deny,status:400"
    "#);

    let mut tx = waf.new_transaction();
    tx.process_uri("/?a=1&b=2", "GET", "HTTP/1.1");
    assert!(tx.process_request_headers().is_none());
    assert_eq!(
        tx.get_variable(coraza::RuleVariable::ArgumentsLimitReached, None)
            .as_deref(),
        Some("0")
    );

    // Each value counts, not each key
    let mut tx = waf.new_transaction();
    tx.process_uri("/?a=1&a=2&a=3", "GET", "HTTP/1.1");
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(1));
    assert_eq!(values(&tx, RuleVariable::ArgsGet, "a"), ["1", "2"]);
}

#[test]
fn body_arguments_of_every_processor_are_in_args() {
    let waf = waf(&format!(
        r#"
        SecRequestBodyAccess On
        {JSON_PROCESSOR}
        SecRule ARGS "@streq evil" "id:1,phase:2,deny,status:403"
        "#
    ));

    let multipart = "--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nevil\r\n--b--\r\n";
    for (content_type, body) in [
        ("application/x-www-form-urlencoded", "a=evil"),
        ("application/json", r#"{"a": "evil"}"#),
        ("multipart/form-data; boundary=b", multipart),
    ] {
        let mut tx = waf.new_transaction();
        tx.add_request_header("Content-Type", content_type);
        tx.process_request_headers();
        let interruption = tx.process_request_body(body.as_bytes());
        assert_eq!(interruption.map(|i| i.rule_id), Some(1), "{content_type}");
    }
}

#[test]
fn unparsable_uris_are_flagged() {
    let waf = waf(r#"SecRule URI_PARSE_ERROR "@eq 1" "id:1,phase:1,deny,status:400""#);

    for (uri, flagged) in [
        ("/a/b?c=%zz", false),
        ("*", false),
        ("http://example.com/a", false),
        ("/a\0b", true),
        ("/a\nb", true),
        ("/%zz", true),
        ("relative/path", true),
        ("", true),
    ] {
        let mut tx = waf.new_transaction();
        tx.process_uri(uri, "GET", "HTTP/1.1");
        let interruption = tx.process_request_headers();
        assert_eq!(interruption.is_some(), flagged, "{uri:?}");
    }
}

#[test]
fn repeated_multipart_part_headers_are_flagged() {
    let waf = waf(r#"
        SecRequestBodyAccess On
        SecRule MULTIPART_DUPLICATE_PART_HEADER "@eq 1" "id:1,phase:2,deny,status:400"
    "#);

    for (part_headers, flagged) in [
        ("Content-Disposition: form-data; name=\"a\"", false),
        (
            "Content-Disposition: form-data; name=\"a\"\r\nContent-Type: text/plain\r\nContent-Type: text/html",
            true,
        ),
        (
            "Content-Disposition: form-data; name=\"a\"; name=\"b\"",
            true,
        ),
    ] {
        let body = format!("--b\r\n{part_headers}\r\n\r\nx\r\n--b--\r\n");
        let mut tx = waf.new_transaction();
        tx.add_request_header("Content-Type", "multipart/form-data; boundary=b");
        tx.process_request_headers();
        let interruption = tx.process_request_body(body.as_bytes());
        assert_eq!(interruption.is_some(), flagged, "{part_headers:?}");
        assert_eq!(
            tx.get_variable(coraza::RuleVariable::MultipartStrictError, None)
                .as_deref()
                == Some("1"),
            flagged,
            "{part_headers:?}"
        );
    }
}

#[test]
fn audit_log_and_body_directives_set_the_config() {
    use coraza::types::{AuditLogFormat, AuditLogPart, AuditLogType};

    let mut parser = Parser::new();
    parser
        .from_string(
            r#"
            SecAuditLogFormat JSON
            SecAuditLogParts ABIJDEFHZ
            SecAuditLogType Concurrent
            SecAuditLogRelevantStatus "^(?:(5|4)(0|1)[0-9])$"
            SecRxPreFilter Off
            SecRequestBodyJsonDepthLimit 3
            SecResponseBodyJsonDepthLimit 4
            SecResponseBodyMimeType text/plain text/html
            "#,
        )
        .unwrap();

    let config = parser.config();
    assert_eq!(config.audit_log_format, AuditLogFormat::Json);
    use AuditLogPart::*;
    assert_eq!(
        config.audit_log_parts,
        [
            Header,
            RequestHeaders,
            RequestBodyAlternative,
            UploadedFiles,
            IntermediaryResponseHeaders,
            IntermediaryResponseBody,
            ResponseHeaders,
            Trailer,
            EndMarker,
        ]
    );
    assert_eq!(config.audit_log_type, AuditLogType::Concurrent);
    assert_eq!(config.audit_log_relevant_status, "^(?:(5|4)(0|1)[0-9])$");
    assert_eq!(config.request_body_json_depth_limit, 3);
    assert_eq!(config.response_body_json_depth_limit, 4);
    assert_eq!(config.response_body_mime_types, ["text/plain", "text/html"]);
}

#[test]
fn invalid_audit_log_and_body_directives_are_parse_errors() {
    for directive in [
        "SecAuditLogFormat yaml",
        "SecAuditLogParts BCF",
        "SecAuditLogType carrier-pigeon",
        "SecAuditLogRelevantStatus (",
        "SecRxPreFilter maybe",
        "SecRequestBodyJsonDepthLimit 0",
        "SecResponseBodyJsonDepthLimit -1",
    ] {
        assert!(Parser::new().from_string(directive).is_err(), "{directive}");
    }
}

#[test]
fn json_bodies_deeper_than_the_limit_are_body_errors() {
    let waf = waf(&format!(
        r#"
        SecRequestBodyAccess On
        SecRequestBodyJsonDepthLimit 2
        {JSON_PROCESSOR}
        SecRule REQBODY_ERROR "@eq 1" "id:1,phase:2,deny,status:400"
        "#
    ));

    for (body, too_deep) in [
        (r#"{"a": {"b": 1}}"#, false),
        (r#"{"a": [{"b": 1}]}"#, true),
    ] {
        let mut tx = waf.new_transaction();
        tx.add_request_header("Content-Type", "application/json");
        tx.process_request_headers();
        let interruption = tx.process_request_body(body.as_bytes());
        assert_eq!(interruption.is_some(), too_deep, "{body}");
    }
}

#[test]
fn json_response_bodies_deeper_than_the_limit_are_body_errors() {
    let waf = waf(r#"
        SecResponseBodyAccess On
        SecResponseBodyMimeType application/json
        SecResponseBodyJsonDepthLimit 2
        SecRule RESPONSE_HEADERS:Content-Type "@beginsWith application/json" "id:100,phase:3,pass,nolog,ctl:responseBodyProcessor=JSON"
        SecRule RES_BODY_ERROR "@eq 1" "id:1,phase:4,deny,status:500"
    "#);

    for (body, too_deep) in [
        (r#"{"a": {"b": 1}}"#, false),
        (r#"{"a": [{"b": 1}]}"#, true),
    ] {
        let mut tx = waf.new_transaction();
        tx.add_response_header("Content-Type", "application/json");
        tx.process_response_headers(200, "HTTP/1.1");
        let interruption = tx.process_response_body(body.as_bytes());
        assert_eq!(interruption.is_some(), too_deep, "{body}");
    }
}

#[test]
fn only_response_bodies_of_listed_types_are_inspected() {
    let waf = waf(r#"
        SecResponseBodyAccess On
        SecResponseBodyMimeType text/html
        SecRule RESPONSE_BODY "@contains secret" "id:1,phase:4,deny,status:403"
    "#);

    for (content_type, inspected) in [
        ("text/html; charset=utf-8", true),
        ("application/json", false),
    ] {
        let mut tx = waf.new_transaction();
        tx.add_response_header("Content-Type", content_type);
        tx.process_response_headers(200, "HTTP/1.1");
        let interruption = tx.process_response_body(b"a secret");
        assert_eq!(interruption.is_some(), inspected, "{content_type}");
    }
}

#[test]
fn the_request_body_processor_is_chosen_as_in_go() {
    use coraza::RuleVariable::ReqbodyProcessor;

    let waf = waf(r#"
        SecRequestBodyAccess On
        SecRule REQUEST_HEADERS:Content-Type "[+]json" "id:100,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
        SecRule ARGS "@streq evil" "id:1,phase:2,deny,status:403"
    "#);

    // JSON is parsed only when a rule selects it; urlencoded and multipart by Content-Type
    for (content_type, body, processor, parsed) in [
        ("application/vnd.api+json", r#"{"a": "evil"}"#, "JSON", true),
        ("application/json", r#"{"a": "evil"}"#, "", false),
        (
            "application/x-www-form-urlencoded",
            "a=evil",
            "URLENCODED",
            true,
        ),
    ] {
        let mut tx = waf.new_transaction();
        tx.add_request_header("Content-Type", content_type);
        tx.process_request_headers();
        let interruption = tx.process_request_body(body.as_bytes());
        assert_eq!(interruption.is_some(), parsed, "{content_type}");
        assert_eq!(
            tx.get_variable(ReqbodyProcessor, None).as_deref(),
            Some(processor),
            "{content_type}"
        );
    }
}

#[test]
fn forcing_the_request_body_variable_defaults_to_urlencoded() {
    let waf = waf(r#"
        SecRequestBodyAccess On
        SecAction "id:100,phase:1,pass,nolog,ctl:forceRequestBodyVariable=On"
        SecRule ARGS_POST "@streq evil" "id:1,phase:2,deny,status:403"
    "#);

    let mut tx = waf.new_transaction();
    tx.add_request_header("Content-Type", "text/plain");
    tx.process_request_headers();

    assert_eq!(
        tx.process_request_body(b"a=evil").map(|i| i.rule_id),
        Some(1)
    );
}

#[test]
fn the_response_body_processor_is_chosen_by_ctl() {
    let waf = waf(r#"
        SecResponseBodyAccess On
        SecResponseBodyMimeType application/json
        SecRule RESPONSE_HEADERS:Content-Type "@beginsWith application/json" "id:100,phase:3,pass,nolog,ctl:responseBodyProcessor=JSON"
        SecRule RESPONSE_ARGS "@streq leak" "id:1,phase:4,deny,status:403"
        SecRule RES_BODY_ERROR "@eq 1" "id:2,phase:4,deny,status:500"
    "#);

    for (body, rule_id) in [(r#"{"a": "leak"}"#, Some(1)), ("{not json", Some(2))] {
        let mut tx = waf.new_transaction();
        tx.add_response_header("Content-Type", "application/json");
        tx.process_response_headers(200, "HTTP/1.1");
        let interruption = tx.process_response_body(body.as_bytes());
        assert_eq!(interruption.map(|i| i.rule_id), rule_id, "{body}");
    }
}

#[test]
fn unknown_body_processors_are_parse_errors() {
    for ctl in ["requestBodyProcessor=YAML", "responseBodyProcessor=CSV"] {
        let mut parser = Parser::new();
        let rule = format!(r#"SecAction "id:1,phase:1,pass,ctl:{ctl}""#);
        assert!(parser.from_string(&rule).is_err(), "{ctl}");
    }
}

#[test]
fn ctl_changes_audit_and_debug_settings_of_one_transaction() {
    use coraza::types::{AuditEngineStatus, AuditLogPart};

    let dir = tempfile::tempdir().unwrap();
    let audit_log = dir.path().join("audit.log");
    let waf = waf(&format!(
        r#"
        SecAuditEngine RelevantOnly
        SecAuditLog {}
        SecAuditLogParts ABZ
        SecDebugLogLevel 1
        SecRule ARGS:audit "@streq all" "id:1,phase:1,pass,nolog,ctl:auditEngine=On,ctl:auditLogParts=+E,ctl:debugLogLevel=9"
        "#,
        audit_log.display()
    ));
    let logged = || std::fs::read_to_string(&audit_log).unwrap_or_default();
    let has_response_body = |tx: &Transaction| {
        tx.audit_log()
            .parts
            .contains(&AuditLogPart::IntermediaryResponseBody)
    };

    // Nothing relevant happened: no entry
    let mut tx = request_with_arg(&waf, "audit", "none");
    tx.process_request_headers();
    tx.process_logging().unwrap();
    assert!(logged().is_empty());
    assert!(!has_response_body(&tx));
    assert_eq!(tx.debug_log_level(), 1);

    // With `ctl:auditEngine=On`, this transaction's entry is written, with part E
    let mut tx = request_with_arg(&waf, "audit", "all");
    tx.process_request_headers();
    tx.process_logging().unwrap();
    assert!(!logged().is_empty());
    assert!(has_response_body(&tx));
    assert_eq!(tx.debug_log_level(), 9);
    assert_eq!(waf.config().audit_engine, AuditEngineStatus::RelevantOnly);
}

#[test]
fn invalid_ctl_audit_and_debug_values_are_parse_errors() {
    for ctl in [
        "auditEngine=Sometimes",
        "auditLogParts=+A",
        "debugLogLevel=10",
    ] {
        let mut parser = Parser::new();
        let rule = format!(r#"SecAction "id:1,phase:1,pass,ctl:{ctl}""#);
        assert!(parser.from_string(&rule).is_err(), "{ctl}");
    }
}

#[test]
fn ctl_rule_id_ranges_without_a_start_or_running_backwards_are_parse_errors() {
    // As SecRuleRemoveById rejects them; Go's ctl rejects them too, when it runs
    for ctl in ["ruleRemoveById=-5", "ruleRemoveById=5-1"] {
        let mut parser = Parser::new();
        let rule = format!(r#"SecAction "id:1,phase:1,pass,ctl:{ctl}""#);
        assert!(parser.from_string(&rule).is_err(), "{ctl}");
    }
}

#[test]
fn bodies_are_inspected_only_with_body_access() {
    for (access, inspected) in [("Off", false), ("On", true)] {
        let waf = waf(&format!(
            r#"
            SecRequestBodyAccess {access}
            SecResponseBodyAccess {access}
            SecResponseBodyMimeType text/plain
            SecRule REQUEST_BODY "@contains secret" "id:1,phase:2,deny,status:403"
            SecRule RESPONSE_BODY "@contains secret" "id:2,phase:4,deny,status:403"
            "#
        ));

        let mut tx = waf.new_transaction();
        tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
        tx.process_request_headers();
        let interruption = tx.process_request_body(b"a secret");
        assert_eq!(
            interruption.is_some(),
            inspected,
            "request, access {access}"
        );

        let mut tx = waf.new_transaction();
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");
        let interruption = tx.process_response_body(b"a secret");
        assert_eq!(
            interruption.is_some(),
            inspected,
            "response, access {access}"
        );
    }
}

#[test]
fn xml_is_the_parsed_request_xml() {
    let waf = waf(r#"
        SecRequestBodyAccess On
        SecRule REQUEST_HEADERS:Content-Type "^text/xml" "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
        SecRule XML:/* "@contains evil-text" "id:1,phase:2,deny,status:403"
        SecRule XML://@* "@contains evil-attr" "id:2,phase:2,deny,status:403"
    "#);

    for (body, rule_id) in [
        (r#"<a b="ok">evil-text</a>"#, Some(1)),
        (r#"<a b="evil-attr">ok</a>"#, Some(2)),
        (r#"<a b="ok">ok</a>"#, None),
    ] {
        let mut tx = waf.new_transaction();
        tx.add_request_header("Content-Type", "text/xml");
        tx.process_request_headers();
        let interruption = tx.process_request_body(body.as_bytes());
        assert_eq!(interruption.map(|i| i.rule_id), rule_id, "{body}");
    }
}

#[test]
fn matched_variables_describe_the_matches_of_the_current_rule() {
    let waf = waf(r#"
        SecRule ARGS "@rx ^evil" "id:1,phase:1,pass,setvar:tx.var=%{MATCHED_VAR},setvar:tx.name=%{MATCHED_VAR_NAME},chain"
            SecRule MATCHED_VARS_NAMES "@streq ARGS:q" "chain"
            SecRule MATCHED_VARS "@rx ^evil" "setvar:tx.chained=1"
        SecRule MATCHED_VARS "@rx ." "id:2,phase:1,pass,setvar:tx.leaked=1"
    "#);

    let mut tx = request_with_arg(&waf, "q", "evil");
    tx.process_request_headers();

    assert_eq!(tx_var(&tx, "var").as_deref(), Some("evil"));
    assert_eq!(tx_var(&tx, "name").as_deref(), Some("ARGS:q"));
    assert_eq!(tx_var(&tx, "chained").as_deref(), Some("1"));
    // MATCHED_VARS starts empty for each rule
    assert_eq!(tx_var(&tx, "leaked"), None);
}

#[test]
fn names_variables_are_the_keys_of_their_collections() {
    let waf = waf(r#"
        SecRequestBodyAccess On
        SecRule ARGS_NAMES "@streq evil_arg" "id:1,phase:1,deny,status:403"
        SecRule ARGS_GET_NAMES "@streq evil_get" "id:2,phase:1,deny,status:403"
        SecRule REQUEST_HEADERS_NAMES "@streq X-Evil" "id:3,phase:1,deny,status:403"
        SecRule REQUEST_COOKIES_NAMES "@streq evil_cookie" "id:4,phase:1,deny,status:403"
        SecRule ARGS_POST_NAMES "@streq evil_post" "id:5,phase:2,deny,status:403"
        SecRule RESPONSE_HEADERS_NAMES "@streq X-Evil" "id:6,phase:3,deny,status:403"
    "#);

    let mut tx = request_with_arg(&waf, "evil_arg", "x");
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(1));

    let mut tx = waf.new_transaction();
    tx.process_uri("/?evil_get=x", "GET", "HTTP/1.1");
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(2));

    let mut tx = waf.new_transaction();
    tx.add_request_header("X-Evil", "x");
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(3));

    let mut tx = waf.new_transaction();
    tx.add_request_header("Cookie", "evil_cookie=x");
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(4));

    let mut tx = waf.new_transaction();
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
    tx.process_request_headers();
    let interruption = tx.process_request_body(b"evil_post=x");
    assert_eq!(interruption.map(|i| i.rule_id), Some(5));

    let mut tx = waf.new_transaction();
    tx.add_response_header("X-Evil", "x");
    let interruption = tx.process_response_headers(200, "HTTP/1.1");
    assert_eq!(interruption.map(|i| i.rule_id), Some(6));
}

#[test]
fn args_combined_size_and_unique_id_describe_the_transaction() {
    let waf = waf(r#"
        SecRequestBodyAccess On
        SecRule ARGS_COMBINED_SIZE "@gt 9" "id:1,phase:2,deny,status:400"
        SecRule UNIQUE_ID "@streq tx-42" "id:2,phase:1,pass,setvar:tx.id_seen=1"
    "#);

    // ARGS_GET and ARGS_POST keys and values: "a" + "1234" + "b" + "5678" = 10 bytes
    let mut tx = waf.new_transaction_with_id("tx-42".to_string());
    tx.process_uri("/?a=1234", "POST", "HTTP/1.1");
    tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
    tx.process_request_headers();
    assert_eq!(tx_var(&tx, "id_seen").as_deref(), Some("1"));
    let interruption = tx.process_request_body(b"b=5678");
    assert_eq!(interruption.map(|i| i.rule_id), Some(1));

    let mut tx = waf.new_transaction();
    tx.process_uri("/?a=1234", "GET", "HTTP/1.1");
    tx.process_request_headers();
    assert_eq!(tx.process_request_body(b""), None);
}

#[test]
fn quoted_extended_multipart_filenames_are_invalid_quoting() {
    let waf = waf(r#"
        SecRequestBodyAccess On
        SecRule MULTIPART_INVALID_QUOTING "@eq 1" "id:1,phase:2,deny,status:400"
    "#);

    for (disposition, flagged) in [
        (r#"form-data; name="f"; filename*=UTF-8''a.txt"#, false),
        (r#"form-data; name="f"; filename*="UTF-8''a.txt""#, true),
    ] {
        let body = format!("--b\r\nContent-Disposition: {disposition}\r\n\r\nx\r\n--b--\r\n");
        let mut tx = waf.new_transaction();
        tx.add_request_header("Content-Type", "multipart/form-data; boundary=b");
        tx.process_request_headers();
        let interruption = tx.process_request_body(body.as_bytes());
        assert_eq!(interruption.is_some(), flagged, "{disposition}");
    }
}

#[test]
fn setenv_sets_env_for_later_rules() {
    let waf = waf(r#"
        SecAction "id:1,phase:1,pass,nolog,setenv:greeting=hello"
        SecRule ENV:greeting "@streq hello" "id:2,phase:1,deny,status:403"
    "#);

    let mut tx = waf.new_transaction();
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(2));
}

#[test]
fn rule_and_highest_severity_describe_the_rules_evaluated() {
    let waf = waf(r#"
        SecRule ARGS:q "@streq x" "id:7,phase:1,pass,rev:'3',severity:'WARNING',msg:'saw %{ARGS.q}',logdata:'data',setvar:'tx.rule=%{RULE.id}/%{RULE.msg}/%{RULE.rev}/%{RULE.severity}/%{RULE.logdata}'"
        SecRule ARGS:q "@streq x" "id:8,phase:1,pass,severity:'CRITICAL'"
        SecRule ARGS:q "@streq x" "id:9,phase:1,pass,severity:'NOTICE'"
        SecAction "id:10,phase:1,pass,setvar:tx.highest=%{HIGHEST_SEVERITY}"
    "#);

    let tx = waf.new_transaction();
    assert_eq!(
        tx.get_variable(coraza::RuleVariable::HighestSeverity, None)
            .as_deref(),
        Some("255")
    );

    let mut tx = request_with_arg(&waf, "q", "x");
    tx.process_request_headers();
    assert_eq!(
        tx_var(&tx, "rule").as_deref(),
        Some("7/saw x/3/warning/data")
    );
    assert_eq!(tx_var(&tx, "highest").as_deref(), Some("2"));
}

#[test]
fn variables_go_only_ever_sets_to_zero_are_zero() {
    use coraza::RuleVariable::*;

    let tx = waf("").new_transaction();
    for variable in [
        UrlencodedError,
        FullRequestLength,
        Duration,
        MultipartDataAfter,
        OutboundDataError,
    ] {
        assert_eq!(
            tx.get_variable(variable, None).as_deref(),
            Some("0"),
            "{variable}"
        );
    }
}

#[test]
fn time_variables_are_set_when_the_transaction_starts() {
    use coraza::RuleVariable::*;

    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let tx = waf("").new_transaction();
    let get = |variable| tx.get_variable(variable, None).unwrap();

    let epoch: u64 = get(TimeEpoch).parse().unwrap();
    assert!(epoch >= before && epoch <= before + 5);
    assert_eq!(
        get(Time),
        format!("{}:{}:{}", get(TimeHour), get(TimeMin), get(TimeSec))
    );
    assert!((1..=31).contains(&get(TimeDay).parse::<u8>().unwrap()));
    assert!((1..=12).contains(&get(TimeMon).parse::<u8>().unwrap()));
    assert!((0..=6).contains(&get(TimeWday).parse::<u8>().unwrap()));
    assert!(get(TimeYear).parse::<u16>().unwrap() >= 2026);
}

#[test]
fn path_arguments_are_in_args_path_and_args() {
    let waf = waf(r#"
        SecRule ARGS_PATH:id "@streq 42" "id:1,phase:1,pass,setvar:tx.path=1"
        SecRule ARGS:id "@streq 42" "id:2,phase:1,pass,setvar:tx.args=1"
    "#);

    let mut tx = waf.new_transaction();
    tx.add_path_argument("id", "42");
    tx.process_request_headers();

    assert_eq!(tx_var(&tx, "path").as_deref(), Some("1"));
    assert_eq!(tx_var(&tx, "args").as_deref(), Some("1"));
}

#[test]
fn multipart_part_names_and_filenames_are_variables() {
    let waf = waf(r#"
        SecRequestBodyAccess On
        SecRule MULTIPART_NAME "@streq upload" "id:1,phase:2,pass,setvar:tx.name=1"
        SecRule MULTIPART_FILENAME:upload "@streq evil.php" "id:2,phase:2,deny,status:403"
    "#);

    let body = "--b\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"evil.php\"\r\n\r\n<?php\r\n--b--\r\n";
    let mut tx = waf.new_transaction();
    tx.add_request_header("Content-Type", "multipart/form-data; boundary=b");
    tx.process_request_headers();
    let interruption = tx.process_request_body(body.as_bytes());

    assert_eq!(tx_var(&tx, "name").as_deref(), Some("1"));
    assert_eq!(interruption.map(|i| i.rule_id), Some(2));
}

/// A transaction of `waf` that uploaded the file `a.txt`, holding `hello`, through phase 2.
fn upload(waf: &Waf) -> Transaction {
    let body = "--b\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"a.txt\"\r\n\r\nhello\r\n--b--\r\n";
    let mut tx = waf.new_transaction();
    tx.add_request_header("Content-Type", "multipart/form-data; boundary=b");
    tx.process_request_headers();
    tx.process_request_body(body.as_bytes());
    tx
}

/// The contents of the files in `dir`.
fn files_in(dir: &std::path::Path) -> Vec<Vec<u8>> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| std::fs::read(entry.unwrap().path()).unwrap())
        .collect()
}

#[test]
fn uploaded_files_are_stored_in_the_upload_dir_and_listed_in_files_tmpnames() {
    let dir = tempfile::tempdir().unwrap();
    let waf = waf(&format!(
        r#"
        SecRequestBodyAccess On
        SecUploadDir {}
        SecRule FILES_TMPNAMES "@rx ." "id:1,phase:2,deny,status:403"
        "#,
        dir.path().display()
    ));

    let tx = upload(&waf);

    assert_eq!(tx.interruption().map(|i| i.rule_id), Some(1));
    assert_eq!(files_in(dir.path()), [b"hello"]);
}

#[cfg(unix)]
#[test]
fn uploaded_files_are_readable_by_their_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    // As Go's os.CreateTemp creates them
    let dir = tempfile::tempdir().unwrap();
    let waf = waf(&format!(
        r#"
        SecRequestBodyAccess On
        SecUploadDir {}
        "#,
        dir.path().display()
    ));

    // Kept until the end: the transaction removes its uploads when dropped
    let _tx = upload(&waf);

    let modes: Vec<u32> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().metadata().unwrap().permissions().mode() & 0o777)
        .collect();
    assert_eq!(modes, [0o600]);
}

#[test]
fn uploaded_files_are_removed_when_the_transaction_ends_unless_kept() {
    // As Go's Transaction.Close does
    for (keep_files, kept) in [("Off", 0), ("On", 1)] {
        let dir = tempfile::tempdir().unwrap();
        let waf = waf(&format!(
            r#"
            SecRequestBodyAccess On
            SecUploadDir {}
            SecUploadKeepFiles {keep_files}
            "#,
            dir.path().display()
        ));

        drop(upload(&waf));

        assert_eq!(files_in(dir.path()).len(), kept, "{keep_files}");
    }
}

#[test]
fn request_bodies_reaching_the_limit_are_rejected_or_cut() {
    for (action, interrupted, seen) in [
        ("Reject", Some(413), None),
        ("ProcessPartial", None, Some("1")),
    ] {
        let waf = waf(&format!(
            r#"
            SecRequestBodyAccess On
            SecRequestBodyLimit 10
            SecRequestBodyLimitAction {action}
            SecRule REQUEST_BODY "@streq 0123456789" "id:1,phase:2,pass,setvar:tx.seen=1"
            "#
        ));

        let mut tx = waf.new_transaction();
        tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
        tx.process_request_headers();
        let interruption = tx.process_request_body(b"0123456789abcdef");

        assert_eq!(interruption.map(|i| i.status), interrupted, "{action}");
        assert_eq!(tx_var(&tx, "seen").as_deref(), seen, "{action}");
        assert_eq!(
            tx.get_variable(coraza::RuleVariable::InboundDataError, None)
                .as_deref(),
            Some("1"),
            "{action}"
        );
    }
}

#[test]
fn response_bodies_reaching_the_limit_are_rejected_or_cut() {
    for (action, interrupted, seen) in [
        ("Reject", Some(500), None),
        ("ProcessPartial", None, Some("1")),
    ] {
        let waf = waf(&format!(
            r#"
            SecResponseBodyAccess On
            SecResponseBodyMimeType text/plain
            SecResponseBodyLimit 10
            SecResponseBodyLimitAction {action}
            SecRule RESPONSE_BODY "@streq 0123456789" "id:1,phase:4,pass,setvar:tx.seen=1"
            "#
        ));

        let mut tx = waf.new_transaction();
        tx.add_response_header("Content-Type", "text/plain");
        tx.process_response_headers(200, "HTTP/1.1");
        let interruption = tx.process_response_body(b"0123456789abcdef");

        assert_eq!(interruption.map(|i| i.status), interrupted, "{action}");
        assert_eq!(tx_var(&tx, "seen").as_deref(), seen, "{action}");
        assert_eq!(
            tx.get_variable(coraza::RuleVariable::OutboundDataError, None)
                .as_deref(),
            Some("1"),
            "{action}"
        );
    }
}

#[test]
fn rules_can_be_removed_by_id_msg_and_tag() {
    let waf = waf(r#"
        SecRule ARGS "@streq x" "id:1,phase:1,deny,status:403"
        SecRule ARGS "@streq x" "id:2,phase:1,deny,status:403"
        SecRule ARGS "@streq x" "id:3,phase:1,deny,status:403"
        SecRule ARGS "@streq x" "id:4,phase:1,deny,status:403,msg:'remove me'"
        SecRule ARGS "@streq x" "id:5,phase:1,deny,status:403,tag:'legacy'"
        SecRule ARGS "@streq x" "id:6,phase:1,deny,status:403"
        SecRuleRemoveById 1 2-3
        SecRuleRemoveByMsg "remove me"
        SecRuleRemoveByTag legacy
    "#);

    let mut tx = request_with_arg(&waf, "q", "x");
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(6));
    assert_eq!(waf.rule_count(), 1);
}

#[test]
fn update_action_by_id_changes_the_actions_of_rules() {
    let waf = waf(r#"
        SecRule ARGS:a "@streq x" "id:1,phase:1,deny,status:403"
        SecRule ARGS:b "@streq x" "id:2,phase:1,pass"
        SecRule ARGS:b "@streq x" "id:3,phase:1,pass"
        SecRuleUpdateActionById 1 "pass,setvar:tx.one=1"
        SecRuleUpdateActionById 2-3 "setvar:tx.two=+1"
    "#);

    let mut tx = request_with_arg(&waf, "a", "x");
    assert!(tx.process_request_headers().is_none());
    assert_eq!(tx_var(&tx, "one").as_deref(), Some("1"));

    let mut tx = request_with_arg(&waf, "b", "x");
    tx.process_request_headers();
    assert_eq!(tx_var(&tx, "two").as_deref(), Some("2"));

    let mut parser = Parser::new();
    let err = parser
        .from_string(r#"SecRuleUpdateActionById 404 "pass""#)
        .unwrap_err();
    assert!(err.message.contains("404"), "{}", err.message);
}

#[test]
fn datasets_feed_the_dataset_operators() {
    let waf = waf(r#"
        SecDataset bad_words `
        # comments and blank lines are skipped
        evil

        nasty
        `
        SecDataset bad_ips `
        10.0.0.0/8
        192.168.1.1
        `
        SecRule ARGS:q "@pmFromDataset bad_words" "id:1,phase:1,deny,status:403"
        SecRule ARGS:ip "@ipMatchFromDataset bad_ips" "id:2,phase:1,deny,status:403"
    "#);

    let mut tx = request_with_arg(&waf, "q", "something NASTY here");
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(1));
    let mut tx = request_with_arg(&waf, "ip", "10.2.3.4");
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(2));
    let mut tx = request_with_arg(&waf, "q", "fine");
    assert!(tx.process_request_headers().is_none());

    let mut parser = Parser::new();
    let err = parser
        .from_string(r#"SecRule ARGS "@pmFromDataset missing" "id:1,phase:1,pass""#)
        .unwrap_err();
    assert!(err.message.contains("missing"), "{}", err.message);
}

#[test]
fn logging_and_body_directives_set_their_settings() {
    let mut parser = Parser::new();
    parser
        .from_string(
            r#"
            SecDebugLog /var/log/coraza/debug.log
            SecAuditLogDirMode 0700
            SecAuditLogFileMode 0600
            SecAuditLogStorageDir /var/log/coraza/audit
            SecRemoteRulesFailAction Warn
            SecResponseBodyMimeType text/plain text/html
            SecResponseBodyMimeTypesClear
            "#,
        )
        .unwrap();

    let config = parser.config();
    assert_eq!(config.debug_log, "/var/log/coraza/debug.log");
    assert_eq!(config.audit_log_dir_mode, 0o700);
    assert_eq!(config.audit_log_file_mode, 0o600);
    assert_eq!(config.audit_log_storage_dir, "/var/log/coraza/audit");
    assert!(config.response_body_mime_types.is_empty());

    for directive in [
        "SecAuditLogDirMode 0799",
        "SecRemoteRulesFailAction Explode",
        "SecResponseBodyMimeTypesClear text/plain",
        "SecIgnoreRuleCompilationErrors Sometimes",
    ] {
        assert!(Parser::new().from_string(directive).is_err(), "{directive}");
    }
}

#[test]
fn ignoring_rule_compilation_errors_skips_failing_directives() {
    let mut parser = Parser::new();
    parser
        .from_string(
            r#"
            SecIgnoreRuleCompilationErrors On
            SecRule ARGS "@nosuchop x" "id:1"
            SecRule ARGS "@streq x" "id:2,phase:1,deny,status:403"
            "#,
        )
        .unwrap();

    assert_eq!(parser.skipped().len(), 1);
    assert_eq!(parser.into_waf().unwrap().rule_count(), 1);
}

#[test]
fn directives_go_ignores_are_accepted() {
    let mut parser = Parser::new();
    parser
        .from_string(
            r#"
            SecArgumentSeparator &
            SecConnEngine Off
            SecConnReadStateLimit 50
            SecConnWriteStateLimit 50
            SecCookieFormat 0
            SecGsbLookupDb /etc/gsb.dat
            SecHashEngine Off
            SecHashKey rand KeyOnly
            SecHashMethodPm HashHref "foo bar"
            SecHashMethodRx HashHref "^/"
            SecHashParam hmac
            SecHttpBlKey abcdefghijkl
            SecPcreMatchLimit 1000
            SecPcreMatchLimitRecursion 1000
            SecRulePerfTime 1000
            SecRuleScript /etc/script.lua
            SecRuleUpdateTargetByMsg "a message" ARGS
            SecTmpDir /tmp
            SecUnicodeMap unicode.mapping 20127
            "#,
        )
        .unwrap();

    let err = Parser::new()
        .from_string("SecRemoteRules key https://example.com/rules.conf")
        .unwrap_err();
    assert!(err.message.contains("not supported"), "{}", err.message);
}

#[test]
fn matched_rules_give_go_error_log_lines() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules.conf");
    std::fs::write(&rules, "# rules\n\nSecRule ARGS:q \"@rx ^ev(il)\" \"id:1,phase:1,pass,log,capture,msg:'Evil found',logdata:'Matched %{MATCHED_VAR}',tag:'attack',tag:'evil',rev:'2',ver:'v1',severity:'CRITICAL',maturity:9,accuracy:8\"\nSecRule ARGS:q \"@rx ^evil\" \"id:2,phase:1,deny,status:403\"\n").unwrap();
    std::fs::write(
        dir.path().join("main.conf"),
        "SecRuleEngine On\nInclude rules.conf\n",
    )
    .unwrap();
    let mut parser = Parser::new();
    parser.from_file(dir.path().join("main.conf")).unwrap();
    let waf = parser.into_waf().unwrap();

    let mut tx = waf.new_transaction_with_id("tx-1".to_string());
    tx.process_connection("10.0.0.1", 4242, "10.0.0.2", 80);
    tx.process_uri("/x?q=evil", "GET", "HTTP/1.1");
    tx.process_request_headers();

    let file = rules.display();
    let lines: Vec<String> = tx.matched_rules().iter().map(|m| m.error_log()).collect();
    assert_eq!(
        lines,
        [
            format!(
                r#"[client "10.0.0.1"] Coraza: Warning. Evil found [file "{file}"] [line "3"] [id "1"] [rev "2"] [msg "Evil found"] [data "Matched evil"] [severity "critical"] [ver "v1"] [maturity "9"] [accuracy "8"] [tag "attack"] [tag "evil"] [hostname "10.0.0.2"] [uri "/x?q=evil"] [unique_id "tx-1"]"#
            ),
            format!(
                r#"[client "10.0.0.1"] Coraza: Access denied (phase 1).  [file "{file}"] [line "4"] [id "2"] [rev ""] [msg ""] [data ""] [severity "unknown"] [ver ""] [maturity "0"] [accuracy "0"] [hostname "10.0.0.2"] [uri "/x?q=evil"] [unique_id "tx-1"]"#
            ),
        ]
    );
}

fn audited_waf(dir: &std::path::Path, extra: &str) -> Waf {
    waf(&format!(
        r#"
        SecRuleEngine On
        SecAuditEngine RelevantOnly
        SecAuditLog {}
        SecAuditLogParts ABFHKZ
        {extra}
        SecRule ARGS:q "@streq evil" "id:1,phase:1,deny,status:403,log,auditlog,msg:'Evil'"
        "#,
        dir.join("audit.log").display()
    ))
}

fn audit_request(waf: &Waf, id: &str, q: &str) -> Transaction {
    let mut tx = waf.new_transaction_with_id(id.to_string());
    tx.process_connection("10.0.0.1", 4242, "10.0.0.2", 80);
    tx.process_uri(&format!("/x?q={q}"), "GET", "HTTP/1.1");
    tx.add_request_header("Host", "example.com");
    tx.process_request_headers();
    tx.process_logging().unwrap();
    tx
}

#[test]
fn relevant_transactions_are_audit_logged_natively() {
    let dir = tempfile::tempdir().unwrap();
    let waf = audited_waf(dir.path(), "");

    audit_request(&waf, "tx-benign", "fine");
    audit_request(&waf, "tx-evil", "evil");

    let log = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    assert!(!log.contains("tx-benign"), "{log}");
    let boundary = log.lines().next().unwrap().strip_suffix("A--").unwrap();
    for expected in [
        format!("{boundary}A--\n"),
        "tx-evil 10.0.0.1 4242 10.0.0.2 80\n".to_string(),
        format!("{boundary}B--\nGET /x?q=evil HTTP/1.1\nhost: example.com\n\n"),
        format!("{boundary}H--\n[client \"10.0.0.1\"] Coraza: Access denied (phase 1). Evil "),
        format!("{boundary}K--\nSecRule ARGS:q \"@streq evil\""),
        format!("{boundary}Z--\n"),
    ] {
        assert!(log.contains(&expected), "{expected:?} not in {log}");
    }
}

#[test]
fn detection_only_audit_logs_by_the_status_a_rule_would_have_set() {
    let dir = tempfile::tempdir().unwrap();
    let waf = audited_waf(
        dir.path(),
        r#"SecRuleEngine DetectionOnly
        SecAuditLogRelevantStatus "^4""#,
    );

    let tx = audit_request(&waf, "tx-evil", "evil");

    // As in Go Coraza, the status is the one rule 1's deny would have set: there is no
    // response status, and the transaction wasn't interrupted
    assert!(tx.interruption().is_none());
    let log = std::fs::read_to_string(dir.path().join("audit.log")).unwrap_or_default();
    assert!(log.contains("tx-evil"), "{log}");
}

#[test]
fn audit_log_entries_can_be_json() {
    let dir = tempfile::tempdir().unwrap();
    let waf = audited_waf(dir.path(), "SecAuditLogFormat JSON");

    audit_request(&waf, "tx-evil", "evil");

    let log = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    let entry: serde_json::Value = serde_json::from_str(log.trim_end()).unwrap();
    assert_eq!(entry["transaction"]["id"], "tx-evil");
    assert_eq!(entry["transaction"]["client_ip"], "10.0.0.1");
    assert_eq!(entry["transaction"]["request"]["uri"], "/x?q=evil");
    assert_eq!(entry["transaction"]["is_interrupted"], true);
    assert_eq!(entry["messages"][0]["data"]["id"], 1);
    assert_eq!(entry["messages"][0]["message"], "Evil");
}

#[test]
fn concurrent_audit_logs_write_a_file_per_entry() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let waf = audited_waf(
        dir.path(),
        &format!(
            "SecAuditLogType Concurrent\nSecAuditLogStorageDir {}",
            store.display()
        ),
    );

    audit_request(&waf, "tx-evil", "evil");

    let index = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    let path = index.trim_end().rsplit(" - ").next().unwrap();
    assert!(path.starts_with(&store.display().to_string()), "{index}");
    assert!(path.ends_with("-tx-evil"), "{index}");
    let entry = std::fs::read_to_string(path).unwrap();
    assert!(entry.contains("[id \"1\"]"), "{entry}");
}

#[test]
fn https_audit_logs_are_not_supported() {
    let mut parser = Parser::new();
    parser
        .from_string(
            "SecAuditEngine On\nSecAuditLogType HTTPS\nSecAuditLog https://example.com/log",
        )
        .unwrap();
    let err = parser.into_waf().unwrap_err();
    assert!(err.to_string().contains("HTTPS"), "{err}");
}

#[test]
fn audit_log_entries_can_be_ocsf() {
    let dir = tempfile::tempdir().unwrap();
    let waf = audited_waf(dir.path(), "SecAuditLogFormat OCSF");

    audit_request(&waf, "tx-evil", "evil");

    let log = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    let event: serde_json::Value = serde_json::from_str(log.trim_end()).unwrap();
    assert_eq!(event["class_uid"], 6001);
    assert_eq!(event["type_uid"], 600102);
    assert_eq!(event["action"], "Denied");
    assert_eq!(event["action_id"], 2);
    assert_eq!(event["http_request"]["uid"], "tx-evil");
    assert_eq!(event["http_request"]["url"]["url_string"], "/x?q=evil");
    assert_eq!(event["src_endpoint"]["ip"], "10.0.0.1");
    assert_eq!(event["enrichments"][0]["name"], "Evil");
    assert_eq!(event["message"], "Evil");
    // Zero values are left out, as protobuf's JSON tags do in Go
    assert!(event["http_request"].get("length").is_none(), "{event}");
}

#[test]
fn audit_log_entries_list_the_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let waf = audited_waf(dir.path(), "SecAuditLogFormat OCSF");

    audit_request(&waf, "tx-evil", "evil");

    let log = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    let event: serde_json::Value = serde_json::from_str(log.trim_end()).unwrap();
    assert_eq!(event["http_request"]["args"], "q=evil,");
}

#[test]
fn audit_log_entries_can_go_to_syslog() {
    let dir = tempfile::tempdir().unwrap();
    let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let address = server.local_addr().unwrap();
    let waf = waf(&format!(
        r#"
        SecRuleEngine On
        SecAuditEngine RelevantOnly
        SecAuditLogType Syslog
        SecAuditLog udp://{address}
        SecAuditLogParts ABHZ
        SecRule ARGS:q "@streq evil" "id:1,phase:1,deny,status:403,log,auditlog,msg:'Evil'"
        "#
    ));
    let _ = dir;

    audit_request(&waf, "tx-evil", "evil");

    let mut buffer = [0; 65_536];
    let received = server.recv(&mut buffer).unwrap();
    let message = String::from_utf8_lossy(&buffer[..received]);
    // local0.err, as the transaction was interrupted
    assert!(message.starts_with("<131>"), "{message}");
    assert!(message.contains(" com.coraza.waf["), "{message}");
    assert!(message.contains("[id \"1\"]"), "{message}");
}

#[test]
fn restpath_fills_args_path_from_the_path_template() {
    let waf = waf(r#"
        SecRule REQUEST_FILENAME "@restpath /users/{id}/{name}" "id:1,phase:1,pass,nolog"
        SecRule ARGS_PATH:id "@streq 123" "id:2,phase:1,pass,setvar:tx.id=%{ARGS_PATH.id}"
        SecRule ARGS:name "@streq juan" "id:3,phase:1,deny,status:403"
    "#);

    let mut tx = waf.new_transaction();
    tx.process_uri("/users/123/juan?q=1", "GET", "HTTP/1.1");
    let interruption = tx.process_request_headers();

    assert_eq!(tx_var(&tx, "id").as_deref(), Some("123"));
    assert_eq!(interruption.map(|i| i.rule_id), Some(3));
}

#[test]
fn validate_nid_finds_valid_national_ids() {
    let waf = waf(r#"
        SecRule ARGS:rut "@validateNid cl [0-9.]+-[0-9kK]" "id:1,phase:1,pass,capture,setvar:tx.rut=%{TX.0}"
        SecRule ARGS:ssn "@validateNid us [0-9-]+" "id:2,phase:1,deny,status:403"
    "#);

    let mut tx = request_with_arg(&waf, "rut", "mine is 10727393-K");
    assert!(tx.process_request_headers().is_none());
    assert_eq!(tx_var(&tx, "rut").as_deref(), Some("10727393-K"));

    let mut tx = request_with_arg(&waf, "ssn", "078-05-1120");
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(2));
    // Same digits throughout, or in sequence, are not valid
    for ssn in ["111-11-1111", "123-45-6789"] {
        let mut tx = request_with_arg(&waf, "ssn", ssn);
        assert!(tx.process_request_headers().is_none(), "{ssn}");
    }
}

#[test]
fn geo_lookup_always_matches_as_in_go() {
    let waf = waf(r#"SecRule REMOTE_ADDR "@geoLookup" "id:1,phase:1,deny,status:403""#);
    let mut tx = waf.new_transaction();
    tx.process_connection("192.0.2.1", 1, "192.0.2.2", 80);
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(1));
}

#[test]
fn rbl_does_not_match_names_that_do_not_resolve() {
    let waf = waf(r#"SecRule REMOTE_ADDR "@rbl rbl.invalid" "id:1,phase:1,deny,status:403""#);
    let mut tx = waf.new_transaction();
    tx.process_connection("192.0.2.1", 1, "192.0.2.2", 80);
    assert!(tx.process_request_headers().is_none());
}

#[cfg(unix)]
#[test]
fn inspect_file_runs_a_program_on_the_value() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("inspect.sh");
    std::fs::write(&script, "#!/bin/sh\necho \"$1\"\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let waf = waf(&format!(
        r#"SecRule ARGS:f "@inspectFile {}" "id:1,phase:1,deny,status:403""#,
        script.display()
    ));

    // As in Go, it matches unless the program's output starts with 1
    let mut tx = request_with_arg(&waf, "f", "0 virus found");
    assert_eq!(tx.process_request_headers().map(|i| i.rule_id), Some(1));
    let mut tx = request_with_arg(&waf, "f", "1 clean");
    assert!(tx.process_request_headers().is_none());
}

#[test]
fn extended_multipart_filenames_are_decoded_with_their_charset_and_language() {
    use coraza::RuleVariable::{
        Files, MultipartFilename, MultipartFilenameCharset, MultipartFilenameLanguage,
    };

    let waf = waf("SecRequestBodyAccess On");
    let body = "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"plain.txt\"; filename*=UTF-8'en'%E2%82%AC.php\r\n\r\nx\r\n--b--\r\n";
    let mut tx = waf.new_transaction();
    tx.add_request_header("Content-Type", "multipart/form-data; boundary=b");
    tx.process_request_headers();
    tx.process_request_body(body.as_bytes());

    let sorted = |variable| {
        let mut values = values(&tx, variable, "f");
        values.sort();
        values
    };
    assert_eq!(sorted(MultipartFilename), ["plain.txt", "€.php"]);
    assert_eq!(sorted(MultipartFilenameCharset), ["UTF-8"]);
    assert_eq!(sorted(MultipartFilenameLanguage), ["en"]);
    assert_eq!(values(&tx, Files, "f"), ["€.php"]);
    assert_eq!(
        tx.get_variable(coraza::RuleVariable::MultipartStrictError, None)
            .as_deref(),
        Some("")
    );
}

#[test]
fn variables_have_go_names() {
    let mut parser = Parser::new();
    parser
        .from_string(
            r#"SecRule RES_BODY_ERROR|RES_BODY_ERROR_MSG|RES_BODY_PROCESSOR|RES_BODY_PROCESSOR_ERROR|RES_BODY_PROCESSOR_ERROR_MSG|FILES_TMPNAMES "@rx x" "id:1,phase:4,pass""#,
        )
        .unwrap();
}

#[test]
fn transformations_producing_invalid_utf8_are_safe() {
    // base64 of [0xff, 0xfe], a hex escape, a SHA-1 digest and a URL escape: each yields
    // bytes that aren't UTF-8, then a transformation reads them as text
    let waf = waf(r#"
        SecRule ARGS:a "@rx x" "id:1,phase:1,pass,t:base64Decode,t:removeWhitespace"
        SecRule ARGS:b "@rx x" "id:2,phase:1,pass,t:hexDecode,t:lowercase"
        SecRule ARGS:c "@rx x" "id:3,phase:1,pass,t:sha1,t:trim"
        SecRule ARGS:d "@rx x" "id:4,phase:1,pass,t:urlDecode,t:compressWhitespace"
    "#);

    let mut tx = waf.new_transaction();
    tx.add_get_argument("a", "//4=");
    tx.add_get_argument("b", "fffe");
    tx.add_get_argument("c", "anything");
    tx.add_get_argument("d", "%ff%fe");
    assert!(tx.process_request_headers().is_none());
}

#[test]
fn ctl_removes_targets_from_rules_for_the_transaction() {
    // CRS 941010 removes REQUEST_FILENAME from the XSS rules this way
    let waf = waf(r#"
        SecRule REQUEST_FILENAME "@unconditionalMatch" "id:1,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=t;REQUEST_FILENAME,ctl:ruleRemoveTargetById=3;ARGS:/^IGN/"
        SecRule REQUEST_FILENAME|ARGS "@contains evil" "id:2,phase:1,pass,tag:t,setvar:tx.two=+1"
        SecRule &ARGS "@eq 1" "id:3,phase:1,pass,chain"
            SecRule ARGS "@contains evil" "t:none,setvar:tx.three=1"
    "#);

    let run = |uri: &str| {
        let mut tx = waf.new_transaction();
        tx.process_uri(uri, "GET", "HTTP/1.1");
        tx.process_request_headers();
        (tx_var(&tx, "two"), tx_var(&tx, "three"))
    };
    // REQUEST_FILENAME is no longer inspected by rule 2, ARGS still is
    assert_eq!(run("/evil").0, None);
    assert_eq!(run("/x?a=evil").0.as_deref(), Some("1"));
    // A regex key, matched whatever its case, removes the arguments it selects, also from
    // a chain's links and from a count
    assert_eq!(run("/x?a=1&ignored=evil").1, None);
    assert_eq!(run("/x?ignored=1&a=evil").1.as_deref(), Some("1"));
}

#[test]
fn ctl_removes_a_target_from_every_rule_in_an_id_range() {
    // As in Go, ruleRemoveTargetById takes an id or a range, as ruleRemoveById does
    let waf = waf(r#"
        SecAction "id:1,phase:1,pass,nolog,ctl:ruleRemoveTargetById=10-15;ARGS"
        SecRule ARGS "@contains evil" "id:10,phase:1,pass,setvar:tx.ten=1"
        SecRule ARGS "@contains evil" "id:15,phase:1,pass,setvar:tx.fifteen=1"
        SecRule ARGS "@contains evil" "id:20,phase:1,pass,setvar:tx.twenty=1"
    "#);

    let mut tx = waf.new_transaction();
    tx.process_uri("/x?a=evil", "GET", "HTTP/1.1");
    tx.process_request_headers();

    assert_eq!(tx_var(&tx, "ten"), None);
    assert_eq!(tx_var(&tx, "fifteen"), None);
    assert_eq!(tx_var(&tx, "twenty").as_deref(), Some("1"));
}
