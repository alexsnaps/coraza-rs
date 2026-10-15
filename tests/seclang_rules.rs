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

/// Coraza's rule 200001 (`coraza.conf-recommended`): as in Go, JSON bodies are parsed only
/// once a rule selects the JSON body processor.
const JSON_PROCESSOR: &str = r#"SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON""#;

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
    let waf = waf(r#"
        SecRequestBodyAccess On
        SecRule REQUEST_BODY "@contains attack" "id:1,phase:2,deny,status:403"
    "#);

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
    let interruption = tx.process_request_body(b"{not json").unwrap();

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
    tx.args_mut().add("a", "x");
    tx.args_mut().add("b", "x");
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
    assert_eq!(tx.process_request_body(b"").unwrap(), None);
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
    assert_eq!(tx.args_get().get("a"), vec!["1", "2"]);
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
        let interruption = tx.process_request_body(body.as_bytes()).unwrap();
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
        let interruption = tx.process_request_body(body.as_bytes()).unwrap();
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
    use coraza::types::{AuditLogFormat, AuditLogType, parse_audit_log_parts};

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
    assert_eq!(
        config.audit_log_parts,
        parse_audit_log_parts("ABIJDEFHZ").unwrap()
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
        let interruption = tx.process_request_body(body.as_bytes()).unwrap();
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
        let interruption = tx.process_request_body(body.as_bytes()).unwrap();
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
        tx.process_request_body(b"a=evil")
            .unwrap()
            .map(|i| i.rule_id),
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
        SecRule RESBODY_ERROR "@eq 1" "id:2,phase:4,deny,status:500"
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

    let waf = waf(r#"
        SecAuditEngine RelevantOnly
        SecAuditLogParts ABZ
        SecDebugLogLevel 1
        SecRule ARGS:audit "@streq all" "id:1,phase:1,pass,nolog,ctl:auditEngine=On,ctl:auditLogParts=+E,ctl:debugLogLevel=9"
    "#);

    let tx = request_with_arg(&waf, "audit", "none");
    assert_eq!(tx.audit_engine(), AuditEngineStatus::RelevantOnly);
    assert_eq!(tx.debug_log_level(), 1);

    let mut tx = request_with_arg(&waf, "audit", "all");
    tx.process_request_headers();
    assert_eq!(tx.audit_engine(), AuditEngineStatus::On);
    assert!(
        tx.audit_log_parts()
            .contains(&AuditLogPart::IntermediaryResponseBody)
    );
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
        tx.add_request_header("Content-Type", "text/plain");
        tx.process_request_headers();
        let interruption = tx.process_request_body(b"a secret").unwrap();
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
        let interruption = tx.process_request_body(body.as_bytes()).unwrap();
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
