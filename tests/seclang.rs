// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for SecLang parser
//!
//! Ported from:
//! - coraza/internal/seclang/parser_test.go
//! - coraza/internal/seclang/rule_parser_test.go
//! - coraza/internal/seclang/directives_test.go

use coraza::seclang::{AuditEngineStatus, Parser};
use coraza::types::{BodyLimitAction, RuleEngineStatus};
use std::fs;

/// Test that directive names are case-insensitive
#[test]
fn test_directives_case_insensitive() {
    let mut parser = Parser::new();

    // Mix of cases should all work
    let result = parser.from_string("seCwEbAppid test123");
    assert!(result.is_ok(), "Case-insensitive directive should parse");
    assert_eq!(parser.config().web_app_id, "test123");

    let result = parser.from_string("SECRULEENGINE On");
    assert!(result.is_ok());
    assert_eq!(parser.config().rule_engine, RuleEngineStatus::On);

    let result = parser.from_string("secRequestBodyAccess on");
    assert!(result.is_ok());
    assert!(parser.config().request_body_access);
}

/// Test that unknown directives return errors
#[test]
fn test_invalid_directive() {
    let mut parser = Parser::new();

    // Unknown directive should error
    let result = parser.from_string("Unknown Rule");
    assert!(result.is_err(), "Unknown directive should fail");

    // Typo in directive name should error
    let result = parser.from_string("SecEngineRule");
    assert!(result.is_err(), "Misspelled directive should fail");
}

/// Test comments with backticks don't trigger multi-line mode
#[test]
fn test_comments_with_backticks() {
    let mut parser = Parser::new();

    // Two backticks in comment - should be ignored
    let input = r#"# This comment has a trailing backtick `here`
SecRuleEngine On
"#;
    let result = parser.from_string(input);
    assert!(result.is_ok(), "Backticks in comments should be ignored");

    // Single backtick in comment - should be ignored
    let input = "# The rule 942510 is related to 942110 which catches a single ' or `";
    let result = parser.from_string(input);
    assert!(
        result.is_ok(),
        "Single backtick in comment should be ignored"
    );
}

/// Test unclosed backtick in SecDataset triggers error
#[test]
fn test_error_with_backticks() {
    let mut parser = Parser::new();

    // Unclosed backtick should error
    let result = parser.from_string("SecDataset test `");
    assert!(result.is_err(), "Unclosed backtick should fail");
}

/// Test line continuations with backslash
#[test]
fn test_line_continuations() {
    let mut parser = Parser::new();

    // Line continuation should work
    let input = "SecRuleEngine \\\nOn";
    let result = parser.from_string(input);
    assert!(result.is_ok(), "Line continuation should work");
    assert_eq!(parser.config().rule_engine, RuleEngineStatus::On);

    // Multiple continuations
    let input = "SecWebAppId \\\ntest\\\n123";
    let result = parser.from_string(input);
    assert!(result.is_ok(), "Multiple continuations should work");
    assert_eq!(parser.config().web_app_id, "test123");
}

/// Test Include directive with non-existent file
#[test]
fn test_include_nonexistent_file() {
    let mut parser = Parser::new();

    let result = parser.from_file("/tmp/coraza-test-nonexistent-file.conf");
    assert!(result.is_err(), "Include non-existent file should fail");
}

/// Test Include directive with glob patterns
#[test]
fn test_include_glob_patterns() {
    // Create temporary test files
    let temp_dir = std::env::temp_dir().join("coraza-test-glob");
    fs::create_dir_all(&temp_dir).unwrap();

    let file1 = temp_dir.join("test1.conf");
    let file2 = temp_dir.join("test2.conf");
    let file3 = temp_dir.join("other.txt");

    fs::write(&file1, "SecRuleEngine On\n").unwrap();
    fs::write(&file2, "SecWebAppId test\n").unwrap();
    fs::write(&file3, "SecRequestBodyAccess On\n").unwrap();

    let mut parser = Parser::new();

    // Include *.conf should match file1 and file2 but not file3
    let pattern = temp_dir.join("*.conf").to_string_lossy().to_string();
    let result = parser.from_file(&pattern);
    assert!(result.is_ok(), "Glob pattern should work: {:?}", result);

    // Verify both .conf files were loaded
    assert_eq!(parser.config().rule_engine, RuleEngineStatus::On);
    assert_eq!(parser.config().web_app_id, "test");

    // Clean up
    fs::remove_dir_all(&temp_dir).unwrap();
}

/// Test Include directive with empty glob result (should not error)
#[test]
fn test_include_empty_glob() {
    let mut parser = Parser::new();

    // Non-matching glob should succeed (no files to load)
    let result = parser.from_file("/tmp/coraza-nonexistent-*.conf");
    assert!(result.is_ok(), "Empty glob result should not error");
}

/// Test Include directive recursion protection
#[test]
fn test_include_recursion_protection() {
    // Create a file that includes itself
    let temp_dir = std::env::temp_dir().join("coraza-test-recursion");
    fs::create_dir_all(&temp_dir).unwrap();

    let file1 = temp_dir.join("recursive.conf");
    fs::write(&file1, format!("Include {}\n", file1.to_string_lossy())).unwrap();

    let mut parser = Parser::new();
    let result = parser.from_file(&file1);

    assert!(result.is_err(), "Self-referencing include should fail");
    assert!(
        result.unwrap_err().to_string().contains("recursion"),
        "Error should mention recursion"
    );

    // Clean up
    fs::remove_dir_all(&temp_dir).unwrap();
}

/// Test Include directive with nested includes
#[test]
fn test_nested_includes() {
    let temp_dir = std::env::temp_dir().join("coraza-test-nested");
    fs::create_dir_all(&temp_dir).unwrap();

    let child = temp_dir.join("child.conf");
    let parent = temp_dir.join("parent.conf");

    fs::write(&child, "SecWebAppId child\n").unwrap();
    fs::write(
        &parent,
        format!("Include {}\nSecRuleEngine On\n", child.to_string_lossy()),
    )
    .unwrap();

    let mut parser = Parser::new();
    let result = parser.from_file(&parent);
    assert!(result.is_ok(), "Nested includes should work: {:?}", result);

    // Verify both files were loaded
    assert_eq!(parser.config().web_app_id, "child");
    assert_eq!(parser.config().rule_engine, RuleEngineStatus::On);

    // Clean up
    fs::remove_dir_all(&temp_dir).unwrap();
}

/// Test Include directive with many nested includes (but under limit)
#[test]
fn test_include_deep_nesting() {
    let temp_dir = std::env::temp_dir().join("coraza-test-deep");
    fs::create_dir_all(&temp_dir).unwrap();

    // Create a chain of 10 includes (well under the 100 limit)
    let mut files = Vec::new();
    for i in 0..10 {
        let file = temp_dir.join(format!("level{}.conf", i));
        files.push(file.clone());

        if i < 9 {
            // Include next level
            let next = temp_dir.join(format!("level{}.conf", i + 1));
            fs::write(&file, format!("Include {}\n", next.to_string_lossy())).unwrap();
        } else {
            // Last file sets a directive
            fs::write(&file, "SecWebAppId deep\n").unwrap();
        }
    }

    let mut parser = Parser::new();
    let result = parser.from_file(&files[0]);
    assert!(result.is_ok(), "Deep nesting under limit should work");
    assert_eq!(parser.config().web_app_id, "deep");

    // Clean up
    fs::remove_dir_all(&temp_dir).unwrap();
}

/// Test Include directive exceeding recursion limit
#[test]
fn test_include_exceeds_recursion_limit() {
    let temp_dir = std::env::temp_dir().join("coraza-test-limit");
    fs::create_dir_all(&temp_dir).unwrap();

    let base = temp_dir.join("base.conf");
    let target = temp_dir.join("target.conf");

    // Create empty target file
    fs::write(&target, "SecWebAppId target\n").unwrap();

    // Create base file that includes target 101 times (exceeds MAX_INCLUDE_RECURSION = 100)
    let mut base_content = String::new();
    for _ in 0..101 {
        base_content.push_str(&format!("Include {}\n", target.to_string_lossy()));
    }
    fs::write(&base, base_content).unwrap();

    let mut parser = Parser::new();
    let result = parser.from_file(&base);

    assert!(result.is_err(), "Exceeding recursion limit should fail");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("cannot include more than") || err_msg.contains("100"),
        "Error should mention include limit, got: {}",
        err_msg
    );

    // Clean up
    fs::remove_dir_all(&temp_dir).unwrap();
}

/// Test configuration directives
#[test]
fn test_sec_rule_engine() {
    let mut parser = Parser::new();

    parser.from_string("SecRuleEngine On").unwrap();
    assert_eq!(parser.config().rule_engine, RuleEngineStatus::On);

    parser.from_string("SecRuleEngine Off").unwrap();
    assert_eq!(parser.config().rule_engine, RuleEngineStatus::Off);

    parser.from_string("SecRuleEngine DetectionOnly").unwrap();
    assert_eq!(parser.config().rule_engine, RuleEngineStatus::DetectionOnly);

    // Invalid value should error
    let result = parser.from_string("SecRuleEngine Maybe");
    assert!(result.is_err());
}

#[test]
fn test_sec_request_body_access() {
    let mut parser = Parser::new();

    parser.from_string("SecRequestBodyAccess On").unwrap();
    assert!(parser.config().request_body_access);

    parser.from_string("SecRequestBodyAccess Off").unwrap();
    assert!(!parser.config().request_body_access);

    // Invalid value should error
    let result = parser.from_string("SecRequestBodyAccess Maybe");
    assert!(result.is_err());
}

#[test]
fn test_sec_request_body_limit() {
    let mut parser = Parser::new();

    parser.from_string("SecRequestBodyLimit 1000000").unwrap();
    assert_eq!(parser.config().request_body_limit, 1000000);

    // Invalid value should error
    let result = parser.from_string("SecRequestBodyLimit abc");
    assert!(result.is_err());

    // Missing value should error
    let result = parser.from_string("SecRequestBodyLimit");
    assert!(result.is_err());
}

#[test]
fn test_sec_response_body_access() {
    let mut parser = Parser::new();

    parser.from_string("SecResponseBodyAccess On").unwrap();
    assert!(parser.config().response_body_access);

    parser.from_string("SecResponseBodyAccess Off").unwrap();
    assert!(!parser.config().response_body_access);
}

#[test]
fn test_sec_response_body_limit() {
    let mut parser = Parser::new();

    parser.from_string("SecResponseBodyLimit 524288").unwrap();
    assert_eq!(parser.config().response_body_limit, 524288);
}

#[test]
fn test_sec_request_body_limit_action() {
    let mut parser = Parser::new();

    parser
        .from_string("SecRequestBodyLimitAction Reject")
        .unwrap();
    assert_eq!(
        parser.config().request_body_limit_action,
        BodyLimitAction::Reject
    );

    parser
        .from_string("SecRequestBodyLimitAction ProcessPartial")
        .unwrap();
    assert_eq!(
        parser.config().request_body_limit_action,
        BodyLimitAction::ProcessPartial
    );

    // Invalid value should error
    let result = parser.from_string("SecRequestBodyLimitAction Allow");
    assert!(result.is_err());
}

#[test]
fn test_sec_response_body_limit_action() {
    let mut parser = Parser::new();

    parser
        .from_string("SecResponseBodyLimitAction Reject")
        .unwrap();
    assert_eq!(
        parser.config().response_body_limit_action,
        BodyLimitAction::Reject
    );

    parser
        .from_string("SecResponseBodyLimitAction ProcessPartial")
        .unwrap();
    assert_eq!(
        parser.config().response_body_limit_action,
        BodyLimitAction::ProcessPartial
    );
}

#[test]
fn test_sec_web_app_id() {
    let mut parser = Parser::new();

    parser.from_string("SecWebAppId myapp123").unwrap();
    assert_eq!(parser.config().web_app_id, "myapp123");

    // Missing value should error
    let result = parser.from_string("SecWebAppId");
    assert!(result.is_err());
}

#[test]
fn test_sec_server_signature() {
    let mut parser = Parser::new();

    parser
        .from_string(r#"SecServerSignature "Microsoft-IIS/6.0""#)
        .unwrap();
    assert_eq!(parser.config().server_signature, "Microsoft-IIS/6.0");
}

#[test]
fn test_sec_sensor_id() {
    let mut parser = Parser::new();

    parser.from_string("SecSensorId sensor01").unwrap();
    assert_eq!(parser.config().sensor_id, "sensor01");
}

#[test]
fn test_sec_arguments_limit() {
    let mut parser = Parser::new();

    parser.from_string("SecArgumentsLimit 500").unwrap();
    assert_eq!(parser.config().argument_limit, 500);

    // Invalid value should error
    let result = parser.from_string("SecArgumentsLimit 0");
    assert!(result.is_err(), "Zero arguments limit should fail");
}

#[test]
fn test_sec_request_body_in_memory_limit() {
    let mut parser = Parser::new();

    parser
        .from_string("SecRequestBodyInMemoryLimit 131072")
        .unwrap();
    assert_eq!(parser.config().request_body_in_memory_limit, 131072);
}

#[test]
fn test_sec_request_body_no_files_limit() {
    let mut parser = Parser::new();

    parser
        .from_string("SecRequestBodyNoFilesLimit 65536")
        .unwrap();
    assert_eq!(parser.config().request_body_no_files_limit, 65536);
}

#[test]
fn test_sec_upload_dir() {
    let mut parser = Parser::new();

    // Use /tmp which should exist on Unix systems
    #[cfg(unix)]
    {
        parser.from_string("SecUploadDir /tmp").unwrap();
        assert_eq!(parser.config().upload_dir, "/tmp");
    }

    // Non-existent directory should error
    let result = parser.from_string("SecUploadDir /tmp-nonexistent-coraza-test");
    assert!(result.is_err(), "Non-existent upload dir should fail");
}

#[test]
fn test_sec_upload_file_limit() {
    let mut parser = Parser::new();

    parser.from_string("SecUploadFileLimit 50").unwrap();
    assert_eq!(parser.config().upload_file_limit, 50);
}

#[test]
fn test_sec_upload_file_mode() {
    let mut parser = Parser::new();

    parser.from_string("SecUploadFileMode 0600").unwrap();
    assert_eq!(parser.config().upload_file_mode, 0o600);

    parser.from_string("SecUploadFileMode 0755").unwrap();
    assert_eq!(parser.config().upload_file_mode, 0o755);

    // Invalid octal should error
    let result = parser.from_string("SecUploadFileMode 0888");
    assert!(result.is_err(), "Invalid octal should fail");
}

#[test]
fn test_sec_upload_keep_files() {
    let mut parser = Parser::new();

    parser.from_string("SecUploadKeepFiles On").unwrap();
    assert!(parser.config().upload_keep_files);

    parser.from_string("SecUploadKeepFiles Off").unwrap();
    assert!(!parser.config().upload_keep_files);

    // Case-insensitive
    parser.from_string("SecUploadKeepFiles ON").unwrap();
    assert!(parser.config().upload_keep_files);
}

#[test]
fn test_sec_audit_engine() {
    let mut parser = Parser::new();

    parser.from_string("SecAuditEngine On").unwrap();
    assert_eq!(parser.config().audit_engine, AuditEngineStatus::On);

    parser.from_string("SecAuditEngine Off").unwrap();
    assert_eq!(parser.config().audit_engine, AuditEngineStatus::Off);

    parser.from_string("SecAuditEngine RelevantOnly").unwrap();
    assert_eq!(
        parser.config().audit_engine,
        AuditEngineStatus::RelevantOnly
    );

    // Invalid value should error
    let result = parser.from_string("SecAuditEngine Maybe");
    assert!(result.is_err());
}

#[test]
fn test_sec_audit_log() {
    let mut parser = Parser::new();

    parser
        .from_string("SecAuditLog /var/log/coraza/audit.log")
        .unwrap();
    assert_eq!(parser.config().audit_log, "/var/log/coraza/audit.log");
}

#[test]
fn test_sec_data_dir() {
    let mut parser = Parser::new();

    parser.from_string("SecDataDir /var/coraza/data").unwrap();
    assert_eq!(parser.config().data_dir, "/var/coraza/data");
}

#[test]
fn test_sec_collection_timeout() {
    let mut parser = Parser::new();

    parser.from_string("SecCollectionTimeout 7200").unwrap();
    assert_eq!(parser.config().collection_timeout, 7200);
}

#[test]
fn test_sec_debug_log_level() {
    let mut parser = Parser::new();

    parser.from_string("SecDebugLogLevel 3").unwrap();
    assert_eq!(parser.config().debug_log_level, 3);

    parser.from_string("SecDebugLogLevel 9").unwrap();
    assert_eq!(parser.config().debug_log_level, 9);

    // Out of range should error
    let result = parser.from_string("SecDebugLogLevel 10");
    assert!(result.is_err());
}

/// Test multiple directives in one string
#[test]
fn test_multiple_directives() {
    let mut parser = Parser::new();

    let input = r#"
# Configuration for WAF
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecWebAppId myapp

# Upload settings
SecUploadDir /tmp
SecUploadFileLimit 100
SecUploadKeepFiles Off
"#;

    let result = parser.from_string(input);
    assert!(
        result.is_ok(),
        "Multiple directives should parse: {:?}",
        result
    );

    assert_eq!(parser.config().rule_engine, RuleEngineStatus::On);
    assert!(parser.config().request_body_access);
    assert_eq!(parser.config().request_body_limit, 13107200);
    assert_eq!(parser.config().web_app_id, "myapp");
    assert_eq!(parser.config().upload_dir, "/tmp");
    assert_eq!(parser.config().upload_file_limit, 100);
    assert!(!parser.config().upload_keep_files);
}

/// Test empty input
#[test]
fn test_empty_input() {
    let mut parser = Parser::new();

    let result = parser.from_string("");
    assert!(result.is_ok(), "Empty string should parse");

    let result = parser.from_string("   \n\n  \n");
    assert!(result.is_ok(), "Whitespace-only string should parse");
}

/// Test comments only
#[test]
fn test_comments_only() {
    let mut parser = Parser::new();

    let input = r#"
# This is a comment
# Another comment
  # Indented comment
"#;

    let result = parser.from_string(input);
    assert!(result.is_ok(), "Comments-only input should parse");
}

/// Test directive with missing required argument
#[test]
fn test_missing_required_arguments() {
    let mut parser = Parser::new();

    // Each of these should error due to missing arguments
    let cases = vec![
        "SecRuleEngine",
        "SecWebAppId",
        "SecRequestBodyLimit",
        "SecServerSignature",
        "SecArgumentsLimit",
    ];

    for directive in cases {
        let result = parser.from_string(directive);
        assert!(
            result.is_err(),
            "{} should fail without argument",
            directive
        );
    }
}

/// Test boolean parsing is case-insensitive
#[test]
fn test_boolean_case_insensitive() {
    let mut parser = Parser::new();

    // Test various cases
    parser.from_string("SecRequestBodyAccess On").unwrap();
    assert!(parser.config().request_body_access);

    parser.from_string("SecRequestBodyAccess ON").unwrap();
    assert!(parser.config().request_body_access);

    parser.from_string("SecRequestBodyAccess on").unwrap();
    assert!(parser.config().request_body_access);

    parser.from_string("SecRequestBodyAccess oN").unwrap();
    assert!(parser.config().request_body_access);

    parser.from_string("SecRequestBodyAccess Off").unwrap();
    assert!(!parser.config().request_body_access);

    parser.from_string("SecRequestBodyAccess OFF").unwrap();
    assert!(!parser.config().request_body_access);

    parser.from_string("SecRequestBodyAccess off").unwrap();
    assert!(!parser.config().request_body_access);
}
