// SPDX-License-Identifier: Apache-2.0

//! Uploads without `SecUploadDir`, in a test binary of their own: the test sets `TMPDIR`,
//! which no other test may read meanwhile.

use coraza::RuleVariable;
use coraza::seclang::Parser;

#[cfg(unix)]
#[test]
fn uploads_without_an_upload_dir_go_to_the_system_temp_dir() {
    // As in Go Coraza, whose os.CreateTemp("", ...) reads TMPDIR
    let tmp = tempfile::tempdir().unwrap();
    // SAFETY: this binary's only test, so no other thread reads the environment
    unsafe { std::env::set_var("TMPDIR", tmp.path()) };

    let mut parser = Parser::new();
    parser
        .from_string(
            r#"
            SecRequestBodyAccess On
            SecRule FILES_TMPNAMES "@rx ." "id:1,phase:2,pass,nolog,setvar:tx.stored=%{MATCHED_VAR}"
            "#,
        )
        .unwrap();
    let waf = parser.into_waf().unwrap();
    let body = "--b\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"a.txt\"\r\n\r\nhello\r\n--b--\r\n";
    let mut tx = waf.new_transaction();
    tx.add_request_header("Content-Type", "multipart/form-data; boundary=b");
    tx.process_request_headers();
    tx.process_request_body(body.as_bytes());

    let stored = tx
        .get_variable(RuleVariable::TX, Some("stored"))
        .expect("the upload is stored");
    assert_eq!(std::path::Path::new(&stored).parent(), Some(tmp.path()));
}
