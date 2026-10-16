// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! RAW body processor (pass-through, no parsing).
//!
//! The RAW processor simply stores the entire body as-is in REQUEST_BODY
//! and sets REQUEST_BODY_LENGTH. It doesn't perform any parsing or
//! variable extraction.

use crate::transaction::Transaction;

/// Stores a request body in REQUEST_BODY (as text) and its length in REQUEST_BODY_LENGTH.
pub(super) fn process_request(body: &[u8], tx: &mut Transaction) {
    tx.request_body.set(String::from_utf8_lossy(body));
    tx.request_body_length.set(body.len().to_string());
}

#[cfg(test)]
mod tests {
    use super::super::{BodyProcessorKind, inspect_request, inspect_response, response_error};
    use crate::RuleVariable;

    #[test]
    fn test_raw_processor_basic() {
        let body = b"this is a body\nwithout &any=meaning";
        let tx = inspect_request(BodyProcessorKind::Raw, "text/plain", body);

        assert_eq!(
            tx.request_body.get(),
            "this is a body\nwithout &any=meaning"
        );
        assert_eq!(tx.request_body_length.get(), "35");
    }

    #[test]
    fn test_raw_processor_empty_body() {
        // As in Go Coraza, an empty body reaches no processor
        let tx = inspect_request(BodyProcessorKind::Raw, "text/plain", b"");

        assert_eq!(tx.request_body.get(), "");
        assert_eq!(tx.request_body_length.get(), "0");
    }

    #[test]
    fn test_raw_processor_binary_data() {
        let tx = inspect_request(BodyProcessorKind::Raw, "text/plain", b"\x00\x01\x02\xFF");

        // Binary data gets converted with replacement characters
        assert_eq!(tx.request_body_length.get(), "4");
    }

    #[test]
    fn test_raw_processor_response_is_noop() {
        let tx = inspect_response(BodyProcessorKind::Raw, b"response body");

        // RAW parses no response body, and, being named, keeps it from RESPONSE_BODY
        assert_eq!(response_error(&tx), None);
        let response_body = tx.get_variable(RuleVariable::ResponseBody, None);
        assert_eq!(response_body.as_deref(), Some(""));
    }
}
