// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! RAW body processor (pass-through, no parsing).
//!
//! The RAW processor simply stores the entire body as-is in REQUEST_BODY
//! and sets REQUEST_BODY_LENGTH. It doesn't perform any parsing or
//! variable extraction.

use super::{BodyProcessor, BodyProcessorError, BodyProcessorOptions};
use crate::transaction::Transaction;

/// RAW body processor that stores body without parsing
pub struct RawBodyProcessor;

impl BodyProcessor for RawBodyProcessor {
    fn process_request(
        &self,
        body: &[u8],
        tx: &mut Transaction,
        _options: &BodyProcessorOptions,
    ) -> Result<(), BodyProcessorError> {
        // Convert body to string (UTF-8)
        let body_str = String::from_utf8_lossy(body).to_string();
        let body_len = body.len();

        // Set REQUEST_BODY
        tx.request_body.set(body_str);

        // Set REQUEST_BODY_LENGTH
        tx.request_body_length.set(body_len.to_string());

        Ok(())
    }

    fn process_response(
        &self,
        _body: &[u8],
        _tx: &mut Transaction,
        _options: &BodyProcessorOptions,
    ) -> Result<(), BodyProcessorError> {
        // RAW processor doesn't process response bodies
        Ok(())
    }
}

/// Factory function for creating RAW body processors
pub fn create_raw() -> Box<dyn BodyProcessor> {
    Box::new(RawBodyProcessor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body_processors::get_body_processor;
    use crate::collection::SingleCollection;

    #[test]
    fn test_raw_processor_basic() {
        let processor = RawBodyProcessor;
        let mut tx = Transaction::new("test-1");

        let body = b"this is a body\nwithout &any=meaning";
        processor
            .process_request(body, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        assert_eq!(
            tx.request_body.get(),
            "this is a body\nwithout &any=meaning"
        );
        assert_eq!(tx.request_body_length.get(), "35");
    }

    #[test]
    fn test_raw_processor_empty_body() {
        let processor = RawBodyProcessor;
        let mut tx = Transaction::new("test");

        let body = b"";
        processor
            .process_request(body, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        assert_eq!(tx.request_body.get(), "");
        assert_eq!(tx.request_body_length.get(), "0");
    }

    #[test]
    fn test_raw_processor_binary_data() {
        let processor = RawBodyProcessor;
        let mut tx = Transaction::new("test");

        let body = b"\x00\x01\x02\xFF";
        processor
            .process_request(body, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        // Binary data gets converted with replacement characters
        assert_eq!(tx.request_body_length.get(), "4");
    }

    #[test]
    fn test_raw_processor_from_registry() {
        let processor = get_body_processor("raw").unwrap();
        let mut tx = Transaction::new("test");

        let body = b"test body";
        processor
            .process_request(body, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        assert_eq!(tx.request_body.get(), "test body");
        assert_eq!(tx.request_body_length.get(), "9");
    }

    #[test]
    fn test_raw_processor_response_is_noop() {
        let processor = RawBodyProcessor;
        let mut tx = Transaction::new("test");

        let body = b"response body";
        let result = processor.process_response(body, &mut tx, &BodyProcessorOptions::default());

        assert!(result.is_ok());
        // Response processing is a no-op for RAW processor
    }
}
