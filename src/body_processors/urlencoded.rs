// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! URL-encoded body processor (application/x-www-form-urlencoded).
//!
//! Parses bodies in the format `key1=value1&key2=value2` and populates
//! the ARGS_POST collection. This is the standard format for HTML form
//! submissions.

use super::{BodyProcessor, BodyProcessorError, BodyProcessorOptions};
use crate::transaction::Transaction;
use crate::transformations::url_decode;

/// URL-encoded body processor for form data
pub struct UrlencodedBodyProcessor;

impl BodyProcessor for UrlencodedBodyProcessor {
    fn process_request(
        &self,
        body: &[u8],
        tx: &mut Transaction,
        _options: &BodyProcessorOptions,
    ) -> Result<(), BodyProcessorError> {
        // Convert body to string
        let body_str = String::from_utf8_lossy(body).to_string();
        let body_len = body.len();

        for (key, value) in parse_query(&body_str) {
            tx.add_post_argument(&key, &value);
        }

        // Store REQUEST_BODY and REQUEST_BODY_LENGTH
        tx.request_body.set(body_str);
        tx.request_body_length.set(body_len.to_string());

        Ok(())
    }

    fn process_response(
        &self,
        _body: &[u8],
        _tx: &mut Transaction,
        _options: &BodyProcessorOptions,
    ) -> Result<(), BodyProcessorError> {
        // URL-encoded processor doesn't process response bodies
        Ok(())
    }
}

/// Decoded `key=value` pairs of an `application/x-www-form-urlencoded` string (a query
/// string or a form body), in order. Empty pairs are skipped; a key without `=` has an
/// empty value.
pub(crate) fn parse_query(query: &str) -> impl Iterator<Item = (String, String)> + '_ {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (url_decode(key).0, url_decode(value).0)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body_processors::BodyProcessorKind;
    #[test]
    fn test_urlencoded_basic() {
        let processor = UrlencodedBodyProcessor;
        let mut tx = Transaction::new("test-1");

        let body = b"a=1&b=2&c=3";
        processor
            .process_request(body, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        // Check ARGS_POST
        assert_eq!(tx.args_post().get("a"), vec!["1"]);
        assert_eq!(tx.args_post().get("b"), vec!["2"]);
        assert_eq!(tx.args_post().get("c"), vec!["3"]);

        // Check REQUEST_BODY
        assert_eq!(tx.request_body.get(), "a=1&b=2&c=3");
        assert_eq!(tx.request_body_length.get(), "11");
    }

    #[test]
    fn test_urlencoded_with_encoding() {
        let processor = UrlencodedBodyProcessor;
        let mut tx = Transaction::new("test-2");

        let body = b"username=admin&password=secret%20pass";
        processor
            .process_request(body, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        assert_eq!(tx.args_post().get("username"), vec!["admin"]);
        assert_eq!(tx.args_post().get("password"), vec!["secret pass"]);
    }

    #[test]
    fn test_urlencoded_plus_to_space() {
        let processor = UrlencodedBodyProcessor;
        let mut tx = Transaction::new("test-3");

        let body = b"text=hello+world";
        processor
            .process_request(body, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        assert_eq!(tx.args_post().get("text"), vec!["hello world"]);
    }

    #[test]
    fn test_urlencoded_duplicate_keys() {
        let processor = UrlencodedBodyProcessor;
        let mut tx = Transaction::new("test-4");

        let body = b"id=1&id=2&id=3";
        processor
            .process_request(body, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        let ids = tx.args_post().get("id");
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&"1".to_string()));
        assert!(ids.contains(&"2".to_string()));
        assert!(ids.contains(&"3".to_string()));
    }

    #[test]
    fn test_urlencoded_empty_value() {
        let processor = UrlencodedBodyProcessor;
        let mut tx = Transaction::new("test-5");

        let body = b"key1=&key2=value";
        processor
            .process_request(body, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        assert_eq!(tx.args_post().get("key1"), vec![""]);
        assert_eq!(tx.args_post().get("key2"), vec!["value"]);
    }

    #[test]
    fn test_urlencoded_no_value() {
        let processor = UrlencodedBodyProcessor;
        let mut tx = Transaction::new("test-6");

        let body = b"key1&key2=value";
        processor
            .process_request(body, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        // Key without = gets empty value
        assert_eq!(tx.args_post().get("key1"), vec![""]);
        assert_eq!(tx.args_post().get("key2"), vec!["value"]);
    }

    #[test]
    fn test_urlencoded_empty_body() {
        let processor = UrlencodedBodyProcessor;
        let mut tx = Transaction::new("test-7");

        let body = b"";
        processor
            .process_request(body, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        // Empty body should result in no ARGS_POST entries
        assert!(tx.args_post().find_all().is_empty());
        assert_eq!(tx.request_body.get(), "");
        assert_eq!(tx.request_body_length.get(), "0");
    }

    #[test]
    fn test_urlencoded_from_registry() {
        let processor = BodyProcessorKind::UrlEncoded;
        let mut tx = Transaction::new("test-8");

        let body = b"test=value";
        processor
            .process_request(body, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        assert_eq!(tx.args_post().get("test"), vec!["value"]);
    }

    #[test]
    fn test_urlencoded_populates_args() {
        let processor = UrlencodedBodyProcessor;
        let mut tx = Transaction::new("test-9");

        let body = b"username=admin&password=secret";
        processor
            .process_request(body, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        // Should also populate ARGS collection (not just ARGS_POST)
        assert_eq!(tx.args().get("username"), vec!["admin"]);
        assert_eq!(tx.args().get("password"), vec!["secret"]);
    }

    #[test]
    fn test_parse_query() {
        let result: Vec<_> = parse_query("a=1&&b=2&c&a=3").collect();
        let pair = |k: &str, v: &str| (k.to_string(), v.to_string());
        assert_eq!(
            result,
            vec![
                pair("a", "1"),
                pair("b", "2"),
                pair("c", ""),
                pair("a", "3")
            ]
        );
    }

    #[test]
    fn test_parse_query_with_encoding() {
        let result: Vec<_> = parse_query("name=John+Doe&city=New%20York&e=%C3%A9").collect();
        let pair = |k: &str, v: &str| (k.to_string(), v.to_string());
        assert_eq!(
            result,
            vec![
                pair("name", "John Doe"),
                pair("city", "New York"),
                pair("e", "é")
            ]
        );
    }
}
