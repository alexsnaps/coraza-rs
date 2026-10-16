// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! URL-encoded body processor (application/x-www-form-urlencoded).
//!
//! Parses bodies in the format `key1=value1&key2=value2` and populates
//! the ARGS_POST collection. This is the standard format for HTML form
//! submissions.

use crate::transaction::Transaction;
use crate::transformations::{text_from_bytes, text_of, url_decode};

/// Parses a request body's arguments into ARGS_POST (and ARGS), and stores it in
/// REQUEST_BODY (as text) and its length in REQUEST_BODY_LENGTH.
pub(super) fn process_request(body: &[u8], tx: &mut Transaction) {
    // As in Go Coraza, argument values keep the body's bytes
    for (key, value) in parse_query(body) {
        tx.add_post_argument(&key, &value);
    }

    tx.request_body.set(text_of(body));
    tx.request_body_length.set(body.len().to_string());
}

/// Decoded `key=value` pairs of an `application/x-www-form-urlencoded` string (a query
/// string or a form body), in order: keys as text, values as bytes. Empty pairs are
/// skipped; a key without `=` has an empty value.
pub(crate) fn parse_query(query: &[u8]) -> impl Iterator<Item = (String, Vec<u8>)> + '_ {
    query
        .split(|&byte| byte == b'&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = match pair.iter().position(|&byte| byte == b'=') {
                Some(equals) => (&pair[..equals], &pair[equals + 1..]),
                None => (pair, &b""[..]),
            };
            let key = text_from_bytes(url_decode(key).0);
            // As in Go Coraza, a value keeps the bytes it decodes to, UTF-8 or not
            let value = url_decode(value).0;
            (key, value)
        })
}

#[cfg(test)]
mod tests {
    use super::super::{BodyProcessorKind, inspect_request};
    use super::*;
    use crate::RuleVariable;

    const FORM: &str = "application/x-www-form-urlencoded";

    #[test]
    fn test_urlencoded_basic() {
        let body = b"a=1&b=2&c=3";
        let tx = inspect_request(BodyProcessorKind::UrlEncoded, FORM, body);

        // Check ARGS_POST
        assert_eq!(tx.variable_map(RuleVariable::ArgsPost).get("a"), vec!["1"]);
        assert_eq!(tx.variable_map(RuleVariable::ArgsPost).get("b"), vec!["2"]);
        assert_eq!(tx.variable_map(RuleVariable::ArgsPost).get("c"), vec!["3"]);

        // Check REQUEST_BODY
        assert_eq!(tx.request_body.get(), "a=1&b=2&c=3");
        assert_eq!(tx.request_body_length.get(), "11");
    }

    #[test]
    fn test_urlencoded_with_encoding() {
        let body = b"username=admin&password=secret%20pass";
        let tx = inspect_request(BodyProcessorKind::UrlEncoded, FORM, body);

        assert_eq!(
            tx.variable_map(RuleVariable::ArgsPost).get("username"),
            vec!["admin"]
        );
        assert_eq!(
            tx.variable_map(RuleVariable::ArgsPost).get("password"),
            vec!["secret pass"]
        );
    }

    #[test]
    fn test_urlencoded_plus_to_space() {
        let body = b"text=hello+world";
        let tx = inspect_request(BodyProcessorKind::UrlEncoded, FORM, body);

        assert_eq!(
            tx.variable_map(RuleVariable::ArgsPost).get("text"),
            vec!["hello world"]
        );
    }

    #[test]
    fn test_urlencoded_duplicate_keys() {
        let body = b"id=1&id=2&id=3";
        let tx = inspect_request(BodyProcessorKind::UrlEncoded, FORM, body);

        let ids = tx.variable_map(RuleVariable::ArgsPost).get("id");
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&"1".to_string()));
        assert!(ids.contains(&"2".to_string()));
        assert!(ids.contains(&"3".to_string()));
    }

    #[test]
    fn test_urlencoded_empty_value() {
        let body = b"key1=&key2=value";
        let tx = inspect_request(BodyProcessorKind::UrlEncoded, FORM, body);

        assert_eq!(
            tx.variable_map(RuleVariable::ArgsPost).get("key1"),
            vec![""]
        );
        assert_eq!(
            tx.variable_map(RuleVariable::ArgsPost).get("key2"),
            vec!["value"]
        );
    }

    #[test]
    fn test_urlencoded_no_value() {
        let body = b"key1&key2=value";
        let tx = inspect_request(BodyProcessorKind::UrlEncoded, FORM, body);

        // Key without = gets empty value
        assert_eq!(
            tx.variable_map(RuleVariable::ArgsPost).get("key1"),
            vec![""]
        );
        assert_eq!(
            tx.variable_map(RuleVariable::ArgsPost).get("key2"),
            vec!["value"]
        );
    }

    #[test]
    fn test_urlencoded_empty_body() {
        let body = b"";
        let tx = inspect_request(BodyProcessorKind::UrlEncoded, FORM, body);

        // As in Go Coraza, an empty body reaches no processor
        assert!(tx.variable_map(RuleVariable::ArgsPost).is_empty());
        assert_eq!(tx.request_body.get(), "");
        assert_eq!(tx.request_body_length.get(), "0");
    }

    #[test]
    fn test_urlencoded_populates_args() {
        let body = b"username=admin&password=secret";
        let tx = inspect_request(BodyProcessorKind::UrlEncoded, FORM, body);

        // Should also populate ARGS collection (not just ARGS_POST)
        assert_eq!(
            tx.variable_map(RuleVariable::Args).get("username"),
            vec!["admin"]
        );
        assert_eq!(
            tx.variable_map(RuleVariable::Args).get("password"),
            vec!["secret"]
        );
    }

    #[test]
    fn test_parse_query() {
        let result: Vec<_> = parse_query(b"a=1&&b=2&c&a=3").collect();
        let pair = |k: &str, v: &str| (k.to_string(), v.as_bytes().to_vec());
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
        let result: Vec<_> = parse_query(b"name=John+Doe&city=New%20York&e=%C3%A9").collect();
        let pair = |k: &str, v: &str| (k.to_string(), v.as_bytes().to_vec());
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
