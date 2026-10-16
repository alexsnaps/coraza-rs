// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! JSON body processor (application/json).
//!
//! Parses JSON bodies and flattens them into dot-notation keys in ARGS_POST.
//! For example: `{"user": {"name": "admin"}}` becomes `json.user.name` = "admin"

use super::BodyProcessorError;
use crate::transaction::Transaction;
use serde_json::Value;
use std::collections::HashMap;

/// Parses a JSON request body into ARGS_POST (and ARGS), flattened, nesting at most
/// `SecRequestBodyJsonDepthLimit` deep.
///
/// # Errors
///
/// If the body isn't JSON, or nests deeper.
pub(super) fn process_request(body: &[u8], tx: &mut Transaction) -> Result<(), BodyProcessorError> {
    let depth_limit = tx.config().request_body_json_depth_limit;
    for (key, value) in &flattened(body, depth_limit)? {
        tx.add_post_argument(key, value);
    }
    Ok(())
}

/// Parses a JSON response body into RESPONSE_ARGS, flattened, nesting at most
/// `SecResponseBodyJsonDepthLimit` deep.
///
/// # Errors
///
/// If the body isn't JSON, or nests deeper.
pub(super) fn process_response(
    body: &[u8],
    tx: &mut Transaction,
) -> Result<(), BodyProcessorError> {
    let depth_limit = tx.config().response_body_json_depth_limit;
    for (key, value) in &flattened(body, depth_limit)? {
        tx.add_response_argument(key, value);
    }
    Ok(())
}

/// A JSON body nesting at most `depth_limit` deep, flattened as [`flatten_json`] does.
fn flattened(
    body: &[u8],
    depth_limit: usize,
) -> Result<HashMap<String, String>, BodyProcessorError> {
    let json_value = parse_json(&String::from_utf8_lossy(body), depth_limit)?;
    Ok(flatten_json(&json_value))
}

/// Parses a JSON body whose objects and arrays nest at most `depth_limit` deep.
///
/// serde_json itself rejects nesting deeper than 128, whatever the limit.
fn parse_json(body: &str, depth_limit: usize) -> Result<Value, BodyProcessorError> {
    let malformed = |message: String| BodyProcessorError::Malformed("json".to_string(), message);
    let value: Value = serde_json::from_str(body).map_err(|e| malformed(e.to_string()))?;
    if depth(&value) > depth_limit {
        return Err(malformed(format!(
            "nesting deeper than the limit of {}",
            depth_limit
        )));
    }
    Ok(value)
}

/// How deep objects and arrays nest in `value`: 0 for a scalar, 1 for `{"a": 1}`.
fn depth(value: &Value) -> usize {
    let deepest = |children: &mut dyn Iterator<Item = &Value>| children.map(depth).max();
    match value {
        Value::Object(map) => 1 + deepest(&mut map.values()).unwrap_or(0),
        Value::Array(items) => 1 + deepest(&mut items.iter()).unwrap_or(0),
        _ => 0,
    }
}

/// Flatten JSON into dot-notation map
///
/// Converts JSON structures into a flat map with dot-separated keys:
/// - Objects: `{"a": 1}` → `json.a` = "1"
/// - Arrays: `{"c": [1,2,3]}` → `json.c` = "3" (length), `json.c.0` = "1", etc.
/// - Nested: `{"d": {"a": {"b": 1}}}` → `json.d.a.b` = "1"
///
/// # Arguments
///
/// * `value` - The parsed JSON value to flatten
///
/// # Returns
///
/// A HashMap with dot-notation keys and string values
fn flatten_json(value: &Value) -> HashMap<String, String> {
    let mut result = HashMap::new();
    let mut key_buffer = Vec::from(b"json".as_slice());
    flatten_value(value, &mut key_buffer, &mut result);
    result
}

/// Recursively flatten a JSON value
///
/// # Arguments
///
/// * `value` - Current JSON value to process
/// * `key_buffer` - Buffer building the current key path (avoids string concatenation)
/// * `result` - Map to store flattened key-value pairs
fn flatten_value(value: &Value, key_buffer: &mut Vec<u8>, result: &mut HashMap<String, String>) {
    match value {
        Value::Object(map) => {
            // Process each key-value pair in the object
            for (k, v) in map {
                let prev_len = key_buffer.len();
                key_buffer.push(b'.');
                key_buffer.extend_from_slice(k.as_bytes());

                flatten_value(v, key_buffer, result);

                // Restore buffer to previous state
                key_buffer.truncate(prev_len);
            }
        }
        Value::Array(arr) => {
            // Store array length at the current key
            let array_len = arr.len();
            if array_len > 0 {
                let key = String::from_utf8_lossy(key_buffer).to_string();
                result.insert(key, array_len.to_string());

                // Process each array element
                for (index, item) in arr.iter().enumerate() {
                    let prev_len = key_buffer.len();
                    key_buffer.push(b'.');
                    // Append index as bytes
                    key_buffer.extend_from_slice(index.to_string().as_bytes());

                    flatten_value(item, key_buffer, result);

                    // Restore buffer
                    key_buffer.truncate(prev_len);
                }
            }
        }
        Value::String(s) => {
            let key = String::from_utf8_lossy(key_buffer).to_string();
            result.insert(key, s.clone());
        }
        Value::Number(n) => {
            let key = String::from_utf8_lossy(key_buffer).to_string();
            result.insert(key, n.to_string());
        }
        Value::Bool(b) => {
            let key = String::from_utf8_lossy(key_buffer).to_string();
            result.insert(key, b.to_string());
        }
        Value::Null => {
            let key = String::from_utf8_lossy(key_buffer).to_string();
            result.insert(key, String::new());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        BodyProcessorKind, inspect_request, inspect_response, request_error, response_error,
    };
    use super::*;
    use crate::RuleVariable;

    /// A transaction whose JSON request body the JSON processor inspected.
    fn inspect_json(body: &[u8]) -> Transaction {
        inspect_request(BodyProcessorKind::Json, "application/json", body)
    }

    #[test]
    fn test_json_map() {
        let json = r#"
{
  "a": 1,
  "b": 2,
  "c": [
    1,
    2,
    3
  ],
  "d": {
    "a": {
      "b": 1
    }
  },
  "e": [
      {"a": 1}
  ],
  "f": [
      [
          [
              {"z": "abc"}
          ]
      ]
  ]
}
        "#;

        let flattened = flatten_json(&serde_json::from_str(json).unwrap());

        assert_eq!(flattened.get("json.a"), Some(&"1".to_string()));
        assert_eq!(flattened.get("json.b"), Some(&"2".to_string()));
        assert_eq!(flattened.get("json.c"), Some(&"3".to_string())); // array length
        assert_eq!(flattened.get("json.c.0"), Some(&"1".to_string()));
        assert_eq!(flattened.get("json.c.1"), Some(&"2".to_string()));
        assert_eq!(flattened.get("json.c.2"), Some(&"3".to_string()));
        assert_eq!(flattened.get("json.d.a.b"), Some(&"1".to_string()));
        assert_eq!(flattened.get("json.e"), Some(&"1".to_string())); // array length
        assert_eq!(flattened.get("json.e.0.a"), Some(&"1".to_string()));
        assert_eq!(flattened.get("json.f"), Some(&"1".to_string())); // array length
        assert_eq!(flattened.get("json.f.0"), Some(&"1".to_string()));
        assert_eq!(flattened.get("json.f.0.0"), Some(&"1".to_string()));
        assert_eq!(flattened.get("json.f.0.0.0.z"), Some(&"abc".to_string()));
    }

    #[test]
    fn test_json_array() {
        let json = r#"
[
    [
        [
            {
                "q": 1
            }
        ]
    ],
    {
        "a": 1,
        "b": 2,
        "c": [
            1,
            2,
            3
        ],
        "d": {
            "a": {
                "b": 1
            }
        },
        "e": [
            {
                "a": 1
            }
        ],
        "f": [
            [
                [
                    {
                        "z": "abc"
                    }
                ]
            ]
        ]
    }
]
        "#;

        let flattened = flatten_json(&serde_json::from_str(json).unwrap());

        assert_eq!(flattened.get("json"), Some(&"2".to_string())); // root array length
        assert_eq!(flattened.get("json.0"), Some(&"1".to_string()));
        assert_eq!(flattened.get("json.0.0"), Some(&"1".to_string()));
        assert_eq!(flattened.get("json.0.0.0.q"), Some(&"1".to_string()));
        assert_eq!(flattened.get("json.1.a"), Some(&"1".to_string()));
        assert_eq!(flattened.get("json.1.b"), Some(&"2".to_string()));
        assert_eq!(flattened.get("json.1.c"), Some(&"3".to_string()));
        assert_eq!(flattened.get("json.1.c.0"), Some(&"1".to_string()));
        assert_eq!(flattened.get("json.1.c.1"), Some(&"2".to_string()));
        assert_eq!(flattened.get("json.1.c.2"), Some(&"3".to_string()));
        assert_eq!(flattened.get("json.1.d.a.b"), Some(&"1".to_string()));
        assert_eq!(flattened.get("json.1.e"), Some(&"1".to_string()));
        assert_eq!(flattened.get("json.1.e.0.a"), Some(&"1".to_string()));
        assert_eq!(flattened.get("json.1.f"), Some(&"1".to_string()));
        assert_eq!(flattened.get("json.1.f.0"), Some(&"1".to_string()));
        assert_eq!(flattened.get("json.1.f.0.0"), Some(&"1".to_string()));
        assert_eq!(flattened.get("json.1.f.0.0.0.z"), Some(&"abc".to_string()));
    }

    #[test]
    fn test_json_empty_object() {
        let json = "{}";
        let flattened = flatten_json(&serde_json::from_str(json).unwrap());
        assert!(flattened.is_empty());
    }

    #[test]
    fn test_json_null_and_boolean_values() {
        let json = r#"{"null": null, "true": true, "false": false}"#;
        let flattened = flatten_json(&serde_json::from_str(json).unwrap());

        assert_eq!(flattened.get("json.null"), Some(&"".to_string()));
        assert_eq!(flattened.get("json.true"), Some(&"true".to_string()));
        assert_eq!(flattened.get("json.false"), Some(&"false".to_string()));
    }

    #[test]
    fn test_json_nested_empty() {
        // Empty objects/arrays don't produce entries
        let json = r#"{"a": {}, "b": []}"#;
        let flattened = flatten_json(&serde_json::from_str(json).unwrap());

        // Should have no entries (empty object/array produce nothing)
        assert!(flattened.is_empty());
    }

    #[test]
    fn test_json_processor_basic() {
        let body = br#"{"username": "admin", "password": "secret"}"#;
        let tx = inspect_json(body);

        // Check ARGS_POST populated
        assert_eq!(
            tx.variable_map(RuleVariable::ArgsPost).get("json.username"),
            vec!["admin"]
        );
        assert_eq!(
            tx.variable_map(RuleVariable::ArgsPost).get("json.password"),
            vec!["secret"]
        );

        // As in Go Coraza and ModSecurity, only URLENCODED and RAW set REQUEST_BODY
        assert_eq!(tx.request_body.get(), "");
        assert_eq!(tx.request_body_length.get(), "0");
    }

    #[test]
    fn test_json_processor_invalid_json() {
        let tx = inspect_json(b"{invalid json");

        // Should fail with malformed error
        let error = request_error(&tx).expect("an invalid body fails");
        assert!(error.contains("malformed"), "{error}");
    }

    #[test]
    fn test_json_nested_arrays() {
        let body = br#"{"items": [{"id": 1}, {"id": 2}]}"#;
        let tx = inspect_json(body);

        assert_eq!(
            tx.variable_map(RuleVariable::ArgsPost).get("json.items"),
            vec!["2"]
        ); // array length
        assert_eq!(
            tx.variable_map(RuleVariable::ArgsPost)
                .get("json.items.0.id"),
            vec!["1"]
        );
        assert_eq!(
            tx.variable_map(RuleVariable::ArgsPost)
                .get("json.items.1.id"),
            vec!["2"]
        );
    }

    #[test]
    fn test_json_empty_body() {
        let body = b"{}";
        let tx = inspect_json(body);

        // Empty object - no ARGS_POST entries
        // Note: We can't check if collection is empty easily, but we can check specific keys don't exist
        assert!(
            tx.variable_map(RuleVariable::ArgsPost)
                .get("json")
                .is_empty()
        );
    }

    #[test]
    fn test_json_response_processing() {
        let body = br#"{"status":"success","data":{"id":123,"name":"admin"}}"#;
        let tx = inspect_response(BodyProcessorKind::Json, body);

        // Check RESPONSE_ARGS populated
        assert_eq!(
            tx.variable_map(RuleVariable::ResponseArgs)
                .get("json.status"),
            vec!["success"]
        );
        assert_eq!(
            tx.variable_map(RuleVariable::ResponseArgs)
                .get("json.data.id"),
            vec!["123"]
        );
        assert_eq!(
            tx.variable_map(RuleVariable::ResponseArgs)
                .get("json.data.name"),
            vec!["admin"]
        );
    }

    #[test]
    fn test_json_response_array() {
        let body = br#"{"items":[{"id":1},{"id":2}]}"#;
        let tx = inspect_response(BodyProcessorKind::Json, body);

        // Check RESPONSE_ARGS populated
        assert_eq!(
            tx.variable_map(RuleVariable::ResponseArgs)
                .get("json.items"),
            vec!["2"]
        ); // array length
        assert_eq!(
            tx.variable_map(RuleVariable::ResponseArgs)
                .get("json.items.0.id"),
            vec!["1"]
        );
        assert_eq!(
            tx.variable_map(RuleVariable::ResponseArgs)
                .get("json.items.1.id"),
            vec!["2"]
        );
    }

    #[test]
    fn test_json_response_invalid() {
        let tx = inspect_response(BodyProcessorKind::Json, b"{invalid json}");

        // Should fail with malformed error
        let error = response_error(&tx).expect("an invalid body fails");
        assert!(error.contains("malformed"), "{error}");
    }
}
