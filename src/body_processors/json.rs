// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! JSON body processor (application/json).
//!
//! Parses JSON bodies and flattens them into dot-notation keys in ARGS_POST.
//! For example: `{"user": {"name": "admin"}}` becomes `json.user.name` = "admin"

use super::{BodyProcessor, BodyProcessorError, BodyProcessorOptions};
use crate::collection::MapCollection;
use crate::transaction::Transaction;
use serde_json::Value;
use std::collections::HashMap;

/// JSON body processor
pub struct JsonBodyProcessor;

impl BodyProcessor for JsonBodyProcessor {
    fn process_request(
        &self,
        body: &[u8],
        tx: &mut Transaction,
        _options: &BodyProcessorOptions,
    ) -> Result<(), BodyProcessorError> {
        // Convert body to string
        let body_str = String::from_utf8_lossy(body).to_string();
        let body_len = body.len();

        // Parse JSON
        let json_value: Value = serde_json::from_str(&body_str)
            .map_err(|e| BodyProcessorError::Malformed("json".to_string(), e.to_string()))?;

        // Flatten JSON into dot-notation map
        let flattened = flatten_json(&json_value);

        // Populate ARGS_POST with flattened values
        let args_post = tx.args_post_mut();
        for (key, value) in &flattened {
            args_post.set_index(key, 0, value);
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
        // JSON processor doesn't process response bodies in this implementation
        Ok(())
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

/// Factory function for creating JSON body processors
pub fn create_json() -> Box<dyn BodyProcessor> {
    Box::new(JsonBodyProcessor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body_processors::get_body_processor;
    use crate::collection::{Keyed, SingleCollection};

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
        let processor = JsonBodyProcessor;
        let mut tx = Transaction::new("test-1");

        let body = br#"{"username": "admin", "password": "secret"}"#;
        processor
            .process_request(body, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        // Check ARGS_POST populated
        assert_eq!(tx.args_post().get("json.username"), vec!["admin"]);
        assert_eq!(tx.args_post().get("json.password"), vec!["secret"]);

        // Check REQUEST_BODY stored
        assert_eq!(
            tx.request_body.get(),
            r#"{"username": "admin", "password": "secret"}"#
        );
        assert_eq!(tx.request_body_length.get(), "43");
    }

    #[test]
    fn test_json_processor_invalid_json() {
        let processor = JsonBodyProcessor;
        let mut tx = Transaction::new("test-2");

        let body = b"{invalid json";
        let result = processor.process_request(body, &mut tx, &BodyProcessorOptions::default());

        // Should fail with malformed error
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("malformed"));
        }
    }

    #[test]
    fn test_json_from_registry() {
        let processor = get_body_processor("json").unwrap();
        let mut tx = Transaction::new("test-3");

        let body = br#"{"test": "value"}"#;
        processor
            .process_request(body, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        assert_eq!(tx.args_post().get("json.test"), vec!["value"]);
    }

    #[test]
    fn test_json_nested_arrays() {
        let processor = JsonBodyProcessor;
        let mut tx = Transaction::new("test-4");

        let body = br#"{"items": [{"id": 1}, {"id": 2}]}"#;
        processor
            .process_request(body, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        assert_eq!(tx.args_post().get("json.items"), vec!["2"]); // array length
        assert_eq!(tx.args_post().get("json.items.0.id"), vec!["1"]);
        assert_eq!(tx.args_post().get("json.items.1.id"), vec!["2"]);
    }

    #[test]
    fn test_json_empty_body() {
        let processor = JsonBodyProcessor;
        let mut tx = Transaction::new("test-5");

        let body = b"{}";
        processor
            .process_request(body, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        // Empty object - no ARGS_POST entries (but REQUEST_BODY is set)
        // Note: We can't check if collection is empty easily, but we can check specific keys don't exist
        assert!(tx.args_post().get("json").is_empty());
        assert_eq!(tx.request_body.get(), "{}");
    }
}
