// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Transformation pipeline for rule evaluation.
//!
//! This module implements transformation chains that apply multiple transformations
//! sequentially to input values before operator matching. Transformations can be
//! chained together (e.g., `t:lowercase,urlDecode`) and are applied in order.
//!
//! Values pass from one transformation to the next as bytes, so that one can produce
//! bytes that aren't UTF-8 (`t:sha1`, `t:urlDecode` of `%ff`) for the next
//! (`t:hexEncode`). The result becomes text for the operator: each invalid sequence
//! is then replaced by U+FFFD.
//!
//! # Modes
//!
//! - **Simple Mode**: Apply transformations in sequence, returning the final value
//! - **Multi-Match Mode**: Collect all intermediate transformed values for matching
//!
//! # Examples
//!
//! ```
//! use coraza::rules::TransformationChain;
//! use coraza::transformations::{lowercase, url_decode};
//!
//! let mut chain = TransformationChain::new();
//! chain.add("lowercase", lowercase);
//! chain.add("urlDecode", url_decode);
//!
//! let (result, errors) = chain.apply(b"HELLO%20WORLD");
//! assert_eq!(result, b"hello world");
//! ```

use crate::transformations::{Transformation, TransformationError, text_from_bytes};

/// A transformation in the chain with its name for identification.
#[derive(Debug, Clone)]
struct NamedTransformation {
    name: String,
    function: Transformation,
}

/// A chain of transformations to apply sequentially.
///
/// Transformations are applied in the order they were added. The output of one
/// transformation becomes the input to the next. Errors are collected but don't
/// stop the chain from executing.
///
/// # Examples
///
/// ```
/// use coraza::rules::TransformationChain;
/// use coraza::transformations::lowercase;
///
/// let mut chain = TransformationChain::new();
/// chain.add("lowercase", lowercase);
///
/// let (result, errors) = chain.apply(b"HELLO");
/// assert_eq!(result, b"hello");
/// assert!(errors.is_empty());
/// ```
#[derive(Debug, Clone)]
pub struct TransformationChain {
    transformations: Vec<NamedTransformation>,
}

impl TransformationChain {
    /// Create a new empty transformation chain.
    pub fn new() -> Self {
        Self {
            transformations: Vec::new(),
        }
    }

    /// Add a transformation to the chain.
    ///
    /// Transformations are applied in the order they are added.
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the transformation (for logging/debugging)
    /// * `function` - The transformation function to apply
    ///
    /// # Returns
    ///
    /// Result indicating success or error if name is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::rules::TransformationChain;
    /// use coraza::transformations::{lowercase, url_decode};
    ///
    /// let mut chain = TransformationChain::new();
    /// chain.add("lowercase", lowercase).unwrap();
    /// chain.add("urlDecode", url_decode).unwrap();
    /// ```
    pub fn add(&mut self, name: impl Into<String>, function: Transformation) -> Result<(), String> {
        let name = name.into();
        if name.is_empty() {
            return Err("transformation name cannot be empty".to_string());
        }

        self.transformations
            .push(NamedTransformation { name, function });
        Ok(())
    }

    /// Clear all transformations from the chain.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::rules::TransformationChain;
    /// use coraza::transformations::lowercase;
    ///
    /// let mut chain = TransformationChain::new();
    /// chain.add("lowercase", lowercase).unwrap();
    /// chain.clear();
    /// assert_eq!(chain.len(), 0);
    /// ```
    pub fn clear(&mut self) {
        self.transformations.clear();
    }

    /// Get the number of transformations in the chain.
    pub fn len(&self) -> usize {
        self.transformations.len()
    }

    /// Check if the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.transformations.is_empty()
    }

    /// Get the names of all transformations in the chain.
    ///
    /// This is useful for debugging and logging.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::rules::TransformationChain;
    /// use coraza::transformations::lowercase;
    ///
    /// let mut chain = TransformationChain::new();
    /// chain.add("lowercase", lowercase).unwrap();
    /// chain.add("urlDecode", lowercase).unwrap();
    ///
    /// assert_eq!(chain.names(), vec!["lowercase", "urlDecode"]);
    /// ```
    pub fn names(&self) -> Vec<&str> {
        self.transformations
            .iter()
            .map(|t| t.name.as_str())
            .collect()
    }

    /// Apply all transformations in the chain sequentially.
    ///
    /// Each transformation's output becomes the next transformation's input.
    /// Errors are collected but don't stop execution.
    ///
    /// # Arguments
    ///
    /// * `input` - The input string to transform
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - The final transformed string
    /// - A vector of transformation errors encountered (if any)
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::rules::TransformationChain;
    /// use coraza::transformations::lowercase;
    ///
    /// let mut chain = TransformationChain::new();
    /// chain.add("lowercase", lowercase).unwrap();
    ///
    /// let (result, errors) = chain.apply(b"HELLO");
    /// assert_eq!(result, b"hello");
    /// assert!(errors.is_empty());
    /// ```
    pub fn apply(&self, input: &[u8]) -> (Vec<u8>, Vec<TransformationError>) {
        if self.transformations.is_empty() {
            return (input.to_vec(), Vec::new());
        }

        let mut value = input.to_vec();
        let mut errors = Vec::new();

        for t in &self.transformations {
            let (transformed, _changed, err) = (t.function)(&value);
            if let Some(e) = err {
                errors.push(e);
                continue;
            }
            value = transformed;
        }

        (for_operator(value), errors)
    }

    /// Apply all transformations in multi-match mode.
    ///
    /// In multi-match mode, the chain collects all intermediate values that
    /// were changed by transformations. This allows operators to match against
    /// both the original value and all transformed values.
    ///
    /// # Arguments
    ///
    /// * `input` - The input string to transform
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - A vector of all values (original + all changed intermediate values)
    /// - A vector of transformation errors encountered (if any)
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::rules::TransformationChain;
    /// use coraza::transformations::lowercase;
    ///
    /// let mut chain = TransformationChain::new();
    /// chain.add("lowercase", lowercase).unwrap();
    ///
    /// let (values, errors) = chain.apply_multimatch(b"HELLO");
    /// assert_eq!(values, vec![b"HELLO".to_vec(), b"hello".to_vec()]);
    /// assert!(errors.is_empty());
    /// ```
    pub fn apply_multimatch(&self, input: &[u8]) -> (Vec<Vec<u8>>, Vec<TransformationError>) {
        // Always include the original value
        let mut values = vec![input.to_vec()];
        let mut errors = Vec::new();

        if self.transformations.is_empty() {
            return (values, errors);
        }

        let mut value = input.to_vec();

        for t in &self.transformations {
            let (transformed, changed, err) = (t.function)(&value);
            if let Some(e) = err {
                errors.push(e);
                continue;
            }

            // Only collect values that changed
            if changed {
                values.push(for_operator(transformed.clone()));
                value = transformed;
            }
        }

        (values, errors)
    }
}

/// A transformed value as the operator gets it: for now, with invalid UTF-8 replaced with
/// U+FFFD, as when values were text.
fn for_operator(value: Vec<u8>) -> Vec<u8> {
    text_from_bytes(value).into_bytes()
}

impl Default for TransformationChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transformations::{
        TransformationResult, hex_encode, lowercase, sha1_hash, uppercase, url_decode,
    };

    // Helper transformations for testing
    fn append_a(input: &[u8]) -> TransformationResult {
        ([input, b"A"].concat(), true, None)
    }

    fn append_b(input: &[u8]) -> TransformationResult {
        ([input, b"B"].concat(), true, None)
    }

    fn error_a(_input: &[u8]) -> TransformationResult {
        (Vec::new(), false, Some(TransformationError::new("errorA")))
    }

    fn error_b(_input: &[u8]) -> TransformationResult {
        (Vec::new(), false, Some(TransformationError::new("errorB")))
    }

    // Ported from: coraza/internal/corazawaf/rule_test.go::TestAddTransformation
    #[test]
    fn test_add_transformation() {
        let mut chain = TransformationChain::new();
        let result = chain.add("transformation", append_a);

        assert!(result.is_ok());
        assert_eq!(chain.len(), 1);
    }

    // Ported from: coraza/internal/corazawaf/rule_test.go::TestAddTransformationEmpty
    #[test]
    fn test_add_transformation_empty_name() {
        let mut chain = TransformationChain::new();
        let result = chain.add("", append_a);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "transformation name cannot be empty");
    }

    // Ported from: coraza/internal/corazawaf/rule_test.go::TestClearTransformation
    #[test]
    fn test_clear_transformation() {
        let mut chain = TransformationChain::new();
        chain.add("trans", append_a).unwrap();

        assert_eq!(chain.len(), 1);

        chain.clear();

        assert_eq!(chain.len(), 0);
        assert!(chain.is_empty());
    }

    // Ported from: coraza/internal/corazawaf/rule_test.go::TestExecuteTransformations
    #[test]
    fn test_execute_transformations() {
        let mut chain = TransformationChain::new();
        chain.add("AppendA", append_a).unwrap();
        chain.add("AppendB", append_b).unwrap();

        let (result, errors) = chain.apply(b"input");

        assert_eq!(result, b"inputAB");
        assert!(errors.is_empty());
    }

    // Ported from: coraza/internal/corazawaf/rule_test.go::TestExecuteTransformationsReturnsMultipleErrors
    #[test]
    fn test_execute_transformations_returns_multiple_errors() {
        let mut chain = TransformationChain::new();
        chain.add("AppendA", error_a).unwrap();
        chain.add("AppendB", error_b).unwrap();

        let (_result, errors) = chain.apply(b"arg");

        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].message(), "errorA");
        assert_eq!(errors[1].message(), "errorB");
    }

    // Ported from: coraza/internal/corazawaf/rule_test.go::TestExecuteTransformationsMultiMatch
    #[test]
    fn test_execute_transformations_multimatch() {
        let mut chain = TransformationChain::new();
        chain.add("AppendA", append_a).unwrap();
        chain.add("AppendB", append_b).unwrap();

        let (values, errors) = chain.apply_multimatch(b"input");

        assert!(errors.is_empty());
        assert_eq!(values.len(), 3);
        assert_eq!(values[0], b"input");
        assert_eq!(values[1], b"inputA");
        assert_eq!(values[2], b"inputAB");
    }

    #[test]
    fn test_empty_chain_apply() {
        let chain = TransformationChain::new();
        let (result, errors) = chain.apply(b"test");

        assert_eq!(result, b"test");
        assert!(errors.is_empty());
    }

    #[test]
    fn test_empty_chain_multimatch() {
        let chain = TransformationChain::new();
        let (values, errors) = chain.apply_multimatch(b"test");

        assert_eq!(values, vec![b"test".to_vec()]);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_real_transformations() {
        let mut chain = TransformationChain::new();
        chain.add("uppercase", uppercase).unwrap();
        chain.add("lowercase", lowercase).unwrap();

        let (result, errors) = chain.apply(b"HeLLo");

        assert_eq!(result, b"hello");
        assert!(errors.is_empty());
    }

    #[test]
    fn test_multimatch_no_change() {
        // If a transformation doesn't change the value, it shouldn't be included
        fn no_change(input: &[u8]) -> TransformationResult {
            (input.to_vec(), false, None)
        }

        let mut chain = TransformationChain::new();
        chain.add("append", append_a).unwrap();
        chain.add("nochange", no_change).unwrap();
        chain.add("append2", append_b).unwrap();

        let (values, errors) = chain.apply_multimatch(b"input");

        assert!(errors.is_empty());
        // Should have: original "input", changed "inputA", changed "inputAB"
        // The no_change transformation doesn't add a value since changed=false
        assert_eq!(values.len(), 3);
        assert_eq!(values[0], b"input");
        assert_eq!(values[1], b"inputA");
        assert_eq!(values[2], b"inputAB");
    }

    #[test]
    fn test_error_doesnt_stop_chain() {
        let mut chain = TransformationChain::new();
        chain.add("AppendA", append_a).unwrap();
        chain.add("Error", error_a).unwrap();
        chain.add("AppendB", append_b).unwrap();

        let (result, errors) = chain.apply(b"input");

        // Chain should continue despite error
        assert_eq!(result, b"inputAB");
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message(), "errorA");
    }

    #[test]
    fn test_names() {
        let mut chain = TransformationChain::new();
        chain.add("lowercase", lowercase).unwrap();
        chain.add("uppercase", uppercase).unwrap();
        chain.add("custom", append_a).unwrap();

        let names = chain.names();
        assert_eq!(names, vec!["lowercase", "uppercase", "custom"]);
    }

    #[test]
    fn test_empty_names() {
        let chain = TransformationChain::new();
        let names = chain.names();
        assert!(names.is_empty());
    }

    #[test]
    fn test_bytes_pass_between_transformations() {
        let mut chain = TransformationChain::new();
        chain.add("sha1", sha1_hash).unwrap();
        chain.add("hexEncode", hex_encode).unwrap();
        let (result, errors) = chain.apply(b"hello");
        assert_eq!(result, b"aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
        assert!(errors.is_empty());

        let mut chain = TransformationChain::new();
        chain.add("urlDecode", url_decode).unwrap();
        chain.add("hexEncode", hex_encode).unwrap();
        assert_eq!(chain.apply(b"%ff").0, b"ff");
        // The operator gets text
        assert_eq!(
            chain.apply_multimatch(b"%ff").0,
            vec![
                b"%ff".to_vec(),
                "\u{FFFD}".as_bytes().to_vec(),
                b"ff".to_vec()
            ]
        );
    }
}
