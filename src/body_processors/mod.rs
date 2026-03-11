// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Body processors for different content types.
//!
//! Body processors parse HTTP request and response bodies and populate
//! transaction variables accordingly. Different processors handle different
//! content types (URL-encoded, JSON, XML, multipart, etc.).
//!
//! # Example
//!
//! ```
//! use coraza::body_processors::{get_body_processor, BodyProcessorOptions};
//! use coraza::transaction::Transaction;
//!
//! // Get the URL-encoded body processor
//! let processor = get_body_processor("urlencoded");
//! // Processor will be available once URL-encoded is implemented
//!
//! // Example when implemented:
//! // let mut tx = Transaction::new("tx-1");
//! // let body = b"username=admin&password=secret";
//! // processor.process_request(body, &mut tx, BodyProcessorOptions::default())?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::transaction::Transaction;
use std::collections::HashMap;
use std::io;
use std::sync::{LazyLock, RwLock};

pub mod raw;
pub mod urlencoded;

/// Body processor error types
#[derive(Debug)]
pub enum BodyProcessorError {
    /// I/O error while reading body
    Io(io::Error),

    /// Body exceeds size limit
    SizeLimit(usize, usize),

    /// Invalid content encoding
    InvalidEncoding(String, String),

    /// Malformed content
    Malformed(String, String),

    /// Generic error
    Generic(String),
}

impl std::fmt::Display for BodyProcessorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyProcessorError::Io(e) => write!(f, "I/O error: {}", e),
            BodyProcessorError::SizeLimit(size, limit) => {
                write!(f, "body size {} exceeds limit {}", size, limit)
            }
            BodyProcessorError::InvalidEncoding(typ, msg) => {
                write!(f, "invalid {} encoding: {}", typ, msg)
            }
            BodyProcessorError::Malformed(typ, msg) => write!(f, "malformed {}: {}", typ, msg),
            BodyProcessorError::Generic(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for BodyProcessorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BodyProcessorError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for BodyProcessorError {
    fn from(err: io::Error) -> Self {
        BodyProcessorError::Io(err)
    }
}

/// Options passed to body processors
#[derive(Debug, Clone, Default)]
pub struct BodyProcessorOptions {
    /// Upload directory for file uploads (multipart)
    pub upload_dir: String,

    /// File mode for uploaded files (octal, e.g., 0o600)
    pub file_mode: u32,

    /// Directory mode for upload directory (octal, e.g., 0o700)
    pub dir_mode: u32,

    /// Maximum number of files in multipart upload
    pub file_limit: usize,

    /// Keep uploaded files after transaction
    pub keep_files: bool,
}

/// Body processor trait for processing request and response bodies
///
/// Body processors are responsible for parsing bodies and populating
/// transaction variables based on the content type.
pub trait BodyProcessor: Send + Sync {
    /// Process request body and populate transaction variables
    ///
    /// # Arguments
    ///
    /// * `body` - The raw request body bytes
    /// * `tx` - The transaction to populate
    /// * `options` - Body processor options
    ///
    /// # Example
    ///
    /// ```
    /// use coraza::body_processors::{BodyProcessor, BodyProcessorOptions, BodyProcessorError};
    /// use coraza::transaction::Transaction;
    ///
    /// struct MyProcessor;
    ///
    /// impl BodyProcessor for MyProcessor {
    ///     fn process_request(&self, body: &[u8], tx: &mut Transaction,
    ///                        options: &BodyProcessorOptions)
    ///                       -> Result<(), BodyProcessorError> {
    ///         // Parse body and populate tx variables
    ///         Ok(())
    ///     }
    ///
    ///     fn process_response(&self, _body: &[u8], _tx: &mut Transaction,
    ///                         _options: &BodyProcessorOptions)
    ///                        -> Result<(), BodyProcessorError> {
    ///         Ok(())
    ///     }
    /// }
    /// ```
    fn process_request(
        &self,
        body: &[u8],
        tx: &mut Transaction,
        options: &BodyProcessorOptions,
    ) -> Result<(), BodyProcessorError>;

    /// Process response body and populate transaction variables
    ///
    /// # Arguments
    ///
    /// * `body` - The raw response body bytes
    /// * `tx` - The transaction to populate
    /// * `options` - Body processor options
    fn process_response(
        &self,
        body: &[u8],
        tx: &mut Transaction,
        options: &BodyProcessorOptions,
    ) -> Result<(), BodyProcessorError>;
}

/// Factory function for creating body processors
pub type BodyProcessorFactory = fn() -> Box<dyn BodyProcessor>;

/// Global registry of body processors
static BODY_PROCESSORS: LazyLock<RwLock<HashMap<String, BodyProcessorFactory>>> =
    LazyLock::new(|| {
        let mut registry = HashMap::new();
        // Register built-in processors
        registry.insert("raw".to_string(), raw::create_raw as BodyProcessorFactory);
        registry.insert(
            "urlencoded".to_string(),
            urlencoded::create_urlencoded as BodyProcessorFactory,
        );
        RwLock::new(registry)
    });

/// Register a body processor by name
///
/// If a processor with the same name already exists, it will be overwritten.
///
/// # Example
///
/// ```
/// use coraza::body_processors::{register_body_processor, BodyProcessor, BodyProcessorOptions, BodyProcessorError};
/// use coraza::transaction::Transaction;
///
/// struct CustomProcessor;
///
/// impl BodyProcessor for CustomProcessor {
///     fn process_request(&self, _body: &[u8], _tx: &mut Transaction,
///                        _options: &BodyProcessorOptions)
///                       -> Result<(), BodyProcessorError> {
///         Ok(())
///     }
///
///     fn process_response(&self, _body: &[u8], _tx: &mut Transaction,
///                         _options: &BodyProcessorOptions)
///                        -> Result<(), BodyProcessorError> {
///         Ok(())
///     }
/// }
///
/// fn create_custom() -> Box<dyn BodyProcessor> {
///     Box::new(CustomProcessor)
/// }
///
/// register_body_processor("custom", create_custom);
/// ```
pub fn register_body_processor(name: &str, factory: BodyProcessorFactory) {
    let mut registry = BODY_PROCESSORS.write().unwrap();
    registry.insert(name.to_lowercase(), factory);
}

/// Get a body processor by name
///
/// # Errors
///
/// Returns an error if the processor is not registered.
///
/// # Example
///
/// ```
/// use coraza::body_processors::get_body_processor;
///
/// let processor = get_body_processor("raw")?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn get_body_processor(name: &str) -> Result<Box<dyn BodyProcessor>, BodyProcessorError> {
    let registry = BODY_PROCESSORS.read().unwrap();
    registry
        .get(&name.to_lowercase())
        .map(|factory| factory())
        .ok_or_else(|| BodyProcessorError::Generic(format!("invalid bodyprocessor {:?}", name)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_get_processor() {
        struct TestProcessor;

        impl BodyProcessor for TestProcessor {
            fn process_request(
                &self,
                _body: &[u8],
                _tx: &mut Transaction,
                _options: &BodyProcessorOptions,
            ) -> Result<(), BodyProcessorError> {
                Ok(())
            }

            fn process_response(
                &self,
                _body: &[u8],
                _tx: &mut Transaction,
                _options: &BodyProcessorOptions,
            ) -> Result<(), BodyProcessorError> {
                Ok(())
            }
        }

        fn create_test() -> Box<dyn BodyProcessor> {
            Box::new(TestProcessor)
        }

        register_body_processor("test", create_test);
        let processor = get_body_processor("test");
        assert!(processor.is_ok());
    }

    #[test]
    fn test_get_processor_case_insensitive() {
        let processor1 = get_body_processor("RAW");
        let processor2 = get_body_processor("raw");
        let processor3 = get_body_processor("Raw");

        assert!(processor1.is_ok());
        assert!(processor2.is_ok());
        assert!(processor3.is_ok());
    }

    #[test]
    fn test_get_nonexistent_processor() {
        let processor = get_body_processor("nonexistent");
        assert!(processor.is_err());
        if let Err(e) = processor {
            assert!(e.to_string().contains("invalid bodyprocessor"));
        }
    }

    #[test]
    fn test_raw_processor_registered() {
        let processor = get_body_processor("raw");
        assert!(processor.is_ok());
    }
}
