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
//! use coraza::body_processors::{BodyProcessorKind, BodyProcessorOptions};
//! use coraza::transaction::Transaction;
//!
//! let content_type = "application/x-www-form-urlencoded";
//! let processor = BodyProcessorKind::for_content_type(content_type).unwrap();
//!
//! let mut tx = Transaction::new("tx-1");
//! let options = BodyProcessorOptions { mime: content_type.to_string(), ..Default::default() };
//! processor.process_request(b"username=admin", &mut tx, &options)?;
//! assert_eq!(tx.args_post().get("username"), vec!["admin"]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::transaction::Transaction;
use std::io;

pub mod json;
pub mod multipart;
pub mod raw;
pub mod urlencoded;
pub mod xml;

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
    /// MIME type of the request body (e.g., "multipart/form-data; boundary=...")
    pub mime: String,

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

/// The built-in body processors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyProcessorKind {
    /// Keeps the body as-is (`REQUEST_BODY` only)
    Raw,
    /// `application/x-www-form-urlencoded`
    UrlEncoded,
    /// `multipart/form-data`
    Multipart,
    /// `application/json`
    Json,
    /// `application/xml`, `text/xml`
    Xml,
}

impl BodyProcessorKind {
    /// The processor for a request `Content-Type` value, matched by case-insensitive
    /// prefix (as in Go Coraza); `None` if no processor parses that content type.
    pub fn for_content_type(content_type: &str) -> Option<Self> {
        const BY_PREFIX: [(&str, BodyProcessorKind); 5] = [
            (
                "application/x-www-form-urlencoded",
                BodyProcessorKind::UrlEncoded,
            ),
            ("multipart/form-data", BodyProcessorKind::Multipart),
            ("application/json", BodyProcessorKind::Json),
            ("application/xml", BodyProcessorKind::Xml),
            ("text/xml", BodyProcessorKind::Xml),
        ];
        let content_type = content_type.to_ascii_lowercase();
        BY_PREFIX
            .iter()
            .find(|(prefix, _)| content_type.starts_with(prefix))
            .map(|&(_, kind)| kind)
    }

    /// Parses a request body into `tx`; see [`BodyProcessor::process_request`].
    ///
    /// # Errors
    ///
    /// Returns an error if the body is malformed for this processor.
    pub fn process_request(
        self,
        body: &[u8],
        tx: &mut Transaction,
        options: &BodyProcessorOptions,
    ) -> Result<(), BodyProcessorError> {
        self.processor().process_request(body, tx, options)
    }

    /// Parses a response body into `tx`; see [`BodyProcessor::process_response`].
    ///
    /// # Errors
    ///
    /// Returns an error if the body is malformed for this processor.
    pub fn process_response(
        self,
        body: &[u8],
        tx: &mut Transaction,
        options: &BodyProcessorOptions,
    ) -> Result<(), BodyProcessorError> {
        self.processor().process_response(body, tx, options)
    }

    fn processor(self) -> &'static dyn BodyProcessor {
        match self {
            Self::Raw => &raw::RawBodyProcessor,
            Self::UrlEncoded => &urlencoded::UrlencodedBodyProcessor,
            Self::Multipart => &multipart::MultipartBodyProcessor,
            Self::Json => &json::JsonBodyProcessor,
            Self::Xml => &xml::XmlBodyProcessor,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_content_type_matches_by_prefix_ignoring_case() {
        assert_eq!(
            BodyProcessorKind::for_content_type("Application/JSON; charset=utf-8"),
            Some(BodyProcessorKind::Json)
        );
        assert_eq!(
            BodyProcessorKind::for_content_type("multipart/form-data; boundary=x"),
            Some(BodyProcessorKind::Multipart)
        );
        assert_eq!(
            BodyProcessorKind::for_content_type("text/xml"),
            Some(BodyProcessorKind::Xml)
        );
        assert_eq!(
            BodyProcessorKind::for_content_type("application/json-patch+json"),
            Some(BodyProcessorKind::Json)
        );
    }

    #[test]
    fn for_content_type_rejects_unparsed_types() {
        assert_eq!(BodyProcessorKind::for_content_type("text/plain"), None);
        assert_eq!(BodyProcessorKind::for_content_type(""), None);
    }
}
