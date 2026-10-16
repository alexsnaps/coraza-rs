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
//! use coraza::RuleVariable;
//! use coraza::body_processors::{BodyProcessorKind, BodyProcessorOptions};
//! use coraza::waf::Waf;
//!
//! let content_type = "application/x-www-form-urlencoded";
//! let processor = BodyProcessorKind::for_content_type(content_type).unwrap();
//!
//! let mut tx = Waf::default().new_transaction();
//! let options = BodyProcessorOptions { mime: content_type.to_string(), ..Default::default() };
//! processor.process_request(b"username=admin", &mut tx, &options)?;
//! let username = tx.get_variable(RuleVariable::ArgsPost, Some("username"));
//! assert_eq!(username.as_deref(), Some("admin"));
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
#[derive(Debug, Clone)]
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

    /// Deepest nesting of objects and arrays a JSON body may have
    pub json_depth_limit: usize,
}

impl Default for BodyProcessorOptions {
    fn default() -> Self {
        Self {
            mime: String::new(),
            upload_dir: String::new(),
            file_mode: 0,
            dir_mode: 0,
            file_limit: 0,
            keep_files: false,
            json_depth_limit: crate::config::DEFAULT_JSON_DEPTH_LIMIT,
        }
    }
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

/// The built-in body processors, named as `REQBODY_PROCESSOR` and
/// `ctl:requestBodyProcessor` name them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyProcessorKind {
    /// Keeps the body as-is (`REQUEST_BODY` only): `RAW`
    Raw,
    /// `application/x-www-form-urlencoded`: `URLENCODED`
    UrlEncoded,
    /// `multipart/form-data`: `MULTIPART`
    Multipart,
    /// JSON: `JSON`
    Json,
    /// XML: `XML`
    Xml,
}

impl BodyProcessorKind {
    /// The processor a request `Content-Type` value selects, matched by
    /// case-insensitive prefix: urlencoded and multipart only. As in Go Coraza, JSON
    /// and XML bodies need `ctl:requestBodyProcessor`.
    pub fn for_content_type(content_type: &str) -> Option<Self> {
        let content_type = content_type.trim().to_ascii_lowercase();
        if content_type.starts_with("application/x-www-form-urlencoded") {
            Some(Self::UrlEncoded)
        } else if content_type.starts_with("multipart/form-data") {
            Some(Self::Multipart)
        } else {
            None
        }
    }

    /// The processor's name, e.g. `URLENCODED`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Raw => "RAW",
            Self::UrlEncoded => "URLENCODED",
            Self::Multipart => "MULTIPART",
            Self::Json => "JSON",
            Self::Xml => "XML",
        }
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

impl std::str::FromStr for BodyProcessorKind {
    type Err = crate::types::ParseValueError;

    /// Parses a processor name, case-insensitive: `URLENCODED`, `MULTIPART`, `JSON`,
    /// `XML` or `RAW`.
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        [
            Self::Raw,
            Self::UrlEncoded,
            Self::Multipart,
            Self::Json,
            Self::Xml,
        ]
        .into_iter()
        .find(|kind| kind.name().eq_ignore_ascii_case(name))
        .ok_or_else(|| {
            crate::types::ParseValueError::new("unknown body processor", name.to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_content_type_matches_by_prefix_ignoring_case() {
        assert_eq!(
            BodyProcessorKind::for_content_type("Application/X-WWW-Form-Urlencoded; charset=utf-8"),
            Some(BodyProcessorKind::UrlEncoded)
        );
        assert_eq!(
            BodyProcessorKind::for_content_type("multipart/form-data; boundary=x"),
            Some(BodyProcessorKind::Multipart)
        );
    }

    #[test]
    fn for_content_type_rejects_unparsed_types() {
        assert_eq!(BodyProcessorKind::for_content_type("text/plain"), None);
        assert_eq!(BodyProcessorKind::for_content_type(""), None);
        // As in Go, JSON and XML need ctl:requestBodyProcessor
        assert_eq!(
            BodyProcessorKind::for_content_type("application/json"),
            None
        );
        assert_eq!(BodyProcessorKind::for_content_type("text/xml"), None);
    }

    #[test]
    fn names_round_trip() {
        for name in ["RAW", "URLENCODED", "MULTIPART", "JSON", "XML"] {
            let kind: BodyProcessorKind = name.to_lowercase().parse().unwrap();
            assert_eq!(kind.name(), name);
        }
        assert!("YAML".parse::<BodyProcessorKind>().is_err());
    }
}
