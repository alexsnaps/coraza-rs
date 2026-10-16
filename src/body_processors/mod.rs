// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Body processors: the parsers that turn a transaction's request or response body into
//! variables, as `REQBODY_PROCESSOR` and `RES_BODY_PROCESSOR` name them.
//!
//! A transaction runs them from [`Transaction::process_request_body`] and
//! [`Transaction::process_response_body`], which record their failures in `REQBODY_ERROR`
//! and `RES_BODY_ERROR`. Each one writes only its own variables, and reads what it needs
//! (the `Content-Type`, the WAF's limits and upload directory) from the transaction.

use crate::transaction::Transaction;
use std::io;

mod json;
mod multipart;
mod raw;
mod urlencoded;
mod xml;

pub(crate) use urlencoded::parse_query;

/// Why a body processor could not parse a body. Its text ends up in the variables rules
/// read, such as `REQBODY_ERROR_MSG`.
#[derive(Debug)]
pub(crate) enum BodyProcessorError {
    /// Storing an uploaded file failed
    Io(io::Error),

    /// The body's encoding, as its content type gives it, is invalid: the kind of body,
    /// and why
    InvalidEncoding(String, String),

    /// The body is malformed: the kind of body, and how
    Malformed(String, String),
}

impl std::fmt::Display for BodyProcessorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyProcessorError::Io(e) => write!(f, "I/O error: {}", e),
            BodyProcessorError::InvalidEncoding(typ, msg) => {
                write!(f, "invalid {} encoding: {}", typ, msg)
            }
            BodyProcessorError::Malformed(typ, msg) => write!(f, "malformed {}: {}", typ, msg),
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

/// The built-in body processors, named as `REQBODY_PROCESSOR` and
/// `ctl:requestBodyProcessor` name them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyProcessorKind {
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
    pub(crate) fn for_content_type(content_type: &str) -> Option<Self> {
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
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Raw => "RAW",
            Self::UrlEncoded => "URLENCODED",
            Self::Multipart => "MULTIPART",
            Self::Json => "JSON",
            Self::Xml => "XML",
        }
    }

    /// Parses a request body into `tx`'s variables.
    ///
    /// # Errors
    ///
    /// If the body is malformed for this processor, or an uploaded file can't be stored.
    pub(crate) fn process_request(
        self,
        body: &[u8],
        tx: &mut Transaction,
    ) -> Result<(), BodyProcessorError> {
        match self {
            Self::Multipart => multipart::process_request(body, tx),
            Self::Json => json::process_request(body, tx),
            // Any body parses as these
            Self::Raw => {
                raw::process_request(body, tx);
                Ok(())
            }
            Self::UrlEncoded => {
                urlencoded::process_request(body, tx);
                Ok(())
            }
            Self::Xml => {
                xml::process_request(body, tx);
                Ok(())
            }
        }
    }

    /// Parses a response body into `tx`'s variables; only JSON ones are parsed, the
    /// others are left alone.
    ///
    /// # Errors
    ///
    /// If the body is malformed for this processor.
    pub(crate) fn process_response(
        self,
        body: &[u8],
        tx: &mut Transaction,
    ) -> Result<(), BodyProcessorError> {
        match self {
            Self::Json => json::process_response(body, tx),
            Self::Raw | Self::UrlEncoded | Self::Multipart | Self::Xml => Ok(()),
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

/// A transaction whose request body, of `content_type`, `processor` inspected in the
/// request body phase, with request body access and otherwise `config`'s settings.
#[cfg(test)]
fn inspect_request_with(
    config: crate::config::WafConfig,
    processor: BodyProcessorKind,
    content_type: &str,
    body: &[u8],
) -> Transaction {
    let mut tx = Transaction::with_config(
        "test",
        std::sync::Arc::new(crate::config::WafConfig {
            request_body_access: true,
            ..config
        }),
    );
    tx.add_request_header("Content-Type", content_type);
    tx.set_request_body_processor(processor);
    tx.process_request_headers();
    tx.process_request_body(body);
    tx
}

/// [`inspect_request_with`] a default WAF's settings.
#[cfg(test)]
fn inspect_request(processor: BodyProcessorKind, content_type: &str, body: &[u8]) -> Transaction {
    inspect_request_with(
        crate::config::WafConfig::default(),
        processor,
        content_type,
        body,
    )
}

/// A transaction whose JSON response body `processor` inspected in the response body
/// phase.
#[cfg(test)]
fn inspect_response(processor: BodyProcessorKind, body: &[u8]) -> Transaction {
    let mut tx = Transaction::with_config(
        "test",
        std::sync::Arc::new(crate::config::WafConfig {
            response_body_access: true,
            response_body_mime_types: vec!["application/json".to_string()],
            ..crate::config::WafConfig::default()
        }),
    );
    tx.add_response_header("Content-Type", "application/json");
    tx.set_response_body_processor(processor);
    tx.process_response_headers(200, "HTTP/1.1");
    tx.process_response_body(body);
    tx
}

/// REQBODY_PROCESSOR_ERROR_MSG, if the request body processor failed.
#[cfg(test)]
fn request_error(tx: &Transaction) -> Option<String> {
    use crate::RuleVariable::{ReqbodyProcessorError, ReqbodyProcessorErrorMsg};
    let failed = tx.get_variable(ReqbodyProcessorError, None).as_deref() == Some("1");
    failed.then(|| {
        tx.get_variable(ReqbodyProcessorErrorMsg, None)
            .unwrap_or_default()
    })
}

/// RES_BODY_PROCESSOR_ERROR_MSG, if the response body processor failed.
#[cfg(test)]
fn response_error(tx: &Transaction) -> Option<String> {
    use crate::RuleVariable::{ResBodyProcessorError, ResBodyProcessorErrorMsg};
    let failed = tx.get_variable(ResBodyProcessorError, None).as_deref() == Some("1");
    failed.then(|| {
        tx.get_variable(ResBodyProcessorErrorMsg, None)
            .unwrap_or_default()
    })
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
