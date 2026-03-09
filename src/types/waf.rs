// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! WAF engine configuration types.
//!
//! This module contains types for configuring the WAF engine behavior,
//! audit logging, and rule processing.

use std::fmt;
use std::str::FromStr;

/// Status of the audit logging engine.
///
/// Controls whether and when transactions are logged for audit purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AuditEngineStatus {
    /// Audit each auditable event
    On = 0,
    /// Do not audit any event
    Off = 1,
    /// Audit only relevant events (events that trigger rules)
    RelevantOnly = 2,
}

impl AuditEngineStatus {
    /// Returns the string representation of the audit engine status.
    pub const fn as_str(&self) -> &'static str {
        match self {
            AuditEngineStatus::On => "On",
            AuditEngineStatus::Off => "Off",
            AuditEngineStatus::RelevantOnly => "RelevantOnly",
        }
    }
}

impl fmt::Display for AuditEngineStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error type for invalid audit engine status parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseAuditEngineStatusError {
    input: String,
}

impl fmt::Display for ParseAuditEngineStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid audit engine status: {}", self.input)
    }
}

impl std::error::Error for ParseAuditEngineStatusError {}

impl FromStr for AuditEngineStatus {
    type Err = ParseAuditEngineStatusError;

    /// Parses an audit engine status from a string (case-insensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::types::AuditEngineStatus;
    /// use std::str::FromStr;
    ///
    /// assert_eq!(AuditEngineStatus::from_str("on").unwrap(), AuditEngineStatus::On);
    /// assert_eq!(AuditEngineStatus::from_str("OFF").unwrap(), AuditEngineStatus::Off);
    /// assert_eq!(AuditEngineStatus::from_str("RelevantOnly").unwrap(), AuditEngineStatus::RelevantOnly);
    /// assert!(AuditEngineStatus::from_str("invalid").is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "on" => Ok(AuditEngineStatus::On),
            "off" => Ok(AuditEngineStatus::Off),
            "relevantonly" => Ok(AuditEngineStatus::RelevantOnly),
            _ => Err(ParseAuditEngineStatusError {
                input: s.to_string(),
            }),
        }
    }
}

/// Status of the rule processing engine.
///
/// Controls whether rules are processed and whether they can generate disruptive actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RuleEngineStatus {
    /// Process each rule and may generate disruptive actions (block, deny, etc.)
    On = 0,
    /// Process each rule but only log matches, no disruptive actions
    DetectionOnly = 1,
    /// Do not process any rules
    Off = 2,
}

impl RuleEngineStatus {
    /// Returns the string representation of the rule engine status.
    pub const fn as_str(&self) -> &'static str {
        match self {
            RuleEngineStatus::On => "On",
            RuleEngineStatus::DetectionOnly => "DetectionOnly",
            RuleEngineStatus::Off => "Off",
        }
    }
}

impl fmt::Display for RuleEngineStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error type for invalid rule engine status parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseRuleEngineStatusError {
    input: String,
}

impl fmt::Display for ParseRuleEngineStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid rule engine status: {}", self.input)
    }
}

impl std::error::Error for ParseRuleEngineStatusError {}

impl FromStr for RuleEngineStatus {
    type Err = ParseRuleEngineStatusError;

    /// Parses a rule engine status from a string (case-insensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::types::RuleEngineStatus;
    /// use std::str::FromStr;
    ///
    /// assert_eq!(RuleEngineStatus::from_str("on").unwrap(), RuleEngineStatus::On);
    /// assert_eq!(RuleEngineStatus::from_str("DetectionOnly").unwrap(), RuleEngineStatus::DetectionOnly);
    /// assert_eq!(RuleEngineStatus::from_str("OFF").unwrap(), RuleEngineStatus::Off);
    /// assert!(RuleEngineStatus::from_str("invalid").is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "on" => Ok(RuleEngineStatus::On),
            "detectiononly" => Ok(RuleEngineStatus::DetectionOnly),
            "off" => Ok(RuleEngineStatus::Off),
            _ => Err(ParseRuleEngineStatusError {
                input: s.to_string(),
            }),
        }
    }
}

/// Action to take when body size exceeds configured limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BodyLimitAction {
    /// Process the body up to the limit and ignore remaining bytes
    ProcessPartial = 0,
    /// Reject the connection when body size exceeds the limit
    Reject = 1,
}

impl BodyLimitAction {
    /// Returns the string representation of the body limit action.
    pub const fn as_str(&self) -> &'static str {
        match self {
            BodyLimitAction::ProcessPartial => "ProcessPartial",
            BodyLimitAction::Reject => "Reject",
        }
    }

    /// Returns the numeric value.
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl fmt::Display for BodyLimitAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parts of an audit log entry.
///
/// Audit logs are divided into sections identified by letters A-K and Z.
/// Parts A (header) and Z (end marker) are mandatory.
///
/// See ModSecurity documentation for details on each part:
/// <https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)#secauditlogparts>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AuditLogPart {
    /// A: Audit log header (mandatory)
    Header = b'A',
    /// B: Request headers
    RequestHeaders = b'B',
    /// C: Request body
    RequestBody = b'C',
    /// D: Intermediary response headers (reserved, not implemented)
    IntermediaryResponseHeaders = b'D',
    /// E: Intermediary response body (reserved, not implemented)
    IntermediaryResponseBody = b'E',
    /// F: Final response headers
    ResponseHeaders = b'F',
    /// G: Response body (reserved, not fully implemented)
    ResponseBody = b'G',
    /// H: Audit log trailer
    Trailer = b'H',
    /// I: Request body alternative (replacement for C)
    RequestBodyAlternative = b'I',
    /// J: Uploaded files information (multipart/form-data)
    UploadedFiles = b'J',
    /// K: List of matched rules
    RulesMatched = b'K',
    /// Z: Final boundary, end of entry (mandatory)
    EndMarker = b'Z',
}

impl AuditLogPart {
    /// Returns the character representation of the audit log part.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::types::AuditLogPart;
    ///
    /// assert_eq!(AuditLogPart::Header.as_char(), 'A');
    /// assert_eq!(AuditLogPart::RequestHeaders.as_char(), 'B');
    /// assert_eq!(AuditLogPart::EndMarker.as_char(), 'Z');
    /// ```
    pub const fn as_char(&self) -> char {
        *self as u8 as char
    }

    /// Returns the byte representation of the audit log part.
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Creates an AuditLogPart from a character.
    ///
    /// Returns None if the character doesn't correspond to a valid part.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::types::AuditLogPart;
    ///
    /// assert_eq!(AuditLogPart::from_char('A'), Some(AuditLogPart::Header));
    /// assert_eq!(AuditLogPart::from_char('B'), Some(AuditLogPart::RequestHeaders));
    /// assert_eq!(AuditLogPart::from_char('X'), None);
    /// ```
    pub const fn from_char(c: char) -> Option<Self> {
        match c {
            'A' => Some(AuditLogPart::Header),
            'B' => Some(AuditLogPart::RequestHeaders),
            'C' => Some(AuditLogPart::RequestBody),
            'D' => Some(AuditLogPart::IntermediaryResponseHeaders),
            'E' => Some(AuditLogPart::IntermediaryResponseBody),
            'F' => Some(AuditLogPart::ResponseHeaders),
            'G' => Some(AuditLogPart::ResponseBody),
            'H' => Some(AuditLogPart::Trailer),
            'I' => Some(AuditLogPart::RequestBodyAlternative),
            'J' => Some(AuditLogPart::UploadedFiles),
            'K' => Some(AuditLogPart::RulesMatched),
            'Z' => Some(AuditLogPart::EndMarker),
            _ => None,
        }
    }

    /// Returns true if this part is mandatory (A or Z).
    pub const fn is_mandatory(&self) -> bool {
        matches!(self, AuditLogPart::Header | AuditLogPart::EndMarker)
    }
}

impl fmt::Display for AuditLogPart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_char())
    }
}

/// Error type for invalid audit log part parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseAuditLogPartError {
    input: char,
}

impl fmt::Display for ParseAuditLogPartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid audit log part: {}", self.input)
    }
}

impl std::error::Error for ParseAuditLogPartError {}

impl TryFrom<char> for AuditLogPart {
    type Error = ParseAuditLogPartError;

    fn try_from(c: char) -> Result<Self, Self::Error> {
        Self::from_char(c).ok_or(ParseAuditLogPartError { input: c })
    }
}

/// A collection of audit log parts.
///
/// This type represents the configured parts of an audit log entry.
/// Parts A (header) and Z (end marker) are always mandatory and implicitly included.
pub type AuditLogParts = Vec<AuditLogPart>;

/// Canonical ordering for audit log parts (B through K, excluding mandatory A and Z).
const ORDERED_AUDIT_LOG_PARTS: &[AuditLogPart] = &[
    AuditLogPart::RequestHeaders,              // B
    AuditLogPart::RequestBody,                 // C
    AuditLogPart::IntermediaryResponseHeaders, // D
    AuditLogPart::IntermediaryResponseBody,    // E
    AuditLogPart::ResponseHeaders,             // F
    AuditLogPart::ResponseBody,                // G
    AuditLogPart::Trailer,                     // H
    AuditLogPart::RequestBodyAlternative,      // I
    AuditLogPart::UploadedFiles,               // J
    AuditLogPart::RulesMatched,                // K
];

/// Error type for invalid audit log parts string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseAuditLogPartsError {
    message: String,
}

impl fmt::Display for ParseAuditLogPartsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ParseAuditLogPartsError {}

/// Parses audit log parts from a string (e.g., "ABCDEFGHIJKZ").
///
/// The string must start with 'A' and end with 'Z' (mandatory parts).
/// All characters between A and Z must be valid audit log part identifiers (B-K).
///
/// # Examples
///
/// ```
/// use coraza::types::{parse_audit_log_parts, AuditLogPart};
///
/// let parts = parse_audit_log_parts("ABCDEFGHIJKZ").unwrap();
/// assert_eq!(parts.len(), 12);
/// assert_eq!(parts[0], AuditLogPart::Header);
/// assert_eq!(parts[11], AuditLogPart::EndMarker);
///
/// assert!(parse_audit_log_parts("").is_err());  // Empty
/// assert!(parse_audit_log_parts("DEFGHZ").is_err());  // Missing A
/// assert!(parse_audit_log_parts("ABCD").is_err());  // Missing Z
/// assert!(parse_audit_log_parts("AMZ").is_err());  // Invalid middle part 'M'
/// ```
pub fn parse_audit_log_parts(opts: &str) -> Result<AuditLogParts, ParseAuditLogPartsError> {
    if !opts.starts_with('A') {
        return Err(ParseAuditLogPartsError {
            message: "audit log parts is required to start with A".to_string(),
        });
    }

    if !opts.ends_with('Z') {
        return Err(ParseAuditLogPartsError {
            message: "audit log parts is required to end with Z".to_string(),
        });
    }

    // Validate the middle parts (everything between A and Z)
    let middle_parts = &opts[1..opts.len() - 1];
    for p in middle_parts.chars() {
        let part = AuditLogPart::from_char(p).ok_or_else(|| ParseAuditLogPartsError {
            message: format!("invalid audit log parts {:?}", opts),
        })?;

        // Ensure it's one of the valid middle parts (B-K, not A or Z)
        if !ORDERED_AUDIT_LOG_PARTS.contains(&part) {
            return Err(ParseAuditLogPartsError {
                message: format!("invalid audit log parts {:?}", opts),
            });
        }
    }

    // Convert the string to a Vec<AuditLogPart>
    opts.chars()
        .map(|c| {
            AuditLogPart::from_char(c).ok_or_else(|| ParseAuditLogPartsError {
                message: format!("invalid audit log parts {:?}", opts),
            })
        })
        .collect()
}

/// Applies audit log parts modifications to base parts.
///
/// This function supports three modes:
/// - Addition: prefix with '+' (e.g., "+E" adds part E)
/// - Removal: prefix with '-' (e.g., "-E" removes part E)
/// - Absolute: no prefix (e.g., "ABCDEFZ" sets exact parts)
///
/// Parts A and Z are mandatory and cannot be added or removed via modifications.
/// Results are returned in canonical order (BCDEFGHIJK).
///
/// # Examples
///
/// ```
/// use coraza::types::{apply_audit_log_parts, AuditLogPart};
///
/// // Addition
/// let base = vec![AuditLogPart::RequestHeaders, AuditLogPart::RequestBody];
/// let result = apply_audit_log_parts(&base, "+E").unwrap();
/// assert_eq!(result.len(), 3);
///
/// // Removal
/// let base = vec![AuditLogPart::RequestHeaders, AuditLogPart::RequestBody,
///                 AuditLogPart::IntermediaryResponseBody];
/// let result = apply_audit_log_parts(&base, "-E").unwrap();
/// assert_eq!(result.len(), 2);
///
/// // Absolute value
/// let base = vec![AuditLogPart::RequestHeaders];
/// let result = apply_audit_log_parts(&base, "ABCDEFZ").unwrap();
/// assert_eq!(result.len(), 7);
///
/// // Cannot add/remove mandatory parts
/// assert!(apply_audit_log_parts(&base, "+A").is_err());
/// assert!(apply_audit_log_parts(&base, "-Z").is_err());
/// ```
pub fn apply_audit_log_parts(
    base: &[AuditLogPart],
    modification: &str,
) -> Result<AuditLogParts, ParseAuditLogPartsError> {
    if modification.is_empty() {
        return Err(ParseAuditLogPartsError {
            message: "modification string cannot be empty".to_string(),
        });
    }

    // Check if this is a modification (starts with + or -)
    let first_char = modification.chars().next().unwrap();
    if first_char != '+' && first_char != '-' {
        // This is an absolute value, parse it directly
        return parse_audit_log_parts(modification);
    }

    let is_addition = first_char == '+';
    let parts_to_modify = &modification[1..];

    // Validate all parts to modify
    for p in parts_to_modify.chars() {
        // Parts A and Z are mandatory and cannot be added or removed
        if p == 'A' || p == 'Z' {
            return Err(ParseAuditLogPartsError {
                message: "audit log parts A and Z are mandatory and cannot be modified".to_string(),
            });
        }

        let part = AuditLogPart::from_char(p).ok_or_else(|| ParseAuditLogPartsError {
            message: format!("invalid audit log part {:?}", p),
        })?;

        if !ORDERED_AUDIT_LOG_PARTS.contains(&part) {
            return Err(ParseAuditLogPartsError {
                message: format!("invalid audit log part {:?}", p),
            });
        }
    }

    // Create a set of current parts for efficient lookup
    use std::collections::HashSet;
    let mut parts_set: HashSet<AuditLogPart> = base.iter().copied().collect();

    if is_addition {
        // Add new parts
        for p in parts_to_modify.chars() {
            if let Some(part) = AuditLogPart::from_char(p) {
                parts_set.insert(part);
            }
        }
    } else {
        // Remove parts
        for p in parts_to_modify.chars() {
            if let Some(part) = AuditLogPart::from_char(p) {
                parts_set.remove(&part);
            }
        }
    }

    // Convert set back to vec, maintaining the canonical order
    let mut result = Vec::new();
    for part in ORDERED_AUDIT_LOG_PARTS {
        if parts_set.contains(part) {
            result.push(*part);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_engine_status_as_str() {
        assert_eq!(AuditEngineStatus::On.as_str(), "On");
        assert_eq!(AuditEngineStatus::Off.as_str(), "Off");
        assert_eq!(AuditEngineStatus::RelevantOnly.as_str(), "RelevantOnly");
    }

    #[test]
    fn test_audit_engine_status_display() {
        assert_eq!(format!("{}", AuditEngineStatus::On), "On");
        assert_eq!(format!("{}", AuditEngineStatus::Off), "Off");
        assert_eq!(
            format!("{}", AuditEngineStatus::RelevantOnly),
            "RelevantOnly"
        );
    }

    #[test]
    fn test_audit_engine_status_parse() {
        assert_eq!(
            "on".parse::<AuditEngineStatus>().unwrap(),
            AuditEngineStatus::On
        );
        assert_eq!(
            "OFF".parse::<AuditEngineStatus>().unwrap(),
            AuditEngineStatus::Off
        );
        assert_eq!(
            "RelevantOnly".parse::<AuditEngineStatus>().unwrap(),
            AuditEngineStatus::RelevantOnly
        );
        assert_eq!(
            "relevantonly".parse::<AuditEngineStatus>().unwrap(),
            AuditEngineStatus::RelevantOnly
        );
    }

    #[test]
    fn test_audit_engine_status_parse_invalid() {
        assert!("invalid".parse::<AuditEngineStatus>().is_err());
        assert!("".parse::<AuditEngineStatus>().is_err());
    }

    #[test]
    fn test_rule_engine_status_as_str() {
        assert_eq!(RuleEngineStatus::On.as_str(), "On");
        assert_eq!(RuleEngineStatus::DetectionOnly.as_str(), "DetectionOnly");
        assert_eq!(RuleEngineStatus::Off.as_str(), "Off");
    }

    #[test]
    fn test_rule_engine_status_display() {
        assert_eq!(format!("{}", RuleEngineStatus::On), "On");
        assert_eq!(
            format!("{}", RuleEngineStatus::DetectionOnly),
            "DetectionOnly"
        );
        assert_eq!(format!("{}", RuleEngineStatus::Off), "Off");
    }

    #[test]
    fn test_rule_engine_status_parse() {
        assert_eq!(
            "on".parse::<RuleEngineStatus>().unwrap(),
            RuleEngineStatus::On
        );
        assert_eq!(
            "DetectionOnly".parse::<RuleEngineStatus>().unwrap(),
            RuleEngineStatus::DetectionOnly
        );
        assert_eq!(
            "detectiononly".parse::<RuleEngineStatus>().unwrap(),
            RuleEngineStatus::DetectionOnly
        );
        assert_eq!(
            "OFF".parse::<RuleEngineStatus>().unwrap(),
            RuleEngineStatus::Off
        );
    }

    #[test]
    fn test_rule_engine_status_parse_invalid() {
        assert!("invalid".parse::<RuleEngineStatus>().is_err());
        assert!("detection".parse::<RuleEngineStatus>().is_err());
    }

    #[test]
    fn test_body_limit_action_as_str() {
        assert_eq!(BodyLimitAction::ProcessPartial.as_str(), "ProcessPartial");
        assert_eq!(BodyLimitAction::Reject.as_str(), "Reject");
    }

    #[test]
    fn test_body_limit_action_as_u8() {
        assert_eq!(BodyLimitAction::ProcessPartial.as_u8(), 0);
        assert_eq!(BodyLimitAction::Reject.as_u8(), 1);
    }

    #[test]
    fn test_body_limit_action_display() {
        assert_eq!(
            format!("{}", BodyLimitAction::ProcessPartial),
            "ProcessPartial"
        );
        assert_eq!(format!("{}", BodyLimitAction::Reject), "Reject");
    }

    #[test]
    fn test_audit_log_part_as_char() {
        assert_eq!(AuditLogPart::Header.as_char(), 'A');
        assert_eq!(AuditLogPart::RequestHeaders.as_char(), 'B');
        assert_eq!(AuditLogPart::RequestBody.as_char(), 'C');
        assert_eq!(AuditLogPart::ResponseHeaders.as_char(), 'F');
        assert_eq!(AuditLogPart::RulesMatched.as_char(), 'K');
        assert_eq!(AuditLogPart::EndMarker.as_char(), 'Z');
    }

    #[test]
    fn test_audit_log_part_from_char() {
        assert_eq!(AuditLogPart::from_char('A'), Some(AuditLogPart::Header));
        assert_eq!(
            AuditLogPart::from_char('B'),
            Some(AuditLogPart::RequestHeaders)
        );
        assert_eq!(AuditLogPart::from_char('Z'), Some(AuditLogPart::EndMarker));
        assert_eq!(AuditLogPart::from_char('X'), None);
        assert_eq!(AuditLogPart::from_char('a'), None); // Case sensitive
    }

    #[test]
    fn test_audit_log_part_try_from() {
        assert_eq!(AuditLogPart::try_from('A').unwrap(), AuditLogPart::Header);
        assert_eq!(
            AuditLogPart::try_from('K').unwrap(),
            AuditLogPart::RulesMatched
        );
        assert!(AuditLogPart::try_from('X').is_err());
    }

    #[test]
    fn test_audit_log_part_is_mandatory() {
        assert!(AuditLogPart::Header.is_mandatory());
        assert!(AuditLogPart::EndMarker.is_mandatory());
        assert!(!AuditLogPart::RequestHeaders.is_mandatory());
        assert!(!AuditLogPart::RequestBody.is_mandatory());
        assert!(!AuditLogPart::RulesMatched.is_mandatory());
    }

    #[test]
    fn test_audit_log_part_display() {
        assert_eq!(format!("{}", AuditLogPart::Header), "A");
        assert_eq!(format!("{}", AuditLogPart::RequestHeaders), "B");
        assert_eq!(format!("{}", AuditLogPart::EndMarker), "Z");
    }

    #[test]
    fn test_audit_log_part_roundtrip() {
        let parts = [
            AuditLogPart::Header,
            AuditLogPart::RequestHeaders,
            AuditLogPart::RequestBody,
            AuditLogPart::IntermediaryResponseHeaders,
            AuditLogPart::IntermediaryResponseBody,
            AuditLogPart::ResponseHeaders,
            AuditLogPart::ResponseBody,
            AuditLogPart::Trailer,
            AuditLogPart::RequestBodyAlternative,
            AuditLogPart::UploadedFiles,
            AuditLogPart::RulesMatched,
            AuditLogPart::EndMarker,
        ];

        for part in &parts {
            let c = part.as_char();
            let parsed = AuditLogPart::from_char(c).unwrap();
            assert_eq!(parsed, *part);
        }
    }

    #[test]
    fn test_parse_audit_log_parts_valid() {
        let parts = parse_audit_log_parts("ABCDEFGHIJKZ").unwrap();
        assert_eq!(parts.len(), 12);

        let expected: Vec<AuditLogPart> = "ABCDEFGHIJKZ"
            .chars()
            .map(|c| AuditLogPart::from_char(c).unwrap())
            .collect();

        for (i, part) in expected.iter().enumerate() {
            assert_eq!(&parts[i], part);
        }
    }

    #[test]
    fn test_parse_audit_log_parts_empty() {
        assert!(parse_audit_log_parts("").is_err());
    }

    #[test]
    fn test_parse_audit_log_parts_missing_a() {
        assert!(parse_audit_log_parts("DEFGHZ").is_err());
    }

    #[test]
    fn test_parse_audit_log_parts_missing_z() {
        assert!(parse_audit_log_parts("ABCD").is_err());
    }

    #[test]
    fn test_parse_audit_log_parts_invalid_middle() {
        assert!(parse_audit_log_parts("AMZ").is_err());
    }

    #[test]
    fn test_apply_audit_log_parts_add_single() {
        let base = vec![AuditLogPart::RequestHeaders, AuditLogPart::RequestBody];
        let result = apply_audit_log_parts(&base, "+E").unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], AuditLogPart::RequestHeaders);
        assert_eq!(result[1], AuditLogPart::RequestBody);
        assert_eq!(result[2], AuditLogPart::IntermediaryResponseBody);
    }

    #[test]
    fn test_apply_audit_log_parts_add_multiple() {
        let base = vec![AuditLogPart::RequestHeaders, AuditLogPart::RequestBody];
        let result = apply_audit_log_parts(&base, "+EFG").unwrap();
        assert_eq!(result.len(), 5);
        assert_eq!(result[0], AuditLogPart::RequestHeaders);
        assert_eq!(result[1], AuditLogPart::RequestBody);
        assert_eq!(result[2], AuditLogPart::IntermediaryResponseBody);
        assert_eq!(result[3], AuditLogPart::ResponseHeaders);
        assert_eq!(result[4], AuditLogPart::ResponseBody);
    }

    #[test]
    fn test_apply_audit_log_parts_add_existing() {
        let base = vec![
            AuditLogPart::RequestHeaders,
            AuditLogPart::RequestBody,
            AuditLogPart::IntermediaryResponseBody,
        ];
        let result = apply_audit_log_parts(&base, "+E").unwrap();
        // Should not add duplicate
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], AuditLogPart::RequestHeaders);
        assert_eq!(result[1], AuditLogPart::RequestBody);
        assert_eq!(result[2], AuditLogPart::IntermediaryResponseBody);
    }

    #[test]
    fn test_apply_audit_log_parts_remove_single() {
        let base = vec![
            AuditLogPart::RequestHeaders,
            AuditLogPart::RequestBody,
            AuditLogPart::IntermediaryResponseBody,
            AuditLogPart::ResponseHeaders,
            AuditLogPart::ResponseBody,
        ];
        let result = apply_audit_log_parts(&base, "-E").unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], AuditLogPart::RequestHeaders);
        assert_eq!(result[1], AuditLogPart::RequestBody);
        assert_eq!(result[2], AuditLogPart::ResponseHeaders);
        assert_eq!(result[3], AuditLogPart::ResponseBody);
    }

    #[test]
    fn test_apply_audit_log_parts_remove_multiple() {
        let base = vec![
            AuditLogPart::RequestHeaders,
            AuditLogPart::RequestBody,
            AuditLogPart::IntermediaryResponseBody,
            AuditLogPart::ResponseHeaders,
            AuditLogPart::ResponseBody,
        ];
        let result = apply_audit_log_parts(&base, "-EF").unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], AuditLogPart::RequestHeaders);
        assert_eq!(result[1], AuditLogPart::RequestBody);
        assert_eq!(result[2], AuditLogPart::ResponseBody);
    }

    #[test]
    fn test_apply_audit_log_parts_remove_non_existing() {
        let base = vec![AuditLogPart::RequestHeaders, AuditLogPart::RequestBody];
        let result = apply_audit_log_parts(&base, "-E").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], AuditLogPart::RequestHeaders);
        assert_eq!(result[1], AuditLogPart::RequestBody);
    }

    #[test]
    fn test_apply_audit_log_parts_absolute_value() {
        let base = vec![AuditLogPart::RequestHeaders, AuditLogPart::RequestBody];
        let result = apply_audit_log_parts(&base, "ABCDEFZ").unwrap();
        assert_eq!(result.len(), 7);
        assert_eq!(result[0], AuditLogPart::Header);
        assert_eq!(result[1], AuditLogPart::RequestHeaders);
        assert_eq!(result[2], AuditLogPart::RequestBody);
        assert_eq!(result[3], AuditLogPart::IntermediaryResponseHeaders);
        assert_eq!(result[4], AuditLogPart::IntermediaryResponseBody);
        assert_eq!(result[5], AuditLogPart::ResponseHeaders);
        assert_eq!(result[6], AuditLogPart::EndMarker);
    }

    #[test]
    fn test_apply_audit_log_parts_empty_modification() {
        let base = vec![AuditLogPart::RequestHeaders, AuditLogPart::RequestBody];
        assert!(apply_audit_log_parts(&base, "").is_err());
    }

    #[test]
    fn test_apply_audit_log_parts_invalid_add() {
        let base = vec![AuditLogPart::RequestHeaders, AuditLogPart::RequestBody];
        assert!(apply_audit_log_parts(&base, "+X").is_err());
    }

    #[test]
    fn test_apply_audit_log_parts_invalid_remove() {
        let base = vec![AuditLogPart::RequestHeaders, AuditLogPart::RequestBody];
        assert!(apply_audit_log_parts(&base, "-X").is_err());
    }

    #[test]
    fn test_apply_audit_log_parts_maintain_order() {
        let base = vec![AuditLogPart::RequestHeaders, AuditLogPart::ResponseHeaders];
        let result = apply_audit_log_parts(&base, "+E").unwrap();
        assert_eq!(result.len(), 3);
        // E should be inserted between B and F
        assert_eq!(result[0], AuditLogPart::RequestHeaders); // B
        assert_eq!(result[1], AuditLogPart::IntermediaryResponseBody); // E
        assert_eq!(result[2], AuditLogPart::ResponseHeaders); // F
    }

    #[test]
    fn test_apply_audit_log_parts_add_all_to_empty() {
        let base: Vec<AuditLogPart> = vec![];
        let result = apply_audit_log_parts(&base, "+BCDEFGHIJK").unwrap();
        assert_eq!(result.len(), 10);
        assert_eq!(result[0], AuditLogPart::RequestHeaders);
        assert_eq!(result[9], AuditLogPart::RulesMatched);
    }

    #[test]
    fn test_apply_audit_log_parts_remove_all() {
        let base = vec![AuditLogPart::RequestHeaders, AuditLogPart::RequestBody];
        let result = apply_audit_log_parts(&base, "-BC").unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_apply_audit_log_parts_cannot_add_a() {
        let base = vec![AuditLogPart::RequestHeaders, AuditLogPart::RequestBody];
        assert!(apply_audit_log_parts(&base, "+A").is_err());
    }

    #[test]
    fn test_apply_audit_log_parts_cannot_add_z() {
        let base = vec![AuditLogPart::RequestHeaders, AuditLogPart::RequestBody];
        assert!(apply_audit_log_parts(&base, "+Z").is_err());
    }

    #[test]
    fn test_apply_audit_log_parts_cannot_remove_a() {
        let base = vec![AuditLogPart::RequestHeaders, AuditLogPart::RequestBody];
        assert!(apply_audit_log_parts(&base, "-A").is_err());
    }

    #[test]
    fn test_apply_audit_log_parts_cannot_remove_z() {
        let base = vec![AuditLogPart::RequestHeaders, AuditLogPart::RequestBody];
        assert!(apply_audit_log_parts(&base, "-Z").is_err());
    }
}
