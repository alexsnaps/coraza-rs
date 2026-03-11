// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Multipart/form-data parser (RFC 7578).
//!
//! A standalone, synchronous parser for multipart/form-data bodies.
//! This implementation follows the Go stdlib mime/multipart closely
//! for maximum compatibility.

use std::collections::HashMap;

/// Errors that can occur during multipart parsing
#[derive(Debug)]
#[allow(dead_code)] // Some variants reserved for future use
pub enum ParseError {
    /// Invalid boundary format
    InvalidBoundary(String),

    /// Malformed part headers
    MalformedHeaders(String),

    /// Unexpected EOF while reading
    UnexpectedEof,

    /// Generic parsing error
    Parse(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::InvalidBoundary(msg) => write!(f, "invalid boundary: {}", msg),
            ParseError::MalformedHeaders(msg) => write!(f, "malformed headers: {}", msg),
            ParseError::UnexpectedEof => write!(f, "unexpected EOF"),
            ParseError::Parse(msg) => write!(f, "parse error: {}", msg),
        }
    }
}

impl std::error::Error for ParseError {}

/// A single part in a multipart message
#[derive(Debug, Clone)]
pub struct Part {
    /// Form field name (from Content-Disposition name parameter)
    pub name: String,

    /// Filename (from Content-Disposition filename parameter), if this is a file upload
    pub filename: Option<String>,

    /// Content-Type of this part, if specified
    pub content_type: Option<String>,

    /// All headers as key-value pairs (reserved for future use)
    #[allow(dead_code)]
    pub headers: HashMap<String, Vec<String>>,

    /// The part body data
    pub data: Vec<u8>,
}

/// Multipart parser for RFC 7578 multipart/form-data
pub struct MultipartParser {
    boundary: Vec<u8>,
    data: Vec<u8>,
}

impl MultipartParser {
    /// Create a new multipart parser
    ///
    /// # Arguments
    ///
    /// * `boundary` - The boundary string (without leading dashes)
    /// * `data` - The complete multipart body
    pub fn new(boundary: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            boundary: boundary.into().into_bytes(),
            data,
        }
    }

    /// Parse all parts from the multipart body
    ///
    /// Returns a vector of parsed parts, or an error if parsing fails.
    pub fn parse(&self) -> Result<Vec<Part>, ParseError> {
        let mut parts = Vec::new();

        // Build boundary markers
        // Initial boundary: --{boundary}
        // Subsequent boundaries: \r\n--{boundary} or \n--{boundary}
        // Final boundary: --{boundary}--
        let mut boundary_marker = b"--".to_vec();
        boundary_marker.extend_from_slice(&self.boundary);

        let mut final_marker = boundary_marker.clone();
        final_marker.extend_from_slice(b"--");

        // Look for first boundary (may have leading data before it)
        let mut pos = if let Some(first_boundary) = find_subsequence(&self.data, &boundary_marker) {
            let after_boundary = first_boundary + boundary_marker.len();
            // Skip line ending after first boundary
            skip_line_ending(&self.data, after_boundary)
        } else {
            return Err(ParseError::Parse("no boundary found".to_string()));
        };

        // Parse each part
        while let Some(p) = find_next_boundary(&self.data[pos..], &boundary_marker) {
            let next_boundary_pos = pos + p;

            // Extract part data (from current pos to boundary)
            let part_data = &self.data[pos..next_boundary_pos];

            // Parse this part (propagate errors)
            let part = parse_part(part_data)?;
            parts.push(part);

            // Move past the boundary
            pos = next_boundary_pos + boundary_marker.len();

            // Check if this is the final boundary (ends with --)
            if self.data.len() >= pos + 2 && &self.data[pos..pos + 2] == b"--" {
                // Final boundary found
                break;
            }

            // Skip line ending after boundary
            pos = skip_line_ending(&self.data, pos);
        }

        Ok(parts)
    }
}

/// Parse a single part (headers + body)
fn parse_part(data: &[u8]) -> Result<Part, ParseError> {
    // Find the blank line that separates headers from body
    let (header_end, separator_len) = find_header_end(data)
        .ok_or_else(|| ParseError::MalformedHeaders("no blank line after headers".to_string()))?;

    // Split headers and body
    let header_data = &data[..header_end];
    let body_start = header_end + separator_len;

    // Body continues until end of part data, but we need to trim trailing CRLF
    let mut body_data = &data[body_start..];

    // Trim trailing line endings (multipart boundaries include leading CRLF)
    while body_data.ends_with(b"\r\n") || body_data.ends_with(b"\n") {
        if body_data.ends_with(b"\r\n") {
            body_data = &body_data[..body_data.len() - 2];
        } else {
            body_data = &body_data[..body_data.len() - 1];
        }
    }

    // Parse headers
    let headers = parse_headers(header_data)?;

    // Extract name and filename from Content-Disposition
    let (name, filename) = extract_content_disposition(&headers)?;

    // Extract Content-Type
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.first())
        .map(|s| s.to_string());

    Ok(Part {
        name,
        filename,
        content_type,
        headers,
        data: body_data.to_vec(),
    })
}

/// Parse headers from header data
fn parse_headers(data: &[u8]) -> Result<HashMap<String, Vec<String>>, ParseError> {
    let mut headers = HashMap::new();
    let header_str = String::from_utf8_lossy(data);

    for line in header_str.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Parse "Key: Value"
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_lowercase();
            let value = line[colon_pos + 1..].trim().to_string();

            headers.entry(key).or_insert_with(Vec::new).push(value);
        }
    }

    Ok(headers)
}

/// Extract name and filename from Content-Disposition header
///
/// Example: `form-data; name="field"; filename="file.txt"`
fn extract_content_disposition(
    headers: &HashMap<String, Vec<String>>,
) -> Result<(String, Option<String>), ParseError> {
    let disposition = headers
        .get("content-disposition")
        .and_then(|v| v.first())
        .ok_or_else(|| ParseError::MalformedHeaders("missing Content-Disposition".to_string()))?;

    // Parse parameters from Content-Disposition
    let params = parse_header_params(disposition);

    let name = params
        .get("name")
        .ok_or_else(|| {
            ParseError::MalformedHeaders("missing name in Content-Disposition".to_string())
        })?
        .clone();

    let filename = params.get("filename").cloned();

    Ok((name, filename))
}

/// Parse header parameters like: `form-data; name="value"; filename="file.txt"`
///
/// Returns a map of parameter names to values (with quotes removed)
fn parse_header_params(header: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();

    for part in header.split(';') {
        let part = part.trim();

        if let Some(eq_pos) = part.find('=') {
            let key = part[..eq_pos].trim().to_lowercase();
            let mut value = part[eq_pos + 1..].trim().to_string();

            // Remove surrounding quotes
            if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
                value = value[1..value.len() - 1].to_string();
            }

            params.insert(key, value);
        }
    }

    params
}

/// Find the end of headers (blank line)
///
/// Returns a tuple of (position, separator_length), or None if not found
fn find_header_end(data: &[u8]) -> Option<(usize, usize)> {
    // Look for \r\n\r\n or \n\n
    if let Some(pos) = find_subsequence(data, b"\r\n\r\n") {
        return Some((pos, 4)); // 4 bytes for \r\n\r\n
    }
    if let Some(pos) = find_subsequence(data, b"\n\n") {
        return Some((pos, 2)); // 2 bytes for \n\n
    }
    None
}

/// Skip a line ending (CRLF or LF) at the given position
///
/// Returns the position after the line ending
fn skip_line_ending(data: &[u8], pos: usize) -> usize {
    if pos >= data.len() {
        return pos;
    }

    // Try CRLF first
    if pos + 1 < data.len() && &data[pos..pos + 2] == b"\r\n" {
        return pos + 2;
    }

    // Try LF
    if data[pos] == b'\n' {
        return pos + 1;
    }

    // No line ending
    pos
}

/// Find the next boundary in the data
///
/// Looks for \r\n--boundary or \n--boundary
fn find_next_boundary(data: &[u8], boundary: &[u8]) -> Option<usize> {
    // Build patterns to search for
    let mut crlf_boundary = b"\r\n".to_vec();
    crlf_boundary.extend_from_slice(boundary);

    let mut lf_boundary = b"\n".to_vec();
    lf_boundary.extend_from_slice(boundary);

    // Try CRLF variant first (more common)
    if let Some(pos) = find_subsequence(data, &crlf_boundary) {
        return Some(pos);
    }

    // Try LF variant
    if let Some(pos) = find_subsequence(data, &lf_boundary) {
        return Some(pos);
    }

    None
}

/// Find a subsequence in a byte slice
///
/// Returns the position of the first occurrence, or None
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }

    if haystack.len() < needle.len() {
        return None;
    }

    for i in 0..=(haystack.len() - needle.len()) {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_multipart() {
        let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"field\"\r\n\
\r\n\
value\r\n\
--boundary--";

        let parser = MultipartParser::new("boundary", body.to_vec());
        let parts = parser.parse().unwrap();

        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].name, "field");
        assert_eq!(parts[0].filename, None);
        assert_eq!(parts[0].data, b"value");
    }

    #[test]
    fn test_multipart_with_file() {
        let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n\
Content-Type: text/plain\r\n\
\r\n\
file content\r\n\
--boundary--";

        let parser = MultipartParser::new("boundary", body.to_vec());
        let parts = parser.parse().unwrap();

        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].name, "file");
        assert_eq!(parts[0].filename, Some("test.txt".to_string()));
        assert_eq!(parts[0].content_type, Some("text/plain".to_string()));
        assert_eq!(parts[0].data, b"file content");
    }

    #[test]
    fn test_multiple_parts() {
        let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"field1\"\r\n\
\r\n\
value1\r\n\
--boundary\r\n\
Content-Disposition: form-data; name=\"field2\"\r\n\
\r\n\
value2\r\n\
--boundary--";

        let parser = MultipartParser::new("boundary", body.to_vec());
        let parts = parser.parse().unwrap();

        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].name, "field1");
        assert_eq!(parts[0].data, b"value1");
        assert_eq!(parts[1].name, "field2");
        assert_eq!(parts[1].data, b"value2");
    }

    #[test]
    fn test_lf_line_endings() {
        let body = b"--boundary\n\
Content-Disposition: form-data; name=\"field\"\n\
\n\
value\n\
--boundary--";

        let parser = MultipartParser::new("boundary", body.to_vec());
        let parts = parser.parse().unwrap();

        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].name, "field");
        assert_eq!(parts[0].data, b"value");
    }

    #[test]
    fn test_empty_part() {
        let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"empty\"\r\n\
\r\n\
\r\n\
--boundary--";

        let parser = MultipartParser::new("boundary", body.to_vec());
        let parts = parser.parse().unwrap();

        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].name, "empty");
        assert_eq!(parts[0].data, b"");
    }

    #[test]
    fn test_no_boundary() {
        let body = b"some random data";

        let parser = MultipartParser::new("boundary", body.to_vec());
        let result = parser.parse();

        assert!(result.is_err());
    }

    #[test]
    fn test_malformed_content_disposition() {
        let body = b"--boundary\r\n\
Content-Type: text/plain\r\n\
\r\n\
value\r\n\
--boundary--";

        let parser = MultipartParser::new("boundary", body.to_vec());
        let result = parser.parse();

        // Should fail due to missing Content-Disposition
        assert!(result.is_err());
    }

    #[test]
    fn test_find_subsequence() {
        assert_eq!(find_subsequence(b"hello world", b"world"), Some(6));
        assert_eq!(find_subsequence(b"hello world", b"foo"), None);
        assert_eq!(find_subsequence(b"hello", b"hello world"), None);
        assert_eq!(find_subsequence(b"abc", b""), Some(0));
    }

    #[test]
    fn test_parse_header_params() {
        let header = "form-data; name=\"field\"; filename=\"file.txt\"";
        let params = parse_header_params(header);

        assert_eq!(params.get("name"), Some(&"field".to_string()));
        assert_eq!(params.get("filename"), Some(&"file.txt".to_string()));
    }

    #[test]
    fn test_complex_boundary() {
        let body = b"-----------------------------9051914041544843365972754266\r\n\
Content-Disposition: form-data; name=\"text\"\r\n\
\r\n\
text default\r\n\
-----------------------------9051914041544843365972754266\r\n\
Content-Disposition: form-data; name=\"file1\"; filename=\"a.txt\"\r\n\
Content-Type: text/plain\r\n\
\r\n\
Content of a.txt.\r\n\
-----------------------------9051914041544843365972754266--";

        let parser = MultipartParser::new(
            "---------------------------9051914041544843365972754266",
            body.to_vec(),
        );
        let parts = parser.parse().unwrap();

        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].name, "text");
        assert_eq!(parts[0].data, b"text default");
        assert_eq!(parts[1].name, "file1");
        assert_eq!(parts[1].filename, Some("a.txt".to_string()));
        assert_eq!(parts[1].data, b"Content of a.txt.");
    }
}
