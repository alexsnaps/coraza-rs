// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! SecLang parser implementation.
//!
//! This module implements the core parser for ModSecurity SecLang directives.
//! The parser uses a simple line-by-line approach (not a full grammar parser):
//!
//! 1. Read lines with continuation (`\`) support
//! 2. Skip comments (`#`)
//! 3. Handle multi-line backtick blocks
//! 4. Extract directive name and options
//! 5. Dispatch to directive handler

use std::collections::HashMap;
use std::path::Path;

/// Maximum include recursion depth to prevent DoS attacks
const MAX_INCLUDE_RECURSION: usize = 100;

/// Parser error type
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
    pub line: usize,
    pub file: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.file, self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

impl ParseError {
    fn new(message: String, line: usize, file: String) -> Self {
        Self {
            message,
            line,
            file,
        }
    }
}

type ParseResult<T> = Result<T, ParseError>;

/// Directive handler function type
///
/// Each directive is implemented as a function that takes DirectiveOptions
/// and modifies WAF state accordingly.
type DirectiveFn = fn(&mut DirectiveOptions) -> ParseResult<()>;

/// Options passed to directive handlers
///
/// Contains parser state and the directive's arguments.
pub struct DirectiveOptions {
    /// Raw directive line (for error reporting)
    pub raw: String,

    /// Directive options/arguments (everything after directive name)
    pub opts: String,

    /// Current parser state
    pub parser_state: ParserState,
    // TODO: Reference to WAF instance (will be added when WAF module exists)
    // For now, we'll use a placeholder
}

/// Parser configuration and state
#[derive(Debug, Clone, Default)]
pub struct ParserState {
    /// Current line number
    pub current_line: usize,

    /// Current file being parsed
    pub current_file: String,

    /// Current directory (for resolving relative includes)
    pub current_dir: String,
}

/// SecLang parser
///
/// Parses ModSecurity SecLang directives and compiles them into executable rules.
///
/// # Example
///
/// ```
/// use coraza::seclang::Parser;
///
/// let mut parser = Parser::new();
///
/// // Parse directives from string
/// parser.from_string("SecRuleEngine On")?;
///
/// // Parse from file (when implemented)
/// // parser.from_file("rules.conf")?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct Parser {
    /// Current parser state
    state: ParserState,

    /// Include recursion counter (prevents DoS)
    include_count: usize,

    /// Directive registry (directive name -> handler function)
    directives: HashMap<String, DirectiveFn>,
}

impl Parser {
    /// Create a new parser
    pub fn new() -> Self {
        let mut parser = Self {
            state: ParserState::default(),
            include_count: 0,
            directives: HashMap::new(),
        };

        // Register built-in directives
        parser.register_directives();

        parser
    }

    /// Register all built-in directives
    fn register_directives(&mut self) {
        // TODO: Register actual directives
        // For now, just register a test directive
        self.directives
            .insert("secruleengine".to_string(), directive_sec_rule_engine);
    }

    /// Parse directives from a string
    ///
    /// # Arguments
    ///
    /// * `data` - SecLang directive text
    ///
    /// # Returns
    ///
    /// Ok(()) if all directives parsed successfully, Err otherwise
    ///
    /// # Example
    ///
    /// ```
    /// use coraza::seclang::Parser;
    ///
    /// let mut parser = Parser::new();
    /// parser.from_string("SecRuleEngine On")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_string(&mut self, data: &str) -> ParseResult<()> {
        let old_file = self.state.current_file.clone();
        self.state.current_file = "_inline_".to_string();
        let result = self.parse_string(data);
        self.state.current_file = old_file;
        result
    }

    /// Parse directives from a file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to SecLang configuration file
    ///
    /// # Returns
    ///
    /// Ok(()) if file parsed successfully, Err otherwise
    ///
    /// # Note
    ///
    /// Supports glob patterns like `/path/to/rules/*.conf`
    pub fn from_file<P: AsRef<Path>>(&mut self, path: P) -> ParseResult<()> {
        let path_str = path.as_ref().to_string_lossy().to_string();

        // TODO: Implement file reading with glob support
        // For now, return error
        Err(ParseError::new(
            format!("from_file not yet implemented: {}", path_str),
            self.state.current_line,
            self.state.current_file.clone(),
        ))
    }

    /// Internal string parsing implementation
    ///
    /// Handles:
    /// - Line continuations (`\` at end of line)
    /// - Comments (`#` at start of line)
    /// - Multi-line backtick blocks (for SecDataset)
    /// - Directive dispatch
    fn parse_string(&mut self, data: &str) -> ParseResult<()> {
        let mut line_buffer = String::new();
        let mut in_backticks = false;

        for line in data.lines() {
            self.state.current_line += 1;
            let trimmed = line.trim();

            // Skip empty lines
            if trimmed.is_empty() {
                continue;
            }

            // Skip comments (lines starting with #)
            if trimmed.starts_with('#') {
                continue;
            }

            // Handle backtick blocks (multi-line for SecDataset)
            // Line ending with ` starts a block, line starting with ` ends it
            if !in_backticks && trimmed.ends_with('`') {
                in_backticks = true;
            } else if in_backticks && trimmed.starts_with('`') {
                in_backticks = false;
            }

            if in_backticks {
                line_buffer.push_str(trimmed);
                line_buffer.push('\n');
                continue;
            }

            // Handle line continuation (\ at end)
            if trimmed.ends_with('\\') {
                // Remove the trailing backslash and continue accumulating
                line_buffer.push_str(trimmed.trim_end_matches('\\'));
            } else {
                // Complete line - process it
                line_buffer.push_str(trimmed);
                self.evaluate_line(&line_buffer)?;
                line_buffer.clear();
            }
        }

        // Check for unclosed backtick blocks
        if in_backticks {
            return Err(ParseError::new(
                "backticks left open".to_string(),
                self.state.current_line,
                self.state.current_file.clone(),
            ));
        }

        Ok(())
    }

    /// Evaluate a single complete directive line
    ///
    /// Extracts directive name and options, then dispatches to handler.
    fn evaluate_line(&mut self, line: &str) -> ParseResult<()> {
        if line.is_empty() || line.starts_with('#') {
            // This shouldn't happen as we filter these in parse_string
            panic!("invalid line passed to evaluate_line");
        }

        // Extract directive name and options
        // Format: "DirectiveName options..."
        let (directive_name, mut opts) = match line.split_once(' ') {
            Some((name, rest)) => (name, rest.to_string()),
            None => (line, String::new()),
        };

        // Convert directive name to lowercase (case-insensitive)
        let directive_lower = directive_name.to_lowercase();

        // Remove surrounding quotes if present
        if opts.len() >= 2 && opts.starts_with('"') && opts.ends_with('"') {
            opts = opts[1..opts.len() - 1].to_string();
        }

        // Special case: Include directive (handled separately due to recursion)
        if directive_lower == "include" {
            if self.include_count >= MAX_INCLUDE_RECURSION {
                return Err(ParseError::new(
                    format!("cannot include more than {} files", MAX_INCLUDE_RECURSION),
                    self.state.current_line,
                    self.state.current_file.clone(),
                ));
            }
            self.include_count += 1;
            return self.from_file(&opts);
        }

        // Look up directive handler
        let handler = self.directives.get(&directive_lower).copied();

        match handler {
            Some(func) => {
                // Call directive handler
                let mut options = DirectiveOptions {
                    raw: line.to_string(),
                    opts,
                    parser_state: self.state.clone(),
                };

                func(&mut options).map_err(|e| {
                    ParseError::new(
                        format!(
                            "failed to compile directive \"{}\": {}",
                            directive_name, e.message
                        ),
                        self.state.current_line,
                        self.state.current_file.clone(),
                    )
                })
            }
            None => Err(ParseError::new(
                format!("unknown directive \"{}\"", directive_name),
                self.state.current_line,
                self.state.current_file.clone(),
            )),
        }
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Placeholder Directive Implementations
// ============================================================================
// These are minimal implementations for testing. Full implementations will
// come in later steps.

fn directive_sec_rule_engine(options: &mut DirectiveOptions) -> ParseResult<()> {
    // Placeholder implementation
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecRuleEngine requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    // TODO: Actually set WAF rule engine status
    // For now, just validate the option
    match options.opts.to_lowercase().as_str() {
        "on" | "off" | "detectiononly" => Ok(()),
        _ => Err(ParseError::new(
            format!("invalid SecRuleEngine value: {}", options.opts),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_new() {
        let parser = Parser::new();
        assert_eq!(parser.state.current_line, 0);
        assert_eq!(parser.include_count, 0);
    }

    #[test]
    fn test_parse_empty_string() {
        let mut parser = Parser::new();
        assert!(parser.from_string("").is_ok());
    }

    #[test]
    fn test_parse_comment_only() {
        let mut parser = Parser::new();
        assert!(parser.from_string("# This is a comment").is_ok());
    }

    #[test]
    fn test_parse_multiple_comments() {
        let mut parser = Parser::new();
        let input = r#"
# Comment 1
# Comment 2
  # Indented comment
"#;
        assert!(parser.from_string(input).is_ok());
    }

    #[test]
    fn test_parse_directive_case_insensitive() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecRuleEngine On").is_ok());
        assert!(parser.from_string("secruleengine On").is_ok());
        assert!(parser.from_string("SECRULEENGINE On").is_ok());
        assert!(parser.from_string("sEcRuLeEnGiNe On").is_ok());
    }

    #[test]
    fn test_parse_unknown_directive() {
        let mut parser = Parser::new();
        let result = parser.from_string("UnknownDirective foo");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("unknown directive"));
        assert!(err.message.contains("UnknownDirective"));
    }

    #[test]
    fn test_parse_line_continuation() {
        let mut parser = Parser::new();
        let input = r#"
SecRuleEngine \
On
"#;
        assert!(parser.from_string(input).is_ok());
    }

    #[test]
    fn test_parse_multiple_line_continuations() {
        let mut parser = Parser::new();
        let input = r#"
SecRuleEngine \
\
\
On
"#;
        assert!(parser.from_string(input).is_ok());
    }

    #[test]
    fn test_parse_backticks_unclosed() {
        let mut parser = Parser::new();
        let input = "SecDataset test `";
        let result = parser.from_string(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("backticks left open"));
    }

    #[test]
    fn test_parse_directive_with_quotes() {
        let mut parser = Parser::new();
        // Quotes around options should be removed
        assert!(parser.from_string("SecRuleEngine \"On\"").is_ok());
    }

    #[test]
    fn test_sec_rule_engine_valid_values() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecRuleEngine On").is_ok());
        assert!(parser.from_string("SecRuleEngine Off").is_ok());
        assert!(parser.from_string("SecRuleEngine DetectionOnly").is_ok());
    }

    #[test]
    fn test_sec_rule_engine_invalid_value() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecRuleEngine Invalid");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("invalid SecRuleEngine value"));
    }

    #[test]
    fn test_sec_rule_engine_no_argument() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecRuleEngine");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("requires an argument"));
    }

    #[test]
    fn test_parse_error_includes_line_number() {
        let mut parser = Parser::new();
        let input = r#"
# Line 1 (comment)
SecRuleEngine On
UnknownDirective
"#;
        let result = parser.from_string(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.line, 4); // Comment is line 2, SecRuleEngine is line 3, Unknown is line 4
    }
}
