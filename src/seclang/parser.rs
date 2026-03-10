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
use std::str::FromStr;

use crate::seclang::WafConfig;
use crate::types::{BodyLimitAction, RuleEngineStatus};

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
type DirectiveFn = fn(&mut DirectiveOptions<'_>) -> ParseResult<()>;

/// Options passed to directive handlers
///
/// Contains parser state and the directive's arguments.
pub struct DirectiveOptions<'a> {
    /// Raw directive line (for error reporting)
    pub raw: String,

    /// Directive options/arguments (everything after directive name)
    pub opts: String,

    /// Current parser state
    pub parser_state: ParserState,

    /// Mutable reference to WAF configuration
    pub waf_config: &'a mut WafConfig,
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
/// // Get the resulting WAF configuration
/// let config = parser.config();
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

    /// WAF configuration (populated by directives)
    waf_config: WafConfig,
}

impl Parser {
    /// Create a new parser
    pub fn new() -> Self {
        let mut parser = Self {
            state: ParserState::default(),
            include_count: 0,
            directives: HashMap::new(),
            waf_config: WafConfig::new(),
        };

        // Register built-in directives
        parser.register_directives();

        parser
    }

    /// Get reference to the WAF configuration
    pub fn config(&self) -> &WafConfig {
        &self.waf_config
    }

    /// Get mutable reference to the WAF configuration
    pub fn config_mut(&mut self) -> &mut WafConfig {
        &mut self.waf_config
    }

    /// Register all built-in directives
    fn register_directives(&mut self) {
        // Engine configuration directives
        self.directives
            .insert("secruleengine".to_string(), directive_sec_rule_engine);
        self.directives.insert(
            "secrequestbodyaccess".to_string(),
            directive_sec_request_body_access,
        );
        self.directives.insert(
            "secresponsebodyaccess".to_string(),
            directive_sec_response_body_access,
        );
        self.directives.insert(
            "secrequestbodylimit".to_string(),
            directive_sec_request_body_limit,
        );
        self.directives.insert(
            "secrequestbodylimitaction".to_string(),
            directive_sec_request_body_limit_action,
        );
        self.directives.insert(
            "secdebugloglevel".to_string(),
            directive_sec_debug_log_level,
        );
        self.directives
            .insert("secwebappid".to_string(), directive_sec_web_app_id);
        self.directives.insert(
            "seccomponentsignature".to_string(),
            directive_sec_component_signature,
        );

        // Additional configuration directives
        self.directives.insert(
            "secserversignature".to_string(),
            directive_sec_server_signature,
        );
        self.directives
            .insert("secsensorid".to_string(), directive_sec_sensor_id);
        self.directives.insert(
            "secresponsebodylimit".to_string(),
            directive_sec_response_body_limit,
        );
        self.directives.insert(
            "secresponsebodylimitaction".to_string(),
            directive_sec_response_body_limit_action,
        );
        self.directives.insert(
            "secrequestbodyinmemorylimit".to_string(),
            directive_sec_request_body_in_memory_limit,
        );
        self.directives.insert(
            "secrequestbodynofileslimit".to_string(),
            directive_sec_request_body_no_files_limit,
        );
        self.directives.insert(
            "secargumentslimit".to_string(),
            directive_sec_arguments_limit,
        );
        self.directives
            .insert("secuploaddir".to_string(), directive_sec_upload_dir);
        self.directives.insert(
            "secuploadfilelimit".to_string(),
            directive_sec_upload_file_limit,
        );
        self.directives.insert(
            "secuploadfilemode".to_string(),
            directive_sec_upload_file_mode,
        );
        self.directives.insert(
            "secuploadkeepfiles".to_string(),
            directive_sec_upload_keep_files,
        );
        self.directives
            .insert("secauditengine".to_string(), directive_sec_audit_engine);
        self.directives
            .insert("secauditlog".to_string(), directive_sec_audit_log);
        self.directives
            .insert("secdatadir".to_string(), directive_sec_data_dir);
        self.directives.insert(
            "seccollectiontimeout".to_string(),
            directive_sec_collection_timeout,
        );
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
    /// * `path` - Path to SecLang configuration file or glob pattern
    ///
    /// # Returns
    ///
    /// Ok(()) if file parsed successfully, Err otherwise
    ///
    /// # Features
    ///
    /// - Supports glob patterns like `/path/to/rules/*.conf`
    /// - Handles relative paths (resolved from current directory)
    /// - Handles absolute paths
    /// - Tracks current directory for nested includes
    ///
    /// # Example
    ///
    /// ```no_run
    /// use coraza::seclang::Parser;
    ///
    /// let mut parser = Parser::new();
    /// parser.from_file("/etc/coraza/rules.conf")?;
    /// parser.from_file("./local_rules/*.conf")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_file<P: AsRef<Path>>(&mut self, path: P) -> ParseResult<()> {
        let original_dir = self.state.current_dir.clone();
        let path_str = path.as_ref().to_string_lossy().to_string();

        // Expand glob patterns if present
        let files = if path_str.contains('*') {
            glob::glob(&path_str)
                .map_err(|e| {
                    ParseError::new(
                        format!("failed to glob pattern '{}': {}", path_str, e),
                        self.state.current_line,
                        self.state.current_file.clone(),
                    )
                })?
                .filter_map(Result::ok)
                .map(|p| p.to_string_lossy().to_string())
                .collect()
        } else {
            vec![path_str]
        };

        // Process each file
        for file_path in files {
            let file_path = file_path.trim();

            // Resolve relative paths from current directory
            let resolved_path = if Path::new(file_path).is_absolute() {
                file_path.to_string()
            } else {
                Path::new(&self.state.current_dir)
                    .join(file_path)
                    .to_string_lossy()
                    .to_string()
            };

            // Update current file and directory
            let last_dir = self.state.current_dir.clone();
            self.state.current_file = resolved_path.clone();
            self.state.current_dir = Path::new(&resolved_path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| ".".to_string());

            // Read file
            let content = std::fs::read_to_string(&resolved_path).map_err(|e| {
                ParseError::new(
                    format!("failed to read file '{}': {}", resolved_path, e),
                    self.state.current_line,
                    self.state.current_file.clone(),
                )
            })?;

            // Parse file content
            let result = self.parse_string(&content);

            // Restore directory for sibling includes
            self.state.current_dir = last_dir;

            // Propagate errors
            result?;
        }

        // Restore original directory and clear current file
        self.state.current_dir = original_dir;
        self.state.current_file = String::new();

        Ok(())
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
                    waf_config: &mut self.waf_config,
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
// Directive Implementations
// ============================================================================

/// Helper function to parse boolean values (On/Off)
fn parse_boolean(value: &str) -> Result<bool, String> {
    match value.to_lowercase().as_str() {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(format!("expected On or Off, got: {}", value)),
    }
}

/// SecRuleEngine On|Off|DetectionOnly
///
/// Configures the rules engine.
fn directive_sec_rule_engine(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecRuleEngine requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    let status = RuleEngineStatus::from_str(&options.opts).map_err(|e| {
        ParseError::new(
            e.to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        )
    })?;

    options.waf_config.rule_engine = status;
    Ok(())
}

/// SecRequestBodyAccess On|Off
///
/// Configures whether request bodies will be buffered and processed.
fn directive_sec_request_body_access(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecRequestBodyAccess requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    let value = parse_boolean(&options.opts.to_lowercase()).map_err(|e| {
        ParseError::new(
            e,
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        )
    })?;

    options.waf_config.request_body_access = value;
    Ok(())
}

/// SecResponseBodyAccess On|Off
///
/// Configures whether response bodies will be buffered and processed.
fn directive_sec_response_body_access(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecResponseBodyAccess requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    let value = parse_boolean(&options.opts.to_lowercase()).map_err(|e| {
        ParseError::new(
            e,
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        )
    })?;

    options.waf_config.response_body_access = value;
    Ok(())
}

/// SecRequestBodyLimit [LIMIT_IN_BYTES]
///
/// Configures the maximum request body size.
fn directive_sec_request_body_limit(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecRequestBodyLimit requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    let limit = options.opts.parse::<i64>().map_err(|e| {
        ParseError::new(
            format!("invalid limit value: {}", e),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        )
    })?;

    options.waf_config.request_body_limit = limit;
    Ok(())
}

/// SecRequestBodyLimitAction Reject|ProcessPartial
///
/// Controls what happens when request body limit is reached.
fn directive_sec_request_body_limit_action(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecRequestBodyLimitAction requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    let action = match options.opts.to_lowercase().as_str() {
        "reject" => BodyLimitAction::Reject,
        "processpartial" => BodyLimitAction::ProcessPartial,
        _ => {
            return Err(ParseError::new(
                format!(
                    "invalid SecRequestBodyLimitAction value: {} (expected Reject or ProcessPartial)",
                    options.opts
                ),
                options.parser_state.current_line,
                options.parser_state.current_file.clone(),
            ));
        }
    };

    options.waf_config.request_body_limit_action = action;
    Ok(())
}

/// SecDebugLogLevel [0-9]
///
/// Configures the verboseness of the debug log.
fn directive_sec_debug_log_level(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecDebugLogLevel requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    let level = options.opts.parse::<u8>().map_err(|e| {
        ParseError::new(
            format!("invalid debug log level: {}", e),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        )
    })?;

    options.waf_config.set_debug_log_level(level).map_err(|e| {
        ParseError::new(
            e,
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        )
    })?;

    Ok(())
}

/// SecWebAppId [ID]
///
/// Configures the web application ID.
fn directive_sec_web_app_id(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecWebAppId requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    options.waf_config.web_app_id = options.opts.clone();
    Ok(())
}

/// SecComponentSignature "COMPONENT_NAME/X.Y.Z (COMMENT)"
///
/// Appends component signature to the Coraza signature.
fn directive_sec_component_signature(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecComponentSignature requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    options
        .waf_config
        .component_names
        .push(options.opts.clone());
    Ok(())
}

/// SecServerSignature [signature]
///
/// Sets the server signature that will be sent in the Server response header.
fn directive_sec_server_signature(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecServerSignature requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    options.waf_config.server_signature = options.opts.clone();
    Ok(())
}

/// SecSensorID [id]
///
/// Sets the sensor ID that will identify this WAF instance in a cluster.
fn directive_sec_sensor_id(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecSensorID requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    options.waf_config.sensor_id = options.opts.clone();
    Ok(())
}

/// SecResponseBodyLimit [limit_in_bytes]
///
/// Sets the maximum response body size that will be buffered.
fn directive_sec_response_body_limit(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecResponseBodyLimit requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    let limit = options.opts.parse::<i64>().map_err(|e| {
        ParseError::new(
            format!("invalid response body limit: {}", e),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        )
    })?;

    options.waf_config.response_body_limit = limit;
    Ok(())
}

/// SecResponseBodyLimitAction [Reject|ProcessPartial]
///
/// Controls what happens when response body limit is reached.
fn directive_sec_response_body_limit_action(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecResponseBodyLimitAction requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    let action = match options.opts.to_lowercase().as_str() {
        "reject" => BodyLimitAction::Reject,
        "processpartial" => BodyLimitAction::ProcessPartial,
        _ => {
            return Err(ParseError::new(
                format!("invalid SecResponseBodyLimitAction value: {}", options.opts),
                options.parser_state.current_line,
                options.parser_state.current_file.clone(),
            ));
        }
    };

    options.waf_config.response_body_limit_action = action;
    Ok(())
}

/// SecRequestBodyInMemoryLimit [limit_in_bytes]
///
/// Sets the limit for request body data stored in memory before writing to disk.
fn directive_sec_request_body_in_memory_limit(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecRequestBodyInMemoryLimit requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    let limit = options.opts.parse::<i64>().map_err(|e| {
        ParseError::new(
            format!("invalid in-memory limit: {}", e),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        )
    })?;

    options.waf_config.request_body_in_memory_limit = limit;
    Ok(())
}

/// SecRequestBodyNoFilesLimit [limit_in_bytes]
///
/// Sets the limit for request body excluding files.
fn directive_sec_request_body_no_files_limit(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecRequestBodyNoFilesLimit requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    let limit = options.opts.parse::<i64>().map_err(|e| {
        ParseError::new(
            format!("invalid no-files limit: {}", e),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        )
    })?;

    options.waf_config.request_body_no_files_limit = limit;
    Ok(())
}

/// SecArgumentsLimit [limit]
///
/// Sets the maximum number of ARGS that will be accepted.
fn directive_sec_arguments_limit(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecArgumentsLimit requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    let limit = options.opts.parse::<usize>().map_err(|e| {
        ParseError::new(
            format!("invalid arguments limit: {}", e),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        )
    })?;

    options.waf_config.argument_limit = limit;
    Ok(())
}

/// SecUploadDir [directory]
///
/// Sets the directory where uploaded files will be stored.
fn directive_sec_upload_dir(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecUploadDir requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    options.waf_config.upload_dir = options.opts.clone();
    Ok(())
}

/// SecUploadFileLimit [limit]
///
/// Sets the maximum number of files that will be processed in a multipart request.
fn directive_sec_upload_file_limit(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecUploadFileLimit requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    let limit = options.opts.parse::<usize>().map_err(|e| {
        ParseError::new(
            format!("invalid upload file limit: {}", e),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        )
    })?;

    options.waf_config.upload_file_limit = limit;
    Ok(())
}

/// SecUploadFileMode [mode]
///
/// Sets the file mode (permissions) for uploaded files.
fn directive_sec_upload_file_mode(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecUploadFileMode requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    let mode = u32::from_str_radix(&options.opts, 8).map_err(|e| {
        ParseError::new(
            format!("invalid file mode (expected octal): {}", e),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        )
    })?;

    options.waf_config.upload_file_mode = mode;
    Ok(())
}

/// SecUploadKeepFiles [On|Off]
///
/// Controls whether uploaded files are kept after transaction.
fn directive_sec_upload_keep_files(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecUploadKeepFiles requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    let keep = parse_boolean(&options.opts).map_err(|e| {
        ParseError::new(
            e,
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        )
    })?;
    options.waf_config.upload_keep_files = keep;
    Ok(())
}

/// SecAuditEngine [On|Off|RelevantOnly]
///
/// Configures the audit logging engine.
fn directive_sec_audit_engine(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecAuditEngine requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    use crate::seclang::waf_config::AuditEngineStatus;

    let status = match options.opts.to_lowercase().as_str() {
        "on" => AuditEngineStatus::On,
        "off" => AuditEngineStatus::Off,
        "relevantonly" => AuditEngineStatus::RelevantOnly,
        _ => {
            return Err(ParseError::new(
                format!(
                    "invalid SecAuditEngine value: {} (expected On, Off, or RelevantOnly)",
                    options.opts
                ),
                options.parser_state.current_line,
                options.parser_state.current_file.clone(),
            ));
        }
    };

    options.waf_config.audit_engine = status;
    Ok(())
}

/// SecAuditLog [path]
///
/// Sets the path to the audit log file.
fn directive_sec_audit_log(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecAuditLog requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    options.waf_config.audit_log = options.opts.clone();
    Ok(())
}

/// SecDataDir [directory]
///
/// Sets the directory for storing data files.
fn directive_sec_data_dir(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecDataDir requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    options.waf_config.data_dir = options.opts.clone();
    Ok(())
}

/// SecCollectionTimeout [seconds]
///
/// Sets the timeout for IP/SESSION/USER collections.
fn directive_sec_collection_timeout(options: &mut DirectiveOptions) -> ParseResult<()> {
    if options.opts.is_empty() {
        return Err(ParseError::new(
            "SecCollectionTimeout requires an argument".to_string(),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        ));
    }

    let timeout = options.opts.parse::<i64>().map_err(|e| {
        ParseError::new(
            format!("invalid collection timeout: {}", e),
            options.parser_state.current_line,
            options.parser_state.current_file.clone(),
        )
    })?;

    options.waf_config.collection_timeout = timeout;
    Ok(())
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
        // Error message should indicate invalid value
        assert!(err.message.to_lowercase().contains("invalid"));
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

    // ========================================================================
    // SecRequestBodyAccess Tests
    // ========================================================================

    #[test]
    fn test_sec_request_body_access_on() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecRequestBodyAccess On").is_ok());
        assert!(parser.config().request_body_access);
    }

    #[test]
    fn test_sec_request_body_access_off() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecRequestBodyAccess Off").is_ok());
        assert!(!parser.config().request_body_access);
    }

    #[test]
    fn test_sec_request_body_access_case_insensitive() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecRequestBodyAccess ON").is_ok());
        assert!(parser.config().request_body_access);
    }

    #[test]
    fn test_sec_request_body_access_invalid() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecRequestBodyAccess Invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_request_body_access_no_argument() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecRequestBodyAccess");
        assert!(result.is_err());
    }

    // ========================================================================
    // SecResponseBodyAccess Tests
    // ========================================================================

    #[test]
    fn test_sec_response_body_access_on() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecResponseBodyAccess On").is_ok());
        assert!(parser.config().response_body_access);
    }

    #[test]
    fn test_sec_response_body_access_off() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecResponseBodyAccess Off").is_ok());
        assert!(!parser.config().response_body_access);
    }

    // ========================================================================
    // SecRequestBodyLimit Tests
    // ========================================================================

    #[test]
    fn test_sec_request_body_limit_valid() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecRequestBodyLimit 1024").is_ok());
        assert_eq!(parser.config().request_body_limit, 1024);
    }

    #[test]
    fn test_sec_request_body_limit_large() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecRequestBodyLimit 134217728").is_ok());
        assert_eq!(parser.config().request_body_limit, 134217728);
    }

    #[test]
    fn test_sec_request_body_limit_invalid() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecRequestBodyLimit abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_request_body_limit_no_argument() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecRequestBodyLimit");
        assert!(result.is_err());
    }

    // ========================================================================
    // SecRequestBodyLimitAction Tests
    // ========================================================================

    #[test]
    fn test_sec_request_body_limit_action_reject() {
        let mut parser = Parser::new();
        assert!(
            parser
                .from_string("SecRequestBodyLimitAction Reject")
                .is_ok()
        );
        assert_eq!(
            parser.config().request_body_limit_action,
            BodyLimitAction::Reject
        );
    }

    #[test]
    fn test_sec_request_body_limit_action_process_partial() {
        let mut parser = Parser::new();
        assert!(
            parser
                .from_string("SecRequestBodyLimitAction ProcessPartial")
                .is_ok()
        );
        assert_eq!(
            parser.config().request_body_limit_action,
            BodyLimitAction::ProcessPartial
        );
    }

    #[test]
    fn test_sec_request_body_limit_action_case_insensitive() {
        let mut parser = Parser::new();
        assert!(
            parser
                .from_string("SecRequestBodyLimitAction REJECT")
                .is_ok()
        );
        assert_eq!(
            parser.config().request_body_limit_action,
            BodyLimitAction::Reject
        );
    }

    #[test]
    fn test_sec_request_body_limit_action_invalid() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecRequestBodyLimitAction Invalid");
        assert!(result.is_err());
    }

    // ========================================================================
    // SecDebugLogLevel Tests
    // ========================================================================

    #[test]
    fn test_sec_debug_log_level_valid_range() {
        let mut parser = Parser::new();
        for level in 0..=9 {
            let directive = format!("SecDebugLogLevel {}", level);
            assert!(parser.from_string(&directive).is_ok());
            assert_eq!(parser.config().debug_log_level, level);
        }
    }

    #[test]
    fn test_sec_debug_log_level_out_of_range() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecDebugLogLevel 10");
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_debug_log_level_invalid() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecDebugLogLevel abc");
        assert!(result.is_err());
    }

    // ========================================================================
    // SecWebAppId Tests
    // ========================================================================

    #[test]
    fn test_sec_web_app_id() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecWebAppId myapp").is_ok());
        assert_eq!(parser.config().web_app_id, "myapp");
    }

    #[test]
    fn test_sec_web_app_id_with_spaces() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecWebAppId my application").is_ok());
        assert_eq!(parser.config().web_app_id, "my application");
    }

    #[test]
    fn test_sec_web_app_id_no_argument() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecWebAppId");
        assert!(result.is_err());
    }

    // ========================================================================
    // SecComponentSignature Tests
    // ========================================================================

    #[test]
    fn test_sec_component_signature() {
        let mut parser = Parser::new();
        assert!(
            parser
                .from_string("SecComponentSignature \"OWASP_CRS/4.0.0\"")
                .is_ok()
        );
        assert_eq!(parser.config().component_names.len(), 1);
        assert_eq!(parser.config().component_names[0], "OWASP_CRS/4.0.0");
    }

    #[test]
    fn test_sec_component_signature_multiple() {
        let mut parser = Parser::new();
        assert!(
            parser
                .from_string("SecComponentSignature \"Component1\"")
                .is_ok()
        );
        assert!(
            parser
                .from_string("SecComponentSignature \"Component2\"")
                .is_ok()
        );
        assert_eq!(parser.config().component_names.len(), 2);
        assert_eq!(parser.config().component_names[0], "Component1");
        assert_eq!(parser.config().component_names[1], "Component2");
    }

    #[test]
    fn test_sec_component_signature_no_argument() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecComponentSignature");
        assert!(result.is_err());
    }

    // ========================================================================
    // Integration Tests (multiple directives)
    // ========================================================================

    #[test]
    fn test_multiple_directives() {
        let mut parser = Parser::new();
        let input = r#"
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRequestBodyLimit 1048576
SecDebugLogLevel 3
SecWebAppId production
"#;
        assert!(parser.from_string(input).is_ok());
        assert_eq!(parser.config().rule_engine, RuleEngineStatus::On);
        assert!(parser.config().request_body_access);
        assert!(!parser.config().response_body_access);
        assert_eq!(parser.config().request_body_limit, 1048576);
        assert_eq!(parser.config().debug_log_level, 3);
        assert_eq!(parser.config().web_app_id, "production");
    }

    // ========================================================================
    // Additional Configuration Directives Tests
    // ========================================================================

    #[test]
    fn test_sec_server_signature() {
        let mut parser = Parser::new();
        assert!(
            parser
                .from_string("SecServerSignature \"Apache/2.4.0\"")
                .is_ok()
        );
        assert_eq!(parser.config().server_signature, "Apache/2.4.0");
    }

    #[test]
    fn test_sec_sensor_id() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecSensorID sensor-01").is_ok());
        assert_eq!(parser.config().sensor_id, "sensor-01");
    }

    #[test]
    fn test_sec_response_body_limit() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecResponseBodyLimit 524288").is_ok());
        assert_eq!(parser.config().response_body_limit, 524288);
    }

    #[test]
    fn test_sec_response_body_limit_action() {
        let mut parser = Parser::new();
        assert!(
            parser
                .from_string("SecResponseBodyLimitAction ProcessPartial")
                .is_ok()
        );
        assert_eq!(
            parser.config().response_body_limit_action,
            BodyLimitAction::ProcessPartial
        );
    }

    #[test]
    fn test_sec_request_body_in_memory_limit() {
        let mut parser = Parser::new();
        assert!(
            parser
                .from_string("SecRequestBodyInMemoryLimit 131072")
                .is_ok()
        );
        assert_eq!(parser.config().request_body_in_memory_limit, 131072);
    }

    #[test]
    fn test_sec_request_body_no_files_limit() {
        let mut parser = Parser::new();
        assert!(
            parser
                .from_string("SecRequestBodyNoFilesLimit 65536")
                .is_ok()
        );
        assert_eq!(parser.config().request_body_no_files_limit, 65536);
    }

    #[test]
    fn test_sec_arguments_limit() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecArgumentsLimit 500").is_ok());
        assert_eq!(parser.config().argument_limit, 500);
    }

    #[test]
    fn test_sec_upload_dir() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecUploadDir /var/tmp").is_ok());
        assert_eq!(parser.config().upload_dir, "/var/tmp");
    }

    #[test]
    fn test_sec_upload_file_limit() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecUploadFileLimit 50").is_ok());
        assert_eq!(parser.config().upload_file_limit, 50);
    }

    #[test]
    fn test_sec_upload_file_mode() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecUploadFileMode 0644").is_ok());
        assert_eq!(parser.config().upload_file_mode, 0o644);
    }

    #[test]
    fn test_sec_upload_keep_files() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecUploadKeepFiles On");
        if let Err(e) = &result {
            eprintln!("Error: {}", e);
        }
        assert!(result.is_ok());
        assert!(parser.config().upload_keep_files);

        let mut parser = Parser::new();
        assert!(parser.from_string("SecUploadKeepFiles Off").is_ok());
        assert!(!parser.config().upload_keep_files);
    }

    #[test]
    fn test_sec_audit_engine() {
        use crate::seclang::AuditEngineStatus;

        let mut parser = Parser::new();
        assert!(parser.from_string("SecAuditEngine On").is_ok());
        assert_eq!(parser.config().audit_engine, AuditEngineStatus::On);

        let mut parser = Parser::new();
        assert!(parser.from_string("SecAuditEngine Off").is_ok());
        assert_eq!(parser.config().audit_engine, AuditEngineStatus::Off);

        let mut parser = Parser::new();
        assert!(parser.from_string("SecAuditEngine RelevantOnly").is_ok());
        assert_eq!(
            parser.config().audit_engine,
            AuditEngineStatus::RelevantOnly
        );
    }

    #[test]
    fn test_sec_audit_log() {
        let mut parser = Parser::new();
        assert!(
            parser
                .from_string("SecAuditLog /var/log/coraza/audit.log")
                .is_ok()
        );
        assert_eq!(parser.config().audit_log, "/var/log/coraza/audit.log");
    }

    #[test]
    fn test_sec_data_dir() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecDataDir /var/cache/coraza").is_ok());
        assert_eq!(parser.config().data_dir, "/var/cache/coraza");
    }

    #[test]
    fn test_sec_collection_timeout() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecCollectionTimeout 7200").is_ok());
        assert_eq!(parser.config().collection_timeout, 7200);
    }

    // ========================================================================
    // Include Directive Tests
    // ========================================================================

    #[test]
    fn test_include_file() {
        use std::fs;
        use std::io::Write;

        // Create a temporary directory for test files
        let temp_dir = std::env::temp_dir().join("coraza_include_test");
        fs::create_dir_all(&temp_dir).unwrap();

        // Create a test config file
        let test_file = temp_dir.join("test_rules.conf");
        let mut file = fs::File::create(&test_file).unwrap();
        writeln!(file, "SecRuleEngine On").unwrap();
        writeln!(file, "SecWebAppId included_file").unwrap();

        // Parse with include
        let mut parser = Parser::new();
        parser.state.current_dir = temp_dir.to_string_lossy().to_string();
        assert!(parser.from_file(&test_file).is_ok());

        assert_eq!(parser.config().rule_engine, RuleEngineStatus::On);
        assert_eq!(parser.config().web_app_id, "included_file");

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_include_directive_from_string() {
        use std::fs;
        use std::io::Write;

        // Create a temporary directory
        let temp_dir = std::env::temp_dir().join("coraza_include_directive_test");
        fs::create_dir_all(&temp_dir).unwrap();

        // Create included file
        let included_file = temp_dir.join("included.conf");
        let mut file = fs::File::create(&included_file).unwrap();
        writeln!(file, "SecWebAppId from_included").unwrap();

        // Create main file with Include directive
        let main_file = temp_dir.join("main.conf");
        let mut file = fs::File::create(&main_file).unwrap();
        writeln!(file, "SecRuleEngine DetectionOnly").unwrap();
        writeln!(file, "Include included.conf").unwrap();

        // Parse main file
        let mut parser = Parser::new();
        parser.state.current_dir = temp_dir.to_string_lossy().to_string();
        assert!(parser.from_file(&main_file).is_ok());

        assert_eq!(parser.config().rule_engine, RuleEngineStatus::DetectionOnly);
        assert_eq!(parser.config().web_app_id, "from_included");

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_include_glob_pattern() {
        use std::fs;
        use std::io::Write;

        // Create a temporary directory
        let temp_dir = std::env::temp_dir().join("coraza_glob_test");
        fs::create_dir_all(&temp_dir).unwrap();

        // Create multiple .conf files
        for i in 1..=3 {
            let file_path = temp_dir.join(format!("rules{}.conf", i));
            let mut file = fs::File::create(&file_path).unwrap();
            writeln!(file, "SecComponentSignature \"Component{}\"", i).unwrap();
        }

        // Parse with glob pattern
        let mut parser = Parser::new();
        let glob_pattern = temp_dir.join("*.conf").to_string_lossy().to_string();
        assert!(parser.from_file(&glob_pattern).is_ok());

        // Should have loaded all 3 components
        assert_eq!(parser.config().component_names.len(), 3);

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_include_recursion_limit() {
        use std::fs;
        use std::io::Write;

        // Create a temporary directory
        let temp_dir = std::env::temp_dir().join("coraza_recursion_test");
        fs::create_dir_all(&temp_dir).unwrap();

        // Create file that includes itself (infinite recursion)
        let self_include = temp_dir.join("self_include.conf");
        let mut file = fs::File::create(&self_include).unwrap();
        writeln!(file, "Include self_include.conf").unwrap();

        // Try to parse - should hit recursion limit
        let mut parser = Parser::new();
        parser.state.current_dir = temp_dir.to_string_lossy().to_string();
        let result = parser.from_file(&self_include);

        // Should error due to recursion limit
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.message.contains("cannot include more than"));
        }

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_include_relative_path() {
        use std::fs;
        use std::io::Write;

        // Create a temporary directory structure
        let temp_dir = std::env::temp_dir().join("coraza_relative_test");
        let sub_dir = temp_dir.join("subdir");
        fs::create_dir_all(&sub_dir).unwrap();

        // Create file in subdirectory
        let sub_file = sub_dir.join("sub_rules.conf");
        let mut file = fs::File::create(&sub_file).unwrap();
        writeln!(file, "SecWebAppId from_subdir").unwrap();

        // Create main file with relative include
        let main_file = temp_dir.join("main.conf");
        let mut file = fs::File::create(&main_file).unwrap();
        writeln!(file, "Include subdir/sub_rules.conf").unwrap();

        // Parse main file
        let mut parser = Parser::new();
        parser.state.current_dir = temp_dir.to_string_lossy().to_string();
        assert!(parser.from_file(&main_file).is_ok());

        assert_eq!(parser.config().web_app_id, "from_subdir");

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_include_nonexistent_file() {
        let mut parser = Parser::new();
        let result = parser.from_file("/nonexistent/path/to/file.conf");

        // Should error
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.message.contains("failed to read file"));
        }
    }
}
