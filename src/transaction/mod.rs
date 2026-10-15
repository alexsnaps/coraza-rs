//! Transaction management for request/response processing.
//!
//! A transaction represents a single HTTP request/response pair and holds
//! all the data (headers, arguments, cookies, etc.) that rules operate on.

pub mod variables;

use std::sync::Arc;

use crate::RuleVariable;
use crate::actions::{AllowType, RuleMetadata};
use crate::audit_log::{
    AuditFile, AuditLog, AuditLogger, AuditMessage, AuditMessageData, AuditProducer, AuditRequest,
    AuditResponse, AuditTransaction, mime_type_of,
};
use crate::body_processors::{BodyProcessorKind, BodyProcessorOptions};
use crate::collection::{Map, MatchData, Single};
use crate::config::WafConfig;
use crate::rules::RuleGroup;
use crate::transformations::text_from_bytes;
use crate::types::{
    AuditEngineStatus, AuditLogPart, AuditLogParts, BodyLimitAction, RuleEngineStatus, RulePhase,
    RuleSeverity,
};
use crate::utils::strings::x2c;
use crate::utils::time::UtcTime;

/// A rule, with its chain, that matched in a transaction, as recorded for logging.
#[derive(Debug, Clone)]
pub struct MatchedRule {
    /// The rule as compiled (for a chain, its first rule), with `raw` holding the
    /// directives of the whole chain
    pub rule: RuleMetadata,

    /// Each value the rule and its chain matched, with `message` and `data` as the
    /// rule's `msg` and `logdata` expanded for it
    pub matches: Vec<MatchData>,

    /// Name of the rule's disruptive action (`deny`, `pass`, ...), whether or not it
    /// took effect; `None` if it has none
    pub disruptive_action: Option<&'static str>,

    /// Whether that disruptive action took effect: the rule engine was On
    pub disruptive: bool,

    /// REMOTE_ADDR when the rule matched
    pub client_ip: String,

    /// SERVER_ADDR when the rule matched
    pub server_ip: String,

    /// REQUEST_URI when the rule matched
    pub uri: String,

    /// The transaction's id
    pub transaction_id: String,
}

/// Longest message or data the log lines show, in bytes, as in Go Coraza.
const MAX_LOG_MESSAGE: usize = 280;

impl MatchedRule {
    /// The first message among the matches, as for a chain the first rule with a `msg`
    /// gives it; empty if none.
    pub fn message(&self) -> &str {
        self.first_with_message().map_or("", |m| m.message.as_str())
    }

    /// The data that goes with [`MatchedRule::message`].
    pub fn data(&self) -> &str {
        self.first_with_message().map_or("", |m| m.data.as_str())
    }

    fn first_with_message(&self) -> Option<&MatchData> {
        self.matches.iter().find(|m| !m.message.is_empty())
    }

    /// The line Go Coraza writes to its error log for this match, e.g.
    /// `[client "10.0.0.1"] Coraza: Access denied (phase 2). XSS [file "rules.conf"]
    /// [line "12"] [id "941100"] ... [unique_id "tx-1"]`.
    pub fn error_log(&self) -> String {
        let first = self.matches.first();
        let mut log = format!("[client {}] ", go_quote(&self.client_ip));
        log.push_str(&self.outcome());
        log.push_str(truncated(self.message(), MAX_LOG_MESSAGE));
        log.push(' ');
        let (msg, data) = first.map_or(("", ""), |m| (m.message.as_str(), m.data.as_str()));
        self.write_details(&mut log, msg, data);
        for (n, extra) in self.matches.iter().enumerate().skip(1) {
            if !extra.message.is_empty() || !extra.data.is_empty() {
                log.push_str(&format!(
                    "[msg_match_{n} {}] [data_match_{n} {}]",
                    go_quote(truncated(&extra.message, MAX_LOG_MESSAGE)),
                    go_quote(truncated(&extra.data, MAX_LOG_MESSAGE)),
                ));
            }
        }
        log
    }

    /// What the rule did, as Go Coraza words it: `Coraza: Warning. ` when no disruptive
    /// action took effect.
    fn outcome(&self) -> String {
        let phase = self.rule.phase.as_int();
        match self.disruptive_action.filter(|_| self.disruptive) {
            None | Some("pass") => "Coraza: Warning. ".to_string(),
            Some("allow") => format!("Coraza: Access allowed (phase {phase}). "),
            Some("deny") => format!("Coraza: Access denied (phase {phase}). "),
            Some("drop") => format!("Coraza: Access dropped (phase {phase}). "),
            Some("redirect") => format!("Coraza: Access redirected (phase {phase}). "),
            Some(_) => format!("Coraza: Custom disruptive action triggered (phase {phase}). "),
        }
    }

    fn write_details(&self, log: &mut String, msg: &str, data: &str) {
        let rule = &self.rule;
        let severity = rule.severity.map_or("unknown", |s| s.as_str());
        log.push_str(&format!(
            "[file {}] [line {}] [id {}] [rev {}] [msg {}] [data {}] [severity {}] [ver {}] [maturity {}] [accuracy {}]",
            go_quote(&rule.file),
            go_quote(&rule.line.to_string()),
            go_quote(&rule.id.to_string()),
            go_quote(&rule.rev),
            go_quote(truncated(msg, MAX_LOG_MESSAGE)),
            go_quote(truncated(data, MAX_LOG_MESSAGE)),
            go_quote(severity),
            go_quote(&rule.ver),
            go_quote(&rule.maturity.to_string()),
            go_quote(&rule.accuracy.to_string()),
        ));
        for tag in &rule.tags {
            log.push_str(&format!(" [tag {}]", go_quote(tag)));
        }
        log.push_str(&format!(
            " [hostname {}] [uri {}] [unique_id {}]",
            go_quote(&self.server_ip),
            go_quote(&self.uri),
            go_quote(&self.transaction_id),
        ));
    }
}

/// The longest prefix of `text` of at most `max` bytes that ends on a character boundary.
fn truncated(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let end = (0..=max)
        .rev()
        .find(|&i| text.is_char_boundary(i))
        .unwrap_or(0);
    &text[..end]
}

/// `text` as a double-quoted string literal the way Go's `%q` writes it.
fn go_quote(text: &str) -> String {
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('"');
    for c in text.chars() {
        match c {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\u{07}' => quoted.push_str("\\a"),
            '\u{08}' => quoted.push_str("\\b"),
            '\u{0c}' => quoted.push_str("\\f"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            '\u{0b}' => quoted.push_str("\\v"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                quoted.push_str(&format!("\\x{:02x}", c as u32));
            }
            c if c.is_control() => quoted.push_str(&format!("\\u{:04x}", c as u32)),
            c => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

/// Interruption returned when a disruptive action is triggered.
///
/// An interruption indicates that a rule matched and triggered a disruptive
/// action (deny, drop, redirect, allow) that should stop further processing.
///
/// # Example
///
/// ```
/// use coraza::transaction::Interruption;
///
/// let interruption = Interruption {
///     rule_id: 123,
///     action: "deny".to_string(),
///     status: 403,
///     data: String::new(),
/// };
///
/// assert_eq!(interruption.status, 403);
/// assert_eq!(interruption.action, "deny");
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Interruption {
    /// Rule ID that caused the interruption
    pub rule_id: usize,

    /// Disruptive action: "deny", "drop", "redirect", "allow"
    pub action: String,

    /// HTTP status code to return
    pub status: u16,

    /// Additional data (used by proxy and redirect)
    pub data: String,
}

/// The data behind one rule variable in a transaction: a single value, a key-value map,
/// or the keys of a map.
///
/// `S` and `M` are `&Single`/`&Map` or their `&mut` forms.
#[derive(Debug)]
pub enum VariableCollection<S, M> {
    /// A variable with one value, such as `REQUEST_URI`
    Single(S),
    /// A variable with values selected by key, such as `ARGS`
    Map(M),
    /// The keys of a map, as variable `.0`, such as `ARGS_NAMES`: each value of the map
    /// stands for its key, which is also the value
    Names(RuleVariable, M),
}

/// Maps each rule variable to the transaction field that holds it; `$borrow` is `&` or
/// `&mut`. This is the only such mapping: adding a [`RuleVariable`] variant fails to
/// compile here until it is mapped to a field or listed as not populated.
macro_rules! variable_storage {
    ($tx:expr, $variable:expr, $($borrow:tt)+) => {{
        use VariableCollection::{Map, Names, Single};
        match $variable {
            RuleVariable::Args => Some(Map($($borrow)+ $tx.args)),
            RuleVariable::ArgsGet => Some(Map($($borrow)+ $tx.args_get)),
            RuleVariable::ArgsPost => Some(Map($($borrow)+ $tx.args_post)),
            RuleVariable::ArgsPath => Some(Map($($borrow)+ $tx.args_path)),
            RuleVariable::MultipartName => Some(Map($($borrow)+ $tx.multipart_name)),
            RuleVariable::MultipartFilename => Some(Map($($borrow)+ $tx.multipart_filename)),
            RuleVariable::MultipartFilenameCharset => {
                Some(Map($($borrow)+ $tx.multipart_filename_charset))
            }
            RuleVariable::MultipartFilenameLanguage => {
                Some(Map($($borrow)+ $tx.multipart_filename_language))
            }
            RuleVariable::RequestHeaders => Some(Map($($borrow)+ $tx.request_headers)),
            RuleVariable::RequestCookies => Some(Map($($borrow)+ $tx.request_cookies)),
            RuleVariable::ResponseHeaders => Some(Map($($borrow)+ $tx.response_headers)),
            RuleVariable::Files => Some(Map($($borrow)+ $tx.files)),
            RuleVariable::FilesTmpNames => Some(Map($($borrow)+ $tx.files_tmp_names)),
            RuleVariable::FilesSizes => Some(Map($($borrow)+ $tx.files_sizes)),
            RuleVariable::FilesNames => Some(Map($($borrow)+ $tx.files_names)),
            RuleVariable::MultipartPartHeaders => Some(Map($($borrow)+ $tx.multipart_part_headers)),
            // As in Go Coraza, XML is REQUEST_XML under another name
            RuleVariable::RequestXML | RuleVariable::XML => Some(Map($($borrow)+ $tx.request_xml)),
            RuleVariable::ResponseArgs => Some(Map($($borrow)+ $tx.response_args)),
            RuleVariable::ResponseXML => Some(Map($($borrow)+ $tx.response_xml)),
            RuleVariable::TX => Some(Map($($borrow)+ $tx.tx)),
            RuleVariable::ArgsNames => Some(Names(RuleVariable::ArgsNames, $($borrow)+ $tx.args)),
            RuleVariable::ArgsGetNames => {
                Some(Names(RuleVariable::ArgsGetNames, $($borrow)+ $tx.args_get))
            }
            RuleVariable::ArgsPostNames => {
                Some(Names(RuleVariable::ArgsPostNames, $($borrow)+ $tx.args_post))
            }
            RuleVariable::RequestHeadersNames => {
                Some(Names(RuleVariable::RequestHeadersNames, $($borrow)+ $tx.request_headers))
            }
            RuleVariable::RequestCookiesNames => {
                Some(Names(RuleVariable::RequestCookiesNames, $($borrow)+ $tx.request_cookies))
            }
            RuleVariable::ResponseHeadersNames => {
                Some(Names(RuleVariable::ResponseHeadersNames, $($borrow)+ $tx.response_headers))
            }
            RuleVariable::UniqueID => Some(Single($($borrow)+ $tx.unique_id)),
            RuleVariable::ArgsCombinedSize => Some(Single($($borrow)+ $tx.args_combined_size)),
            RuleVariable::MultipartInvalidQuoting => {
                Some(Single($($borrow)+ $tx.multipart_invalid_quoting))
            }
            RuleVariable::Env => Some(Map($($borrow)+ $tx.env)),
            RuleVariable::Rule => Some(Map($($borrow)+ $tx.rule)),
            RuleVariable::HighestSeverity => Some(Single($($borrow)+ $tx.highest_severity)),
            RuleVariable::Time => Some(Single($($borrow)+ $tx.time.time)),
            RuleVariable::TimeDay => Some(Single($($borrow)+ $tx.time.day)),
            RuleVariable::TimeEpoch => Some(Single($($borrow)+ $tx.time.epoch)),
            RuleVariable::TimeHour => Some(Single($($borrow)+ $tx.time.hour)),
            RuleVariable::TimeMin => Some(Single($($borrow)+ $tx.time.min)),
            RuleVariable::TimeMon => Some(Single($($borrow)+ $tx.time.mon)),
            RuleVariable::TimeSec => Some(Single($($borrow)+ $tx.time.sec)),
            RuleVariable::TimeWday => Some(Single($($borrow)+ $tx.time.wday)),
            RuleVariable::TimeYear => Some(Single($($borrow)+ $tx.time.year)),
            // Go Coraza sets these to 0 and never changes them
            RuleVariable::UrlencodedError => Some(Single($($borrow)+ $tx.urlencoded_error)),
            RuleVariable::FullRequestLength => {
                Some(Single($($borrow)+ $tx.full_request_length))
            }
            RuleVariable::Duration => Some(Single($($borrow)+ $tx.duration)),
            RuleVariable::MultipartDataAfter => {
                Some(Single($($borrow)+ $tx.multipart_data_after))
            }
            RuleVariable::OutboundDataError => Some(Single($($borrow)+ $tx.outbound_data_error)),
            RuleVariable::InboundDataError => Some(Single($($borrow)+ $tx.inbound_data_error)),
            RuleVariable::MatchedVars => Some(Map($($borrow)+ $tx.matched_vars)),
            RuleVariable::MatchedVarsNames => {
                Some(Names(RuleVariable::MatchedVarsNames, $($borrow)+ $tx.matched_vars))
            }
            RuleVariable::MatchedVar => Some(Single($($borrow)+ $tx.matched_var)),
            RuleVariable::MatchedVarName => Some(Single($($borrow)+ $tx.matched_var_name)),
            RuleVariable::RequestURI => Some(Single($($borrow)+ $tx.request_uri)),
            RuleVariable::RequestMethod => Some(Single($($borrow)+ $tx.request_method)),
            RuleVariable::RemoteAddr => Some(Single($($borrow)+ $tx.remote_addr)),
            RuleVariable::RemotePort => Some(Single($($borrow)+ $tx.remote_port)),
            RuleVariable::ServerAddr => Some(Single($($borrow)+ $tx.server_addr)),
            RuleVariable::ServerPort => Some(Single($($borrow)+ $tx.server_port)),
            RuleVariable::ServerName => Some(Single($($borrow)+ $tx.server_name)),
            RuleVariable::RequestProtocol => Some(Single($($borrow)+ $tx.request_protocol)),
            RuleVariable::RequestURIRaw => Some(Single($($borrow)+ $tx.request_uri_raw)),
            RuleVariable::RequestBasename => Some(Single($($borrow)+ $tx.request_basename)),
            RuleVariable::RequestFilename => Some(Single($($borrow)+ $tx.request_filename)),
            RuleVariable::RequestLine => Some(Single($($borrow)+ $tx.request_line)),
            RuleVariable::QueryString => Some(Single($($borrow)+ $tx.query_string)),
            RuleVariable::RequestBody => Some(Single($($borrow)+ $tx.request_body)),
            RuleVariable::RequestBodyLength => Some(Single($($borrow)+ $tx.request_body_length)),
            RuleVariable::ReqbodyError => Some(Single($($borrow)+ $tx.reqbody_error)),
            RuleVariable::ReqbodyErrorMsg => Some(Single($($borrow)+ $tx.reqbody_error_msg)),
            RuleVariable::ReqbodyProcessor => Some(Single($($borrow)+ $tx.reqbody_processor)),
            RuleVariable::ReqbodyProcessorError => {
                Some(Single($($borrow)+ $tx.reqbody_processor_error))
            }
            RuleVariable::ReqbodyProcessorErrorMsg => {
                Some(Single($($borrow)+ $tx.reqbody_processor_error_msg))
            }
            RuleVariable::ResBodyProcessor => Some(Single($($borrow)+ $tx.res_body_processor)),
            RuleVariable::ResBodyError => Some(Single($($borrow)+ $tx.res_body_error)),
            RuleVariable::ResBodyErrorMsg => Some(Single($($borrow)+ $tx.res_body_error_msg)),
            RuleVariable::ResBodyProcessorError => {
                Some(Single($($borrow)+ $tx.res_body_processor_error))
            }
            RuleVariable::ResBodyProcessorErrorMsg => {
                Some(Single($($borrow)+ $tx.res_body_processor_error_msg))
            }
            RuleVariable::FilesCombinedSize => Some(Single($($borrow)+ $tx.files_combined_size)),
            RuleVariable::MultipartStrictError => Some(Single($($borrow)+ $tx.multipart_strict_error)),
            RuleVariable::MultipartDuplicatePartHeader => {
                Some(Single($($borrow)+ $tx.multipart_duplicate_part_header))
            }
            RuleVariable::UriParseError => Some(Single($($borrow)+ $tx.uri_parse_error)),
            RuleVariable::ArgumentsLimitReached => {
                Some(Single($($borrow)+ $tx.arguments_limit_reached))
            }
            RuleVariable::ResponseStatus => Some(Single($($borrow)+ $tx.response_status)),
            RuleVariable::ResponseProtocol => Some(Single($($borrow)+ $tx.response_protocol)),
            RuleVariable::ResponseContentType => Some(Single($($borrow)+ $tx.response_content_type)),
            RuleVariable::ResponseContentLength => Some(Single($($borrow)+ $tx.response_content_length)),
            RuleVariable::ResponseBody => Some(Single($($borrow)+ $tx.response_body)),

            // Not populated by this engine yet
            RuleVariable::Unknown
            | RuleVariable::RemoteHost
            | RuleVariable::StatusLine
            | RuleVariable::FilesTmpContent
            | RuleVariable::Geo
            | RuleVariable::JSON
            | RuleVariable::AuthType
            | RuleVariable::FullRequest
            | RuleVariable::MultipartBoundaryQuoted
            | RuleVariable::MultipartBoundaryWhitespace
            | RuleVariable::MultipartCrlfLfLines
            | RuleVariable::MultipartDataBefore
            | RuleVariable::MultipartFileLimitExceeded
            | RuleVariable::MultipartHeaderFolding
            | RuleVariable::MultipartInvalidHeaderFolding
            | RuleVariable::MultipartInvalidPart
            | RuleVariable::MultipartLfLine
            | RuleVariable::MultipartMissingSemicolon
            | RuleVariable::MultipartUnmatchedBoundary
            | RuleVariable::PathInfo
            | RuleVariable::Sessionid
            | RuleVariable::Userid
            | RuleVariable::IP => None,
        }
    }};
}

/// A transaction represents a single HTTP request/response being processed.
///
/// Transactions store all request and response data in collections that
/// can be queried by rules. Each transaction is isolated and not thread-safe.
///
/// # Examples
///
/// ```
/// use coraza::transaction::Transaction;
///
/// let mut tx = Transaction::new("tx-001");
///
/// // Add request data
/// tx.args_get_mut().add("id", "123");
/// tx.request_headers_mut().add("User-Agent", "Mozilla/5.0");
///
/// // Query data in rules
/// let id_values = tx.args_get().get("id");
/// assert_eq!(id_values, vec!["123"]);
/// ```
pub struct Transaction {
    /// UNIQUE_ID - The transaction ID
    unique_id: Single,

    /// ARGS_COMBINED_SIZE - Bytes in the keys and values of ARGS_GET and ARGS_POST, as of
    /// the start of the current phase
    args_combined_size: Single,

    /// Combined ARGS (GET + POST parameters)
    args: Map,

    /// GET/query parameters
    args_get: Map,

    /// POST body parameters
    args_post: Map,

    /// Arguments taken from the URL path by the connector (ARGS_PATH)
    args_path: Map,

    /// Request headers (case-insensitive)
    request_headers: Map,

    /// Request cookies
    request_cookies: Map,

    /// Response headers (case-insensitive)
    response_headers: Map,

    /// REQUEST_URI
    request_uri: Single,

    /// REQUEST_METHOD
    request_method: Single,

    /// REMOTE_ADDR
    remote_addr: Single,

    /// REMOTE_PORT
    remote_port: Single,

    /// SERVER_ADDR
    server_addr: Single,

    /// SERVER_PORT
    server_port: Single,

    /// SERVER_NAME
    server_name: Single,

    /// REQUEST_PROTOCOL (HTTP/1.1, HTTP/2, etc.)
    request_protocol: Single,

    /// REQUEST_URI_RAW (original URI before parsing)
    request_uri_raw: Single,

    /// REQUEST_BASENAME (filename from path)
    request_basename: Single,

    /// REQUEST_FILENAME (path component)
    request_filename: Single,

    /// REQUEST_LINE (full request line: METHOD URI PROTOCOL)
    request_line: Single,

    /// QUERY_STRING
    query_string: Single,

    /// REQUEST_BODY (raw body content)
    pub(crate) request_body: Single,

    /// REQUEST_BODY_LENGTH
    pub(crate) request_body_length: Single,

    /// REQBODY_ERROR - "1" when the request body processor failed
    reqbody_error: Single,

    /// REQBODY_ERROR_MSG - Why the request body processor failed, after its name
    reqbody_error_msg: Single,

    /// REQBODY_PROCESSOR - Name of the processor that parses the request body; empty for
    /// none. The only record of the choice: see [`Transaction::set_request_body_processor`]
    reqbody_processor: Single,

    /// REQBODY_PROCESSOR_ERROR - "1" when the request body processor failed
    reqbody_processor_error: Single,

    /// REQBODY_PROCESSOR_ERROR_MSG - Why the request body processor failed
    reqbody_processor_error_msg: Single,

    /// RES_BODY_PROCESSOR - Name of the processor that parses the response body; empty for
    /// none, which stores it in RESPONSE_BODY instead
    res_body_processor: Single,

    /// RES_BODY_ERROR - "1" when the response body processor failed
    res_body_error: Single,

    /// RES_BODY_ERROR_MSG - Why the response body processor failed, after its name
    res_body_error_msg: Single,

    /// RES_BODY_PROCESSOR_ERROR - "1" when the response body processor failed
    res_body_processor_error: Single,

    /// RES_BODY_PROCESSOR_ERROR_MSG - Why the response body processor failed
    res_body_processor_error_msg: Single,

    /// URI_PARSE_ERROR - "1" when the request URI could not be parsed
    uri_parse_error: Single,

    /// ARGUMENTS_LIMIT_REACHED - "1" when arguments were dropped over `argument_limit`
    arguments_limit_reached: Single,

    /// FILES - Original file names from multipart/form-data
    pub(crate) files: Map,

    /// FILES_TMPNAMES - Temporary file paths for uploaded files
    pub(crate) files_tmp_names: Map,

    /// FILES_SIZES - Sizes of uploaded files
    pub(crate) files_sizes: Map,

    /// FILES_NAMES - Form field names for uploaded files
    pub(crate) files_names: Map,

    /// FILES_COMBINED_SIZE - Total size of all uploaded files
    pub(crate) files_combined_size: Single,

    /// MULTIPART_PART_HEADERS - Headers from each multipart part
    pub(crate) multipart_part_headers: Map,

    /// MULTIPART_NAME - The name of each multipart part, by name
    pub(crate) multipart_name: Map,

    /// MULTIPART_FILENAME - The file name of each multipart file part, by part name
    pub(crate) multipart_filename: Map,

    /// MULTIPART_FILENAME_CHARSET - The charset of each part's `filename*`, by part name
    pub(crate) multipart_filename_charset: Map,

    /// MULTIPART_FILENAME_LANGUAGE - The language of each part's `filename*`, by part name
    pub(crate) multipart_filename_language: Map,

    /// MULTIPART_STRICT_ERROR - Set to "1" when multipart parsing fails
    pub(crate) multipart_strict_error: Single,

    /// MULTIPART_DUPLICATE_PART_HEADER - "1" when a part repeats a header or parameter
    pub(crate) multipart_duplicate_part_header: Single,

    /// MULTIPART_INVALID_QUOTING - "1" when a part's `filename*` is quoted
    pub(crate) multipart_invalid_quoting: Single,

    /// REQUEST_XML - Parsed XML data (attributes and content)
    pub(crate) request_xml: Map,

    /// RESPONSE_STATUS (HTTP status code)
    response_status: Single,

    /// RESPONSE_PROTOCOL (HTTP/1.1, etc.)
    response_protocol: Single,

    /// RESPONSE_CONTENT_TYPE (content type without parameters)
    response_content_type: Single,

    /// RESPONSE_CONTENT_LENGTH
    response_content_length: Single,

    /// RESPONSE_BODY
    response_body: Single,

    /// RESPONSE_ARGS - Parsed response arguments (from JSON, etc.)
    response_args: Map,

    /// RESPONSE_XML - Parsed XML response data
    response_xml: Map,

    /// TX - Transaction variables (created with setvar, etc.)
    tx: Map,

    /// ENV - Variables set by `setenv`
    env: Map,

    /// RULE - `id`, `msg`, `rev`, `logdata` and `severity` of the rule being evaluated
    rule: Map,

    /// HIGHEST_SEVERITY - The most severe (lowest) severity of the rules matched so far;
    /// 255 before any
    highest_severity: Single,

    /// When the transaction started
    started: std::time::SystemTime,

    /// TIME, TIME_* - When the transaction started
    time: TimeVariables,

    /// Where the transaction's audit log entry goes; none outside a WAF
    audit_logger: Option<Arc<AuditLogger>>,

    /// URLENCODED_ERROR, FULL_REQUEST_LENGTH, DURATION, MULTIPART_DATA_AFTER - "0", as Go
    /// Coraza sets them and never changes them
    urlencoded_error: Single,
    full_request_length: Single,
    duration: Single,
    multipart_data_after: Single,

    /// INBOUND_DATA_ERROR - "1" once the request body reached its limit; empty before
    inbound_data_error: Single,

    /// OUTBOUND_DATA_ERROR - "1" once the response body reached its limit; "0" before
    outbound_data_error: Single,

    /// MATCHED_VAR - The value of the latest match
    matched_var: Single,

    /// MATCHED_VAR_NAME - The variable of the latest match, as `ARGS:id`
    matched_var_name: Single,

    /// MATCHED_VARS - The matches of the rule being evaluated, chain included, by
    /// variable name; emptied before each rule
    matched_vars: Map,

    // ===== CTL-Modifiable Settings =====
    /// Rule engine status (controlled by ctl:ruleEngine)
    pub(crate) rule_engine: RuleEngineStatus,

    /// Request body access enabled (controlled by ctl:requestBodyAccess)
    pub(crate) request_body_access: bool,

    /// Request body size limit in bytes (controlled by ctl:requestBodyLimit)
    pub(crate) request_body_limit: i64,

    /// Settings of the WAF the transaction belongs to; the defaults for one made with
    /// [`Transaction::new`]
    config: Arc<WafConfig>,

    /// Audit logging mode (`SecAuditEngine`, controlled by ctl:auditEngine)
    audit_engine: AuditEngineStatus,

    /// Audit log parts (`SecAuditLogParts`, controlled by ctl:auditLogParts)
    audit_log_parts: AuditLogParts,

    /// Debug log verbosity, 0 to 9 (`SecDebugLogLevel`, controlled by ctl:debugLogLevel)
    debug_log_level: u8,

    /// Force REQUEST_BODY variable creation (controlled by ctl:forceRequestBodyVariable)
    pub(crate) force_request_body_variable: bool,

    /// Response body access enabled (controlled by ctl:responseBodyAccess)
    pub(crate) response_body_access: bool,

    /// Response body size limit in bytes (controlled by ctl:responseBodyLimit)
    pub(crate) response_body_limit: i64,

    /// Force RESPONSE_BODY variable creation (controlled by ctl:forceResponseBodyVariable)
    pub(crate) force_response_body_variable: bool,

    /// Last phase that was processed
    last_phase: Option<RulePhase>,

    /// Current interruption (if any disruptive action was triggered)
    pub(crate) interruption: Option<Interruption>,

    /// Number of rules to skip in current phase (controlled by skip action)
    pub(crate) skip: i32,

    /// Marker ID to skip to (controlled by skipAfter action)
    pub(crate) skip_after: String,

    /// Whether operators of the rule being evaluated store their captures in TX.0-TX.9
    capturing: bool,

    // ===== CTL Runtime Exclusions =====
    /// Rules with these IDs will be skipped for this transaction
    /// (set by ctl:ruleRemoveById, ctl:ruleRemoveByTag, ctl:ruleRemoveByMsg)
    rule_remove_by_id: std::collections::BTreeSet<i32>,

    /// Variable exclusions per rule ID
    /// (set by ctl:ruleRemoveTargetById, ctl:ruleRemoveTargetByTag, ctl:ruleRemoveTargetByMsg)
    /// Map: rule_id -> Vec<(variable, key)>
    rule_remove_target_by_id: std::collections::BTreeMap<i32, Vec<(RuleVariable, String)>>,

    /// All rules that matched during this transaction (for audit logging)
    matched_rules: Vec<MatchedRule>,

    /// Reference to WAF's rule group for CTL tag/msg-based exclusions
    /// Optional because transactions created via Transaction::new() don't have a WAF reference
    rules: Option<Arc<RuleGroup>>,

    /// Rules skipped because of an `allow` action
    allow_type: AllowType,
}

impl Default for Transaction {
    fn default() -> Self {
        Self::new("default")
    }
}

/// A `0`/`1` variable, starting at `0` as in Go Coraza.
fn flag(variable: RuleVariable) -> Single {
    let mut flag = Single::new(variable);
    flag.set("0");
    flag
}

/// TIME and its parts, for one instant, in UTC (Go Coraza uses local time).
struct TimeVariables {
    /// `HH:MM:SS`
    time: Single,
    /// Day of the month, 1 to 31
    day: Single,
    /// Seconds since the Unix epoch
    epoch: Single,
    /// `HH`, 00 to 23
    hour: Single,
    /// `MM`, 00 to 59
    min: Single,
    /// Month, 1 to 12
    mon: Single,
    /// `SS`, 00 to 59
    sec: Single,
    /// Day of the week, 0 (Sunday) to 6
    wday: Single,
    /// Four-digit year
    year: Single,
}

impl TimeVariables {
    fn since_epoch(seconds: u64) -> Self {
        let at = UtcTime::from_unix(seconds);
        let single = |variable, value: String| {
            let mut single = Single::new(variable);
            single.set(value);
            single
        };
        let hour = format!("{:02}", at.hour);
        let min = format!("{:02}", at.minute);
        let sec = format!("{:02}", at.second);
        Self {
            time: single(RuleVariable::Time, format!("{hour}:{min}:{sec}")),
            day: single(RuleVariable::TimeDay, at.day.to_string()),
            epoch: single(RuleVariable::TimeEpoch, seconds.to_string()),
            hour: single(RuleVariable::TimeHour, hour),
            min: single(RuleVariable::TimeMin, min),
            mon: single(RuleVariable::TimeMon, at.month.to_string()),
            sec: single(RuleVariable::TimeSec, sec),
            wday: single(RuleVariable::TimeWday, at.weekday.to_string()),
            year: single(RuleVariable::TimeYear, at.year.to_string()),
        }
    }
}

/// The path, still `%`-escaped, of `uri` if it is a request URI as Go's
/// `url.ParseRequestURI` accepts one: `*`, an absolute path or an absolute URL, with no
/// control character and only valid `%`-escapes in its path; `None` otherwise. The
/// query string is not checked.
fn request_uri_path(uri: &str) -> Option<&str> {
    if uri.bytes().any(|b| b.is_ascii_control()) {
        return None;
    }
    if uri == "*" {
        return Some(uri);
    }
    let before_query = uri.split_once('?').map_or(uri, |(path, _)| path);
    let path = if before_query.starts_with('/') {
        before_query
    } else {
        let (scheme, rest) = before_query.split_once(':')?;
        let is_scheme = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
        if !is_scheme {
            return None;
        }
        // The path follows the authority (`//host`), if any; a URL without either, such
        // as `mailto:x`, is opaque and has no path
        match rest.strip_prefix("//") {
            Some(authority_and_path) => authority_and_path
                .find('/')
                .map_or("", |start| &authority_and_path[start..]),
            None => "",
        }
    };

    let bytes = path.as_bytes();
    bytes
        .iter()
        .enumerate()
        .all(|(i, &b)| {
            b != b'%'
                || bytes
                    .get(i + 1..i + 3)
                    .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
        })
        .then_some(path)
}

/// `path` with its `%`-escapes, all valid, decoded; `+` stays, as in a URL's path.
fn decode_path(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            decoded.push(x2c(&bytes[i + 1..i + 3]));
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    text_from_bytes(decoded)
}

impl Transaction {
    /// Create a new transaction with the given ID.
    pub fn new(id: impl Into<String>) -> Self {
        let config = WafConfig::default();
        let started = std::time::SystemTime::now();
        let map = |variable: RuleVariable| {
            if variable.has_case_sensitive_keys() {
                Map::new_case_sensitive(variable)
            } else {
                Map::new(variable)
            }
        };
        Self {
            unique_id: {
                let mut unique_id = Single::new(RuleVariable::UniqueID);
                unique_id.set(id);
                unique_id
            },
            args_combined_size: Single::new(RuleVariable::ArgsCombinedSize),
            args: map(RuleVariable::Args),
            args_get: map(RuleVariable::ArgsGet),
            args_post: map(RuleVariable::ArgsPost),
            args_path: map(RuleVariable::ArgsPath),
            request_headers: map(RuleVariable::RequestHeaders),
            request_cookies: map(RuleVariable::RequestCookies),
            response_headers: map(RuleVariable::ResponseHeaders),
            request_uri: Single::new(RuleVariable::RequestURI),
            request_method: Single::new(RuleVariable::RequestMethod),
            remote_addr: Single::new(RuleVariable::RemoteAddr),
            remote_port: Single::new(RuleVariable::RemotePort),
            server_addr: Single::new(RuleVariable::ServerAddr),
            server_port: Single::new(RuleVariable::ServerPort),
            server_name: Single::new(RuleVariable::ServerName),
            request_protocol: Single::new(RuleVariable::RequestProtocol),
            request_uri_raw: Single::new(RuleVariable::RequestURIRaw),
            request_basename: Single::new(RuleVariable::RequestBasename),
            request_filename: Single::new(RuleVariable::RequestFilename),
            request_line: Single::new(RuleVariable::RequestLine),
            query_string: Single::new(RuleVariable::QueryString),
            request_body: Single::new(RuleVariable::RequestBody),
            // Set, with REQUEST_BODY, only by the URLENCODED and RAW body processors
            request_body_length: {
                let mut request_body_length = Single::new(RuleVariable::RequestBodyLength);
                request_body_length.set("0");
                request_body_length
            },
            reqbody_error: flag(RuleVariable::ReqbodyError),
            reqbody_error_msg: Single::new(RuleVariable::ReqbodyErrorMsg),
            reqbody_processor: Single::new(RuleVariable::ReqbodyProcessor),
            reqbody_processor_error: flag(RuleVariable::ReqbodyProcessorError),
            reqbody_processor_error_msg: Single::new(RuleVariable::ReqbodyProcessorErrorMsg),
            res_body_processor: Single::new(RuleVariable::ResBodyProcessor),
            res_body_error: Single::new(RuleVariable::ResBodyError),
            res_body_error_msg: Single::new(RuleVariable::ResBodyErrorMsg),
            res_body_processor_error: Single::new(RuleVariable::ResBodyProcessorError),
            res_body_processor_error_msg: Single::new(RuleVariable::ResBodyProcessorErrorMsg),
            uri_parse_error: flag(RuleVariable::UriParseError),
            arguments_limit_reached: flag(RuleVariable::ArgumentsLimitReached),
            files: map(RuleVariable::Files),
            files_tmp_names: map(RuleVariable::FilesTmpNames),
            files_sizes: map(RuleVariable::FilesSizes),
            files_names: map(RuleVariable::FilesNames),
            files_combined_size: Single::new(RuleVariable::FilesCombinedSize),
            multipart_part_headers: map(RuleVariable::MultipartPartHeaders),
            multipart_name: map(RuleVariable::MultipartName),
            multipart_filename: map(RuleVariable::MultipartFilename),
            multipart_filename_charset: map(RuleVariable::MultipartFilenameCharset),
            multipart_filename_language: map(RuleVariable::MultipartFilenameLanguage),
            multipart_strict_error: Single::new(RuleVariable::MultipartStrictError),
            multipart_duplicate_part_header: flag(RuleVariable::MultipartDuplicatePartHeader),
            multipart_invalid_quoting: flag(RuleVariable::MultipartInvalidQuoting),
            request_xml: map(RuleVariable::RequestXML),
            response_status: Single::new(RuleVariable::ResponseStatus),
            response_protocol: Single::new(RuleVariable::ResponseProtocol),
            response_content_type: Single::new(RuleVariable::ResponseContentType),
            response_content_length: Single::new(RuleVariable::ResponseContentLength),
            response_body: Single::new(RuleVariable::ResponseBody),
            response_args: map(RuleVariable::ResponseArgs),
            response_xml: map(RuleVariable::ResponseXML),
            tx: map(RuleVariable::TX),
            env: map(RuleVariable::Env),
            rule: map(RuleVariable::Rule),
            highest_severity: {
                let mut highest_severity = Single::new(RuleVariable::HighestSeverity);
                highest_severity.set("255");
                highest_severity
            },
            started,
            time: TimeVariables::since_epoch(
                started
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |since| since.as_secs()),
            ),
            audit_logger: None,
            urlencoded_error: flag(RuleVariable::UrlencodedError),
            full_request_length: flag(RuleVariable::FullRequestLength),
            duration: flag(RuleVariable::Duration),
            multipart_data_after: flag(RuleVariable::MultipartDataAfter),
            inbound_data_error: Single::new(RuleVariable::InboundDataError),
            outbound_data_error: flag(RuleVariable::OutboundDataError),
            matched_var: Single::new(RuleVariable::MatchedVar),
            matched_var_name: Single::new(RuleVariable::MatchedVarName),
            matched_vars: map(RuleVariable::MatchedVars),
            rule_engine: RuleEngineStatus::On,
            request_body_access: true,
            request_body_limit: 131072, // 128KB default
            audit_engine: config.audit_engine,
            audit_log_parts: config.audit_log_parts.clone(),
            debug_log_level: config.debug_log_level,
            config: Arc::new(config),
            force_request_body_variable: false,
            response_body_access: false,
            response_body_limit: 524288, // 512KB default
            force_response_body_variable: false,
            last_phase: None,
            interruption: None,
            skip: 0,
            skip_after: String::new(),
            capturing: false,
            rule_remove_by_id: std::collections::BTreeSet::new(),
            rule_remove_target_by_id: std::collections::BTreeMap::new(),
            matched_rules: Vec::new(),
            rules: None, // No WAF reference for standalone transactions
            allow_type: AllowType::Unset,
        }
    }

    /// Get the transaction ID.
    pub fn id(&self) -> &str {
        self.unique_id.get()
    }

    /// Set the rules reference (called by WAF when creating transactions).
    ///
    /// This allows the transaction to access the WAF's rule set for CTL actions
    /// like `ctl:ruleRemoveByTag` and `ctl:ruleRemoveByMsg`.
    pub(crate) fn set_rules(&mut self, rules: Arc<RuleGroup>) {
        self.rules = Some(rules);
    }

    /// Makes the transaction write its audit log entry with `logger`.
    pub(crate) fn set_audit_logger(&mut self, logger: Arc<AuditLogger>) {
        self.audit_logger = Some(logger);
    }

    /// Makes the transaction use the settings of its WAF, starting with its own copy of
    /// those a `ctl` action can change.
    pub(crate) fn set_config(&mut self, config: Arc<WafConfig>) {
        self.rule_engine = config.rule_engine;
        self.request_body_access = config.request_body_access;
        self.request_body_limit = config.request_body_limit;
        self.response_body_access = config.response_body_access;
        self.response_body_limit = config.response_body_limit;
        self.audit_engine = config.audit_engine;
        self.audit_log_parts.clone_from(&config.audit_log_parts);
        self.debug_log_level = config.debug_log_level;
        self.config = config;
    }

    /// Get all rules that matched during this transaction.
    ///
    /// This is used for audit logging - all matched rules (not just blocking ones)
    /// are logged for proper CRS test compatibility.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::transaction::Transaction;
    ///
    /// let tx = Transaction::new("tx-001");
    /// let matches = tx.matched_rules();
    /// assert_eq!(matches.len(), 0); // No rules matched yet
    /// ```
    pub fn matched_rules(&self) -> &[MatchedRule] {
        &self.matched_rules
    }

    /// Record a rule match for audit logging.
    ///
    /// This is called by the rule engine when a rule matches, regardless of
    /// whether it triggers a disruptive action.
    pub(crate) fn record_match(
        &mut self,
        rule: RuleMetadata,
        matches: Vec<MatchData>,
        disruptive_action: Option<&'static str>,
    ) {
        let matched = MatchedRule {
            rule,
            matches,
            disruptive_action,
            disruptive: disruptive_action.is_some() && self.rule_engine == RuleEngineStatus::On,
            client_ip: self.remote_addr.get().to_string(),
            server_ip: self.server_addr.get().to_string(),
            uri: self.request_uri.get().to_string(),
            transaction_id: self.unique_id.get().to_string(),
        };
        self.matched_rules.push(matched);
    }

    /// Evaluates the WAF's rules of `phase`, if the transaction has a WAF.
    fn evaluate_rules(&mut self, phase: RulePhase) {
        // Computed here rather than kept up to date: anything may have added an argument
        let combined_size: usize = [&self.args_get, &self.args_post]
            .into_iter()
            .flat_map(|args| args.find_all())
            .map(|arg| arg.key.len() + arg.value.len())
            .sum();
        self.args_combined_size.set(combined_size.to_string());

        if let Some(rules) = self.rules.clone() {
            let rule_engine_on = self.rule_engine == RuleEngineStatus::On;
            rules.eval(phase, self, rule_engine_on);
        }
    }

    /// Records a value a rule (or chain link) matched, before its actions run: in
    /// MATCHED_VAR, MATCHED_VAR_NAME (`ARGS:id`, or `ARGS` without a key) and
    /// MATCHED_VARS.
    pub(crate) fn record_matched_variable(&mut self, matched: &MatchData) {
        let name = if matched.key.is_empty() {
            matched.variable.name().to_string()
        } else {
            format!("{}:{}", matched.variable.name(), matched.key)
        };
        self.matched_vars.add(&name, &matched.value);
        self.matched_var.set(matched.value.as_str());
        self.matched_var_name.set(name);
    }

    /// Sets `key` of ENV to `value`, as the `setenv` action does.
    pub fn set_env(&mut self, key: &str, value: String) {
        self.env.set(key, vec![value]);
    }

    /// Sets RULE to describe the rule about to be evaluated. As in Go Coraza, `msg` and
    /// `logdata` keep their earlier values when `None`.
    pub(crate) fn set_rule_variable(
        &mut self,
        id: i32,
        msg: Option<String>,
        rev: &str,
        log_data: Option<String>,
        severity: &str,
    ) {
        self.rule.set("id", vec![id.to_string()]);
        if let Some(msg) = msg {
            self.rule.set("msg", vec![msg]);
        }
        self.rule.set("rev", vec![rev.to_string()]);
        if let Some(log_data) = log_data {
            self.rule.set("logdata", vec![log_data]);
        }
        self.rule.set("severity", vec![severity.to_string()]);
    }

    /// Lowers HIGHEST_SEVERITY to `severity` if it is more severe, as a matching rule with
    /// that severity does.
    pub(crate) fn raise_highest_severity(&mut self, severity: RuleSeverity) {
        let highest = self.highest_severity.get().parse::<u8>().unwrap_or(u8::MAX);
        if severity.as_int() < highest {
            self.highest_severity.set(severity.as_int().to_string());
        }
    }

    /// Empties MATCHED_VARS, before a rule is evaluated.
    pub(crate) fn reset_matched_vars(&mut self) {
        self.matched_vars.reset();
    }

    /// The data a rule variable reads in this transaction, or `None` for a variable
    /// this engine doesn't populate.
    pub fn collection(&self, variable: RuleVariable) -> Option<VariableCollection<&Single, &Map>> {
        variable_storage!(self, variable, &)
    }

    /// Like [`Transaction::collection`], for changing the data (e.g. by `setvar`).
    pub fn collection_mut(
        &mut self,
        variable: RuleVariable,
    ) -> Option<VariableCollection<&mut Single, &mut Map>> {
        variable_storage!(self, variable, &mut)
    }

    /// Get ARGS (combined GET + POST) collection.
    pub fn args(&self) -> &Map {
        &self.args
    }

    /// Get mutable ARGS collection.
    pub fn args_mut(&mut self) -> &mut Map {
        &mut self.args
    }

    /// Get ARGS_GET collection.
    pub fn args_get(&self) -> &Map {
        &self.args_get
    }

    /// Get mutable ARGS_GET collection.
    pub fn args_get_mut(&mut self) -> &mut Map {
        &mut self.args_get
    }

    /// Get ARGS_POST collection.
    pub fn args_post(&self) -> &Map {
        &self.args_post
    }

    /// Get mutable ARGS_POST collection.
    pub fn args_post_mut(&mut self) -> &mut Map {
        &mut self.args_post
    }

    /// Get REQUEST_HEADERS collection.
    pub fn request_headers(&self) -> &Map {
        &self.request_headers
    }

    /// Get mutable REQUEST_HEADERS collection.
    pub fn request_headers_mut(&mut self) -> &mut Map {
        &mut self.request_headers
    }

    /// Get REQUEST_COOKIES collection.
    pub fn request_cookies(&self) -> &Map {
        &self.request_cookies
    }

    /// Get mutable REQUEST_COOKIES collection.
    pub fn request_cookies_mut(&mut self) -> &mut Map {
        &mut self.request_cookies
    }

    /// Get RESPONSE_HEADERS collection.
    pub fn response_headers(&self) -> &Map {
        &self.response_headers
    }

    /// Get mutable RESPONSE_HEADERS collection.
    pub fn response_headers_mut(&mut self) -> &mut Map {
        &mut self.response_headers
    }

    /// Get RESPONSE_ARGS collection.
    pub fn response_args(&self) -> &Map {
        &self.response_args
    }

    /// Get mutable RESPONSE_ARGS collection.
    pub fn response_args_mut(&mut self) -> &mut Map {
        &mut self.response_args
    }

    /// Get RESPONSE_XML collection.
    pub fn response_xml(&self) -> &Map {
        &self.response_xml
    }

    /// Get mutable RESPONSE_XML collection.
    pub fn response_xml_mut(&mut self) -> &mut Map {
        &mut self.response_xml
    }

    /// Get the REQUEST_URI value.
    pub fn request_uri(&self) -> &str {
        self.request_uri.get()
    }

    /// Set the REQUEST_URI value.
    pub fn set_request_uri(&mut self, uri: impl Into<String>) {
        self.request_uri.set(uri);
    }

    /// Get the REQUEST_METHOD value.
    pub fn request_method(&self) -> &str {
        self.request_method.get()
    }

    /// Set the REQUEST_METHOD value.
    pub fn set_request_method(&mut self, method: impl Into<String>) {
        self.request_method.set(method);
    }

    /// Get the REMOTE_ADDR value.
    pub fn remote_addr(&self) -> &str {
        self.remote_addr.get()
    }

    /// Set the REMOTE_ADDR value.
    pub fn set_remote_addr(&mut self, addr: impl Into<String>) {
        self.remote_addr.set(addr);
    }

    /// Get the REMOTE_PORT value.
    pub fn remote_port(&self) -> &str {
        self.remote_port.get()
    }

    /// Get the SERVER_ADDR value.
    pub fn server_addr(&self) -> &str {
        self.server_addr.get()
    }

    /// Get the SERVER_PORT value.
    pub fn server_port(&self) -> &str {
        self.server_port.get()
    }

    /// Get the SERVER_NAME value.
    pub fn server_name(&self) -> &str {
        self.server_name.get()
    }

    /// Get the REQUEST_PROTOCOL value.
    pub fn request_protocol(&self) -> &str {
        self.request_protocol.get()
    }

    /// Get the QUERY_STRING value.
    pub fn query_string(&self) -> &str {
        self.query_string.get()
    }

    /// Get the REQUEST_BODY value.
    pub fn request_body(&self) -> &str {
        self.request_body.get()
    }

    /// Get the RESPONSE_STATUS value.
    pub fn response_status(&self) -> &str {
        self.response_status.get()
    }

    /// Get the RESPONSE_PROTOCOL value.
    pub fn response_protocol(&self) -> &str {
        self.response_protocol.get()
    }

    /// Get the RESPONSE_CONTENT_TYPE value.
    pub fn response_content_type(&self) -> &str {
        self.response_content_type.get()
    }

    /// Get the RESPONSE_BODY value.
    pub fn response_body(&self) -> &str {
        self.response_body.get()
    }

    /// Get the FILES_COMBINED_SIZE value.
    pub fn files_combined_size(&self) -> &str {
        self.files_combined_size.get()
    }

    /// Get the FILES collection.
    pub fn files(&self) -> &Map {
        &self.files
    }

    /// Get the FILES_TMPNAMES collection.
    pub fn files_tmp_names(&self) -> &Map {
        &self.files_tmp_names
    }

    /// Get the FILES_NAMES collection.
    pub fn files_names(&self) -> &Map {
        &self.files_names
    }

    /// Get the REQUEST_XML collection.
    pub fn request_xml(&self) -> &Map {
        &self.request_xml
    }

    /// Sets whether operators store their captures in `TX.0`..`TX.9`; follows the `capture`
    /// action of the rule being evaluated.
    pub fn set_capturing(&mut self, enabled: bool) {
        self.capturing = enabled;
    }

    // ===== CTL Action Setters =====

    /// Set rule engine status (used by ctl:ruleEngine).
    pub fn set_rule_engine(&mut self, status: RuleEngineStatus) {
        self.rule_engine = status;
    }

    /// Get rule engine status.
    pub fn rule_engine(&self) -> RuleEngineStatus {
        self.rule_engine
    }

    /// Set request body access (used by ctl:requestBodyAccess).
    pub fn set_request_body_access(&mut self, enabled: bool) {
        self.request_body_access = enabled;
    }

    /// Get request body access status.
    pub fn request_body_access(&self) -> bool {
        self.request_body_access
    }

    /// Set request body limit (used by ctl:requestBodyLimit).
    pub fn set_request_body_limit(&mut self, limit: i64) {
        self.request_body_limit = limit;
    }

    /// Adds a query string argument to ARGS_GET and ARGS.
    ///
    /// Once ARGS_GET holds the argument limit's worth of values (`SecArgumentsLimit`),
    /// counting each value of a repeated key, the argument is dropped and
    /// ARGUMENTS_LIMIT_REACHED set to 1.
    pub fn add_get_argument(&mut self, key: &str, value: &str) {
        if self.within_argument_limit(self.args_get.value_count()) {
            self.args_get.add(key, value);
            self.args.add(key, value);
        }
    }

    /// Adds a request body argument to ARGS_POST and ARGS, within the argument limit as
    /// [`Transaction::add_get_argument`] does.
    pub fn add_post_argument(&mut self, key: &str, value: &str) {
        if self.within_argument_limit(self.args_post.value_count()) {
            self.args_post.add(key, value);
            self.args.add(key, value);
        }
    }

    /// Adds an argument the connector took from the URL path (e.g. `/users/{id}`) to
    /// ARGS_PATH and ARGS, within the argument limit as [`Transaction::add_get_argument`]
    /// does.
    pub fn add_path_argument(&mut self, key: &str, value: &str) {
        if self.within_argument_limit(self.args_path.value_count()) {
            self.args_path.add(key, value);
            self.args.add(key, value);
        }
    }

    /// Sets ARGS_PATH `key` to `value`, replacing its first value, as `@restpath` does;
    /// ARGS follows.
    pub(crate) fn set_path_argument(&mut self, key: &str, value: &str) {
        let previous = self.args_path.get(key).into_iter().next();
        let Some(previous) = previous else {
            self.add_path_argument(key, value);
            return;
        };
        self.args_path.set_index(key, 0, value);
        match self.args.get(key).iter().position(|arg| *arg == previous) {
            Some(index) => self.args.set_index(key, index, value),
            None => self.args.add(key, value),
        }
    }

    /// Adds a response body argument to RESPONSE_ARGS, within the argument limit as
    /// [`Transaction::add_get_argument`] does.
    pub fn add_response_argument(&mut self, key: &str, value: &str) {
        if self.within_argument_limit(self.response_args.value_count()) {
            self.response_args.add(key, value);
        }
    }

    /// Whether a collection holding `values` values can take one more; sets
    /// ARGUMENTS_LIMIT_REACHED if not.
    fn within_argument_limit(&mut self, values: usize) -> bool {
        let within = values < self.config.argument_limit;
        if !within {
            self.arguments_limit_reached.set("1");
        }
        within
    }

    /// Get request body limit.
    pub fn request_body_limit(&self) -> i64 {
        self.request_body_limit
    }

    /// Set force request body variable (used by ctl:forceRequestBodyVariable).
    pub fn set_force_request_body_variable(&mut self, enabled: bool) {
        self.force_request_body_variable = enabled;
    }

    /// Get force request body variable status.
    pub fn force_request_body_variable(&self) -> bool {
        self.force_request_body_variable
    }

    /// Audit logging mode of this transaction; the library writes no audit log, so this
    /// is for the embedder.
    pub fn audit_engine(&self) -> AuditEngineStatus {
        self.audit_engine
    }

    /// Set the audit logging mode (used by ctl:auditEngine).
    pub fn set_audit_engine(&mut self, status: AuditEngineStatus) {
        self.audit_engine = status;
    }

    /// Audit log parts of this transaction, `A` and `Z` included.
    pub fn audit_log_parts(&self) -> &[AuditLogPart] {
        &self.audit_log_parts
    }

    /// Set the audit log parts (used by ctl:auditLogParts).
    pub fn set_audit_log_parts(&mut self, parts: AuditLogParts) {
        self.audit_log_parts = parts;
    }

    /// Debug log verbosity of this transaction, 0 to 9; the library writes no debug log,
    /// so this is for the embedder.
    pub fn debug_log_level(&self) -> u8 {
        self.debug_log_level
    }

    /// Set the debug log verbosity (used by ctl:debugLogLevel).
    pub fn set_debug_log_level(&mut self, level: u8) {
        self.debug_log_level = level;
    }

    /// Set response body access (used by ctl:responseBodyAccess).
    pub fn set_response_body_access(&mut self, enabled: bool) {
        self.response_body_access = enabled;
    }

    /// Get response body access status.
    pub fn response_body_access(&self) -> bool {
        self.response_body_access
    }

    /// Set response body limit (used by ctl:responseBodyLimit).
    pub fn set_response_body_limit(&mut self, limit: i64) {
        self.response_body_limit = limit;
    }

    /// Get response body limit.
    pub fn response_body_limit(&self) -> i64 {
        self.response_body_limit
    }

    /// Set force response body variable (used by ctl:forceResponseBodyVariable).
    pub fn set_force_response_body_variable(&mut self, enabled: bool) {
        self.force_response_body_variable = enabled;
    }

    /// Get force response body variable status.
    pub fn force_response_body_variable(&self) -> bool {
        self.force_response_body_variable
    }

    /// Get last processed phase.
    pub fn last_phase(&self) -> Option<RulePhase> {
        self.last_phase
    }

    // ===== Flow Control & Interruption =====

    /// Get the current interruption, if any.
    pub fn interruption(&self) -> Option<&Interruption> {
        self.interruption.as_ref()
    }

    /// Set an interruption (used for testing and internal rule actions).
    pub fn set_interruption(&mut self, interruption: Option<Interruption>) {
        self.interruption = interruption;
    }

    /// Get the skip counter (number of rules to skip).
    pub fn skip(&self) -> i32 {
        self.skip
    }

    /// Set the skip counter (used by skip action).
    pub fn set_skip(&mut self, count: i32) {
        self.skip = count;
    }

    /// Get the skip_after marker.
    pub fn skip_after(&self) -> &str {
        &self.skip_after
    }

    /// Set the skip_after marker (used by skipAfter action).
    pub fn set_skip_after(&mut self, marker: impl Into<String>) {
        self.skip_after = marker.into();
    }

    // ===== HTTP Processing Methods =====

    /// Process connection information (Phase 1).
    ///
    /// Populates connection-level variables:
    /// - REMOTE_ADDR, REMOTE_PORT
    /// - SERVER_ADDR, SERVER_PORT
    ///
    /// # Example
    ///
    /// ```
    /// use coraza::transaction::Transaction;
    ///
    /// let mut tx = Transaction::new("tx-1");
    /// tx.process_connection("192.168.1.100", 54321, "10.0.0.1", 8080);
    /// ```
    pub fn process_connection(
        &mut self,
        client_addr: &str,
        client_port: u16,
        server_addr: &str,
        server_port: u16,
    ) {
        // Prevent duplicate processing - connection can only be processed once
        // Check if connection variables are already set
        if !self.remote_addr.get().is_empty() {
            return;
        }

        self.remote_addr.set(client_addr);
        self.remote_port.set(client_port.to_string());
        self.server_addr.set(server_addr);
        self.server_port.set(server_port.to_string());
    }

    /// Set the server name.
    ///
    /// Should be called before process_request_headers().
    ///
    /// # Example
    ///
    /// ```
    /// use coraza::transaction::Transaction;
    ///
    /// let mut tx = Transaction::new("tx-1");
    /// tx.set_server_name("example.com");
    /// ```
    pub fn set_server_name(&mut self, name: impl Into<String>) {
        self.server_name.set(name);
    }

    /// Process URI and populate request variables.
    ///
    /// Populates:
    /// - REQUEST_METHOD, REQUEST_PROTOCOL, REQUEST_URI_RAW, REQUEST_LINE
    /// - REQUEST_URI, REQUEST_FILENAME, REQUEST_BASENAME, QUERY_STRING
    /// - ARGS_GET (by parsing query string)
    ///
    /// # Example
    ///
    /// ```
    /// use coraza::transaction::Transaction;
    ///
    /// let mut tx = Transaction::new("tx-1");
    /// tx.process_uri("/api/users?id=123&name=admin", "GET", "HTTP/1.1");
    ///
    /// // Check populated variables
    /// assert_eq!(tx.args_get().get("id"), vec!["123"]);
    /// assert_eq!(tx.args_get().get("name"), vec!["admin"]);
    /// ```
    pub fn process_uri(&mut self, uri: &str, method: &str, http_version: &str) {
        self.request_method.set(method);
        self.request_protocol.set(http_version);
        self.request_uri_raw.set(uri);
        self.request_line
            .set(format!("{} {} {}", method, uri, http_version));

        // Remove anchor if present
        let uri_without_anchor = if let Some(anchor_pos) = uri.find('#') {
            &uri[..anchor_pos]
        } else {
            uri
        };

        // Split into path and query string
        let (path, query) = if let Some(query_pos) = uri_without_anchor.find('?') {
            let path = &uri_without_anchor[..query_pos];
            let query = &uri_without_anchor[query_pos + 1..];
            (path, query)
        } else {
            (uri_without_anchor, "")
        };

        // The path and query string, as in ModSecurity: the request URI without fragment
        self.request_uri.set(uri_without_anchor);

        // As in Go Coraza, the URL's path, decoded, or the raw path if it isn't one
        let filename = match request_uri_path(uri_without_anchor) {
            Some(path) => decode_path(path),
            None => {
                self.uri_parse_error.set("1");
                path.to_string()
            }
        };
        // After the last separator, unless the path ends with it, as in Go Coraza
        let basename = match filename.rfind(['/', '\\']) {
            Some(last_slash) if last_slash + 1 < filename.len() => &filename[last_slash + 1..],
            _ => &filename,
        };
        self.request_basename.set(basename);
        self.request_filename.set(&filename);
        self.query_string.set(query);

        // Parse query string into ARGS_GET
        if !query.is_empty() {
            self.extract_get_arguments(query);
        }
    }

    /// Adds the arguments of a query string to ARGS_GET and ARGS.
    fn extract_get_arguments(&mut self, query: &str) {
        for (key, value) in crate::body_processors::urlencoded::parse_query(query) {
            self.add_get_argument(&key, &value);
        }
    }

    /// Add a request header.
    ///
    /// Handles special headers:
    /// - Content-Type: Sets appropriate body processor
    /// - Cookie: Parses and populates REQUEST_COOKIES
    ///
    /// # Example
    ///
    /// ```
    /// use coraza::transaction::Transaction;
    ///
    /// let mut tx = Transaction::new("tx-1");
    /// tx.add_request_header("User-Agent", "Mozilla/5.0");
    /// tx.add_request_header("Cookie", "session=abc123; user=admin");
    ///
    /// assert_eq!(tx.request_headers().get("user-agent"), vec!["Mozilla/5.0"]);
    /// assert_eq!(tx.request_cookies().get("session"), vec!["abc123"]);
    /// assert_eq!(tx.request_cookies().get("user"), vec!["admin"]);
    /// ```
    pub fn add_request_header(&mut self, key: &str, value: &str) {
        if key.is_empty() {
            return;
        }

        self.request_headers_mut().add(key, value);

        // Handle special headers
        let key_lower = key.to_lowercase();
        match key_lower.as_str() {
            "cookie" => self.parse_cookies(value),
            // Only the first Content-Type picks the processor, as in Go Coraza: letting a
            // later one choose would inspect the body differently from a backend that
            // reads the first (GHSA-w253-m66g-rx24)
            "content-type" if self.request_headers.get("content-type").len() == 1 => {
                if let Some(processor) = BodyProcessorKind::for_content_type(value) {
                    self.set_request_body_processor(processor);
                }
            }
            _ => {}
        }
    }

    /// Makes `processor` parse the request body (`REQBODY_PROCESSOR`), as
    /// `ctl:requestBodyProcessor` does. The first `Content-Type` request header selects
    /// the urlencoded or multipart one.
    pub fn set_request_body_processor(&mut self, processor: BodyProcessorKind) {
        self.reqbody_processor.set(processor.name());
    }

    /// Makes `processor` parse the response body (`RES_BODY_PROCESSOR`), as
    /// `ctl:responseBodyProcessor` does. Without one, the response body is stored in
    /// RESPONSE_BODY.
    pub fn set_response_body_processor(&mut self, processor: BodyProcessorKind) {
        self.res_body_processor.set(processor.name());
    }

    /// Parse cookie header value and populate REQUEST_COOKIES.
    fn parse_cookies(&mut self, cookie_header: &str) {
        for pair in cookie_header.split(';') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }

            if let Some(eq_pos) = pair.find('=') {
                let key = pair[..eq_pos].trim();
                let value = pair[eq_pos + 1..].trim();
                self.request_cookies_mut().add(key, value);
            }
        }
    }

    /// Add a response header.
    ///
    /// Handles special headers:
    /// - Content-Type: Sets RESPONSE_CONTENT_TYPE
    ///
    /// # Example
    ///
    /// ```
    /// use coraza::transaction::Transaction;
    ///
    /// let mut tx = Transaction::new("tx-1");
    /// tx.add_response_header("Content-Type", "application/json; charset=utf-8");
    ///
    /// // Note: RESPONSE_CONTENT_TYPE is not yet accessible, will be added later
    /// ```
    pub fn add_response_header(&mut self, key: &str, value: &str) {
        if key.is_empty() {
            return;
        }

        self.response_headers_mut().add(key, value);

        // Handle special headers
        let key_lower = key.to_lowercase();
        if key_lower.as_str() == "content-type" {
            // Extract just the MIME type (before the semicolon)
            let mime_type = value.split(';').next().unwrap_or(value).trim();
            self.response_content_type.set(mime_type);
        }
    }

    // ===== Phase Processing Methods =====

    /// Process request headers and evaluate Phase 1 rules.
    ///
    /// Should be called after all request headers have been added via
    /// `add_request_header()`. This triggers rule evaluation for Phase 1.
    ///
    /// Returns an interruption if a disruptive action was triggered.
    ///
    /// # Example
    ///
    /// ```
    /// use coraza::waf::Waf;
    /// use coraza::config::WafConfig;
    ///
    /// let waf = Waf::new(WafConfig::new()).unwrap();
    /// let mut tx = waf.new_transaction();
    ///
    /// tx.process_uri("/test", "GET", "HTTP/1.1");
    /// tx.add_request_header("Host", "example.com");
    /// tx.add_request_header("User-Agent", "Test");
    ///
    /// // Evaluate Phase 1 rules
    /// let interruption = tx.process_request_headers();
    /// assert!(interruption.is_none()); // No rules triggered
    /// ```
    pub fn process_request_headers(&mut self) -> Option<Interruption> {
        // Check if already processed
        if let Some(phase) = self.last_phase
            && phase >= RulePhase::RequestHeaders
        {
            return None;
        }

        // Update phase
        self.last_phase = Some(RulePhase::RequestHeaders);

        // Evaluate rules for Phase 1 (Request Headers)
        self.evaluate_rules(RulePhase::RequestHeaders);

        self.interruption.clone()
    }

    /// Stores the request body in REQUEST_BODY and parses it with the processor
    /// REQBODY_PROCESSOR names, if any.
    fn inspect_request_body(&mut self, body: &[u8]) {
        // Get Content-Type to determine body processor
        let content_type_values = self.request_headers().get("content-type");
        let content_type = content_type_values
            .first()
            .map(|s| s.as_str())
            .unwrap_or("");

        let mut processor = self
            .reqbody_processor
            .get()
            .parse::<BodyProcessorKind>()
            .ok();
        if processor.is_none() && self.force_request_body_variable {
            self.set_request_body_processor(BodyProcessorKind::UrlEncoded);
            processor = Some(BodyProcessorKind::UrlEncoded);
        }

        if let Some(processor) = processor {
            let options = BodyProcessorOptions {
                mime: content_type.to_string(),
                json_depth_limit: self.config.request_body_json_depth_limit,
                ..Default::default()
            };

            // A malformed body doesn't stop the transaction: rules see it in REQBODY_ERROR
            if let Err(e) = processor.process_request(body, self, &options) {
                self.reqbody_error.set("1");
                self.reqbody_error_msg
                    .set(format!("{}: {}", processor.name(), e));
                self.reqbody_processor_error.set("1");
                self.reqbody_processor_error_msg.set(e.to_string());
            }
        }
    }

    /// Process request body with appropriate body processor.
    ///
    /// This method:
    /// 1. Takes the body processor `REQBODY_PROCESSOR` names (set from Content-Type, or
    ///    by `ctl:requestBodyProcessor`)
    /// 2. Calls it to parse the body; the URLENCODED and RAW processors also keep the
    ///    body in REQUEST_BODY and REQUEST_BODY_LENGTH, as in Go Coraza and ModSecurity
    /// 3. Updates last_phase to RequestBody
    ///
    /// Returns an interruption if a disruptive action was triggered.
    ///
    /// # Example
    ///
    /// ```
    /// use coraza::transaction::Transaction;
    ///
    /// let mut tx = Transaction::new("tx-1");
    /// tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
    ///
    /// let body = b"username=admin&password=secret";
    /// let result = tx.process_request_body(body);
    ///
    /// // Body is parsed and ARGS_POST is populated
    /// assert_eq!(tx.args_post().get("username"), vec!["admin"]);
    /// assert_eq!(tx.args_post().get("password"), vec!["secret"]);
    /// ```
    pub fn process_request_body(&mut self, body: &[u8]) -> Result<Option<Interruption>, String> {
        // Check if already processed
        if let Some(phase) = self.last_phase
            && phase >= RulePhase::RequestBody
        {
            return Ok(None);
        }

        // As in Go Coraza, an empty body or one without access is left alone
        if self.request_body_access && !body.is_empty() {
            let limit = usize::try_from(self.request_body_limit).unwrap_or(0);
            let mut body = body;
            // As in Go Coraza, reaching the limit counts
            if body.len() >= limit {
                self.inbound_data_error.set("1");
                match self.config.request_body_limit_action {
                    BodyLimitAction::Reject => {
                        self.last_phase = Some(RulePhase::RequestBody);
                        return Ok(Some(self.interrupt_for_body_limit(413)));
                    }
                    BodyLimitAction::ProcessPartial => body = &body[..limit],
                }
            }
            self.inspect_request_body(body);
        }

        // Update phase
        self.last_phase = Some(RulePhase::RequestBody);

        // Evaluate rules for Phase 2 (Request Body)
        self.evaluate_rules(RulePhase::RequestBody);

        Ok(self.interruption.clone())
    }

    /// Process response headers and populate response variables.
    ///
    /// # Example
    ///
    /// ```
    /// use coraza::transaction::Transaction;
    ///
    /// let mut tx = Transaction::new("tx-1");
    /// tx.add_response_header("Content-Type", "application/json");
    ///
    /// let result = tx.process_response_headers(200, "HTTP/1.1");
    ///
    /// // Response variables are populated
    /// // (Note: Direct access to response_status not yet public)
    /// ```
    pub fn process_response_headers(
        &mut self,
        status_code: u16,
        protocol: &str,
    ) -> Option<Interruption> {
        // Check if already processed
        if let Some(phase) = self.last_phase
            && phase >= RulePhase::ResponseHeaders
        {
            return None;
        }

        // Populate response variables
        self.response_status.set(status_code.to_string());
        self.response_protocol.set(protocol);

        // Update phase
        self.last_phase = Some(RulePhase::ResponseHeaders);

        // Evaluate rules for Phase 3 (Response Headers)
        self.evaluate_rules(RulePhase::ResponseHeaders);

        self.interruption.clone()
    }

    /// Whether [`Transaction::process_response_body`] inspects the body, given response
    /// body access: its content type, as set by the `Content-Type` response header, is
    /// one of `SecResponseBodyMimeType`, or `ctl:forceResponseBodyVariable` is on.
    ///
    /// A connector can use it to stream other responses rather than buffer them.
    pub fn is_response_body_processable(&self) -> bool {
        self.force_response_body_variable
            || self
                .config
                .response_body_mime_types
                .iter()
                .any(|mime| mime.eq_ignore_ascii_case(self.response_content_type.get()))
    }

    /// Parses the response body with the processor RES_BODY_PROCESSOR names, or stores it
    /// in RESPONSE_BODY if none.
    fn inspect_response_body(&mut self, body: &[u8]) {
        match self.res_body_processor.get().parse::<BodyProcessorKind>() {
            Ok(processor) => {
                let options = BodyProcessorOptions {
                    json_depth_limit: self.config.response_body_json_depth_limit,
                    ..Default::default()
                };
                if let Err(e) = processor.process_response(body, self, &options) {
                    self.res_body_error.set("1");
                    self.res_body_error_msg
                        .set(format!("{}: {}", processor.name(), e));
                    self.res_body_processor_error.set("1");
                    self.res_body_processor_error_msg.set(e.to_string());
                }
            }
            // As in Go Coraza, the body is stored only when no processor parses it
            Err(_) => {
                self.response_body.set(String::from_utf8_lossy(body));
                self.response_content_length.set(body.len().to_string());
            }
        }
    }

    /// Interrupts the transaction for a body over its limit (`Reject`), as Go Coraza does:
    /// with `deny` and `status`, outside any rule.
    fn interrupt_for_body_limit(&mut self, status: u16) -> Interruption {
        let interruption = Interruption {
            rule_id: 0,
            action: "deny".to_string(),
            status,
            data: String::new(),
        };
        self.interruption = Some(interruption.clone());
        interruption
    }

    /// Process response body.
    ///
    /// # Example
    ///
    /// ```
    /// use coraza::transaction::Transaction;
    ///
    /// let mut tx = Transaction::new("tx-1");
    /// tx.add_response_header("Content-Type", "application/json");
    /// tx.process_response_headers(200, "HTTP/1.1");
    ///
    /// let body = b"{\"status\":\"ok\"}";
    /// let result = tx.process_response_body(body);
    /// ```
    pub fn process_response_body(&mut self, body: &[u8]) -> Option<Interruption> {
        // Check if already processed
        if let Some(phase) = self.last_phase
            && phase >= RulePhase::ResponseBody
        {
            return None;
        }

        if self.response_body_access && self.is_response_body_processable() {
            let limit = usize::try_from(self.response_body_limit).unwrap_or(0);
            let mut body = body;
            // As in Go Coraza, reaching the limit counts
            if body.len() >= limit {
                self.outbound_data_error.set("1");
                match self.config.response_body_limit_action {
                    BodyLimitAction::Reject => {
                        self.last_phase = Some(RulePhase::ResponseBody);
                        return Some(self.interrupt_for_body_limit(500));
                    }
                    BodyLimitAction::ProcessPartial => body = &body[..limit],
                }
            }
            self.inspect_response_body(body);
        }

        // Update phase
        self.last_phase = Some(RulePhase::ResponseBody);

        // Evaluate rules for Phase 4 (Response Body)
        self.evaluate_rules(RulePhase::ResponseBody);

        self.interruption.clone()
    }

    /// Process logging phase (final phase): runs its rules, then writes the transaction's
    /// audit log entry, as Go Coraza decides: always with `SecAuditEngine On`, and with
    /// `RelevantOnly` when a rule with `auditlog` matched or the status is one of
    /// `SecAuditLogRelevantStatus` (the interruption's, or the response's).
    ///
    /// # Errors
    ///
    /// If the audit log entry can't be written.
    ///
    /// # Example
    ///
    /// ```
    /// use coraza::transaction::Transaction;
    ///
    /// let mut tx = Transaction::new("tx-1");
    /// // ... process request and response ...
    /// tx.process_logging().unwrap();
    /// ```
    pub fn process_logging(&mut self) -> std::io::Result<()> {
        // Update phase
        self.last_phase = Some(RulePhase::Logging);

        // Evaluate rules for Phase 5 (Logging)
        // Note: Logging phase rules run even if transaction is disrupted
        self.evaluate_rules(RulePhase::Logging);

        let Some(logger) = self.audit_logger.clone() else {
            return Ok(());
        };
        let logged = match self.audit_engine {
            AuditEngineStatus::Off => false,
            AuditEngineStatus::On => true,
            AuditEngineStatus::RelevantOnly => {
                let status = match &self.interruption {
                    Some(interruption) => interruption.status.to_string(),
                    None => self.response_status.get().to_string(),
                };
                let audited = self.matched_rules.iter().any(|m| m.rule.audit_log);
                logger.is_relevant(audited, &status)
            }
        };
        if logged {
            logger.write(&self.audit_log())?;
        }
        Ok(())
    }

    /// The transaction's audit log entry, with the parts `SecAuditLogParts` (or
    /// `ctl:auditLogParts`) give it, as Go Coraza builds it.
    pub fn audit_log(&self) -> AuditLog {
        let since_epoch = self
            .started
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let at = UtcTime::from_unix(since_epoch.as_secs());
        let mut transaction = AuditTransaction {
            timestamp: format!(
                "{:04}/{:02}/{:02} {:02}:{:02}:{:02}",
                at.year, at.month, at.day, at.hour, at.minute, at.second
            ),
            unix_timestamp: i64::try_from(since_epoch.as_nanos()).unwrap_or(i64::MAX),
            id: self.unique_id.get().to_string(),
            client_ip: self.remote_addr.get().to_string(),
            client_port: self.remote_port.get().parse().unwrap_or(0),
            host_ip: self.server_addr.get().to_string(),
            host_port: self.server_port.get().parse().unwrap_or(0),
            server_id: self.server_name.get().to_string(),
            request: AuditRequest {
                method: self.request_method.get().to_string(),
                protocol: self.request_protocol.get().to_string(),
                uri: self.request_uri.get().to_string(),
                length: self.full_request_length.get().parse().unwrap_or(0),
                args: self
                    .args
                    .find_all()
                    .into_iter()
                    .map(|arg| (arg.key, arg.value))
                    .collect(),
                ..AuditRequest::default()
            },
            highest_severity: self.highest_severity.get().to_string(),
            is_interrupted: self.interruption.is_some(),
            ..AuditTransaction::default()
        };

        let parts = &self.audit_log_parts;
        let has = |part| parts.contains(&part);
        if has(AuditLogPart::RequestHeaders) {
            transaction.request.headers = Some(self.request_headers.entries());
        }
        if has(AuditLogPart::RequestBody) {
            transaction.request.body = self.request_body.get().to_string();
        }
        if has(AuditLogPart::UploadedFiles) {
            transaction.request.files = Some(
                self.files
                    .find_all()
                    .into_iter()
                    .map(|file| AuditFile {
                        size: self
                            .files_sizes
                            .get(&file.value)
                            .first()
                            .and_then(|size| size.parse().ok())
                            .unwrap_or(0),
                        mime: mime_type_of(&file.value).to_string(),
                        name: file.value,
                    })
                    .collect(),
            );
        }
        if has(AuditLogPart::IntermediaryResponseBody) || has(AuditLogPart::ResponseHeaders) {
            let mut response = AuditResponse::default();
            if has(AuditLogPart::IntermediaryResponseBody) {
                response.body = self.response_body.get().to_string();
            }
            if has(AuditLogPart::ResponseHeaders) {
                response.status = self.response_status.get().parse().unwrap_or(0);
                response.headers = Some(self.response_headers.entries());
            }
            transaction.response = Some(response);
        }
        let trailer = has(AuditLogPart::Trailer);
        if trailer {
            let started_ns = transaction.unix_timestamp;
            let elapsed = std::time::SystemTime::now()
                .duration_since(self.started)
                .map_or(0, |elapsed| elapsed.as_nanos());
            transaction.producer = Some(AuditProducer {
                rule_engine: self.rule_engine.as_str().to_string(),
                stopwatch: format!(
                    "{started_ns} {elapsed}; combined=0, p1=0, p2=0, p3=0, p4=0, p5=0"
                ),
                rulesets: self.config.component_names.clone(),
                ..AuditProducer::default()
            });
        }

        let audited = self.matched_rules.iter().filter(|m| m.rule.audit_log);
        let messages = if has(AuditLogPart::RulesMatched) {
            audited
                .flat_map(|matched| {
                    matched.matches.iter().map(move |data| {
                        let rule = &matched.rule;
                        AuditMessage {
                            actionset: self.config.component_names.join(" "),
                            message: data.message.clone(),
                            error_message: if trailer {
                                matched.error_log()
                            } else {
                                String::new()
                            },
                            data: AuditMessageData {
                                file: rule.file.clone(),
                                line: rule.line,
                                id: rule.id,
                                rev: rule.rev.clone(),
                                msg: data.message.clone(),
                                data: data.data.clone(),
                                severity: rule.severity.map_or(-1, |s| s.as_int() as i8),
                                ver: rule.ver.clone(),
                                maturity: rule.maturity,
                                accuracy: rule.accuracy,
                                tags: rule.tags.clone(),
                                raw: rule.raw.clone(),
                            },
                        }
                    })
                })
                .collect()
        } else if trailer {
            audited
                .map(|matched| AuditMessage {
                    error_message: matched.error_log(),
                    ..AuditMessage::default()
                })
                .collect()
        } else {
            Vec::new()
        };

        AuditLog {
            parts: self.audit_log_parts.clone(),
            transaction,
            messages,
        }
    }

    // ===== CTL Action Methods =====

    /// Removes a rule by ID for this transaction only.
    ///
    /// Rules with the specified ID will be skipped during rule evaluation
    /// for this transaction. This does not affect the WAF's rule set or
    /// other transactions.
    ///
    /// Called by `ctl:ruleRemoveById` action.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::transaction::Transaction;
    ///
    /// let mut tx = Transaction::new("tx-1");
    /// tx.remove_rule_by_id(123);
    /// // Rule 123 will be skipped for this transaction
    /// ```
    pub fn remove_rule_by_id(&mut self, id: i32) {
        self.rule_remove_by_id.insert(id);
    }

    /// Removes a specific variable target from a rule for this transaction only.
    ///
    /// The specified variable will be excluded from the rule's targets
    /// during evaluation for this transaction.
    ///
    /// Called by `ctl:ruleRemoveTargetById`, `ctl:ruleRemoveTargetByTag`,
    /// and `ctl:ruleRemoveTargetByMsg` actions.
    ///
    /// # Arguments
    ///
    /// * `rule_id` - The rule ID to modify
    /// * `variable` - The variable type to exclude
    /// * `key` - The specific key to exclude (e.g., "user-agent" for HEADERS)
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::transaction::Transaction;
    /// use coraza::RuleVariable;
    ///
    /// let mut tx = Transaction::new("tx-1");
    ///
    /// // Exclude ARGS:username from rule 123
    /// tx.remove_rule_target_by_id(123, RuleVariable::Args, "username");
    ///
    /// // Exclude REQUEST_HEADERS:User-Agent from rule 456
    /// tx.remove_rule_target_by_id(456, RuleVariable::RequestHeaders, "user-agent");
    /// ```
    pub fn remove_rule_target_by_id(
        &mut self,
        rule_id: i32,
        variable: RuleVariable,
        key: impl Into<String>,
    ) {
        self.rule_remove_target_by_id
            .entry(rule_id)
            .or_default()
            .push((variable, key.into()));
    }

    /// Checks if a rule should be skipped for this transaction.
    ///
    /// Returns true if the rule was excluded via `ctl:ruleRemoveById`.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::transaction::Transaction;
    ///
    /// let mut tx = Transaction::new("tx-1");
    /// tx.remove_rule_by_id(123);
    ///
    /// assert!(tx.is_rule_removed(123));
    /// assert!(!tx.is_rule_removed(456));
    /// ```
    pub fn is_rule_removed(&self, rule_id: i32) -> bool {
        self.rule_remove_by_id.contains(&rule_id)
    }

    /// Checks if a specific variable target is excluded from a rule.
    ///
    /// Returns true if the variable/key combination was excluded via
    /// `ctl:ruleRemoveTargetById` actions.
    ///
    /// # Examples
    ///
    /// ```
    /// use coraza::transaction::Transaction;
    /// use coraza::RuleVariable;
    ///
    /// let mut tx = Transaction::new("tx-1");
    /// tx.remove_rule_target_by_id(123, RuleVariable::Args, "id");
    ///
    /// assert!(tx.is_rule_target_removed(123, RuleVariable::Args, "id"));
    /// assert!(!tx.is_rule_target_removed(123, RuleVariable::Args, "other"));
    /// ```
    pub fn is_rule_target_removed(&self, rule_id: i32, variable: RuleVariable, key: &str) -> bool {
        if let Some(targets) = self.rule_remove_target_by_id.get(&rule_id) {
            targets.iter().any(|(v, k)| *v == variable && k == key)
        } else {
            false
        }
    }
}

/// State that operators and actions read and change while a rule is evaluated.
impl Transaction {
    /// Value of a variable, as macros (`%{VAR.key}`) expand it: the value of a
    /// single-value variable (with `key` `None`), or the first value of `key` in a
    /// collection. `None` if the variable isn't set or not available.
    pub fn get_variable(&self, variable: RuleVariable, key: Option<&str>) -> Option<String> {
        match (self.collection(variable)?, key) {
            (VariableCollection::Single(single), None) => Some(single.get().to_string()),
            (VariableCollection::Map(map), Some(key)) => map.get(key).first().cloned(),
            (VariableCollection::Names(_, map), Some(key)) => {
                (!map.get(key).is_empty()).then(|| key.to_string())
            }
            _ => None,
        }
    }

    /// Whether operators currently store their captures (see [`Transaction::set_capturing`]).
    pub fn capturing(&self) -> bool {
        self.capturing
    }

    /// Stores capture `index` (0-9) in `TX.<index>` if capturing is on; otherwise does nothing.
    pub fn capture_field(&mut self, index: usize, value: &str) {
        if self.capturing {
            self.tx.set(&index.to_string(), vec![value.to_string()]);
        }
    }

    /// Interrupts the transaction on behalf of a disruptive action of `rule_id`.
    pub(crate) fn interrupt(&mut self, rule_id: i32, action: &str, status: i32, data: &str) {
        self.interruption = Some(Interruption {
            rule_id: rule_id as usize,
            action: action.to_string(),
            status: status as u16,
            data: data.to_string(),
        });
    }

    /// Records an `allow` action; see [`AllowType`] for which rules it skips.
    pub(crate) fn set_allow_type(&mut self, allow_type: AllowType) {
        self.allow_type = allow_type;
    }

    /// Whether an earlier `allow` action skips the rules of `phase` still to be evaluated.
    pub(crate) fn is_allowed(&self, phase: RulePhase) -> bool {
        match self.allow_type {
            AllowType::Unset => false,
            AllowType::All | AllowType::Phase => phase != RulePhase::Logging,
            AllowType::Request => {
                matches!(phase, RulePhase::RequestHeaders | RulePhase::RequestBody)
            }
        }
    }

    /// Ends an `allow:phase` once the phase that triggered it has been evaluated.
    pub(crate) fn end_phase_allow(&mut self) {
        if self.allow_type == AllowType::Phase {
            self.allow_type = AllowType::Unset;
        }
    }

    /// The WAF's rules, for `ctl` actions that exclude rules by tag or message; `None`
    /// for a transaction not created by a WAF.
    pub(crate) fn rules(&self) -> Option<&Arc<RuleGroup>> {
        self.rules.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_transaction_new() {
        let tx = Transaction::new("tx-001");
        assert_eq!(tx.id(), "tx-001");
    }

    #[test]
    fn test_transaction_args() {
        let mut tx = Transaction::new("tx-002");
        tx.args_get_mut().add("id", "123");
        tx.args_get_mut().add("name", "test");

        let id_vals = tx.args_get().get("id");
        assert_eq!(id_vals, vec!["123"]);

        let name_vals = tx.args_get().get("name");
        assert_eq!(name_vals, vec!["test"]);
    }

    #[test]
    fn test_transaction_headers() {
        let mut tx = Transaction::new("tx-003");
        tx.request_headers_mut().add("User-Agent", "Mozilla");
        tx.request_headers_mut()
            .add("Content-Type", "application/json");

        // Case-insensitive lookup
        let ua = tx.request_headers().get("user-agent");
        assert_eq!(ua, vec!["Mozilla"]);
    }

    #[test]
    fn test_transaction_single_values() {
        let mut tx = Transaction::new("tx-004");
        tx.set_request_uri("/api/users");
        tx.set_request_method("GET");
        tx.set_remote_addr("127.0.0.1");

        assert_eq!(tx.request_uri.get(), "/api/users");
        assert_eq!(tx.request_method.get(), "GET");
        assert_eq!(tx.remote_addr.get(), "127.0.0.1");
    }

    #[test]
    fn test_transaction_state_get_variable() {
        let mut tx = Transaction::new("tx-005");
        tx.set_request_uri("/test");
        tx.args_get_mut().add("id", "456");

        // Get single-value variable
        let uri = tx.get_variable(RuleVariable::RequestURI, None);
        assert_eq!(uri, Some("/test".to_string()));

        // Get keyed variable
        let id = tx.get_variable(RuleVariable::ArgsGet, Some("id"));
        assert_eq!(id, Some("456".to_string()));

        // Missing key
        let missing = tx.get_variable(RuleVariable::ArgsGet, Some("missing"));
        assert_eq!(missing, None);
    }

    #[test]
    fn test_transaction_capturing() {
        let mut tx = Transaction::new("tx-006");
        assert!(!tx.capturing());

        tx.set_capturing(true);
        assert!(tx.capturing());

        tx.capture_field(0, "match1");
        tx.capture_field(5, "match6"); // Sparse indexing

        assert_eq!(tx.tx.get("0"), vec!["match1"]);
        assert!(tx.tx.get("1").is_empty());
        assert_eq!(tx.tx.get("5"), vec!["match6"]);

        // Captures are dropped while capturing is off
        tx.set_capturing(false);
        tx.capture_field(1, "ignored");
        assert!(tx.tx.get("1").is_empty());
    }

    #[test]
    fn test_process_connection() {
        let mut tx = Transaction::new("tx-007");
        tx.process_connection("192.168.1.100", 54321, "10.0.0.1", 8080);

        assert_eq!(tx.remote_addr.get(), "192.168.1.100");
        assert_eq!(tx.remote_port.get(), "54321");
        assert_eq!(tx.server_addr.get(), "10.0.0.1");
        assert_eq!(tx.server_port.get(), "8080");
    }

    #[test]
    fn test_set_server_name() {
        let mut tx = Transaction::new("tx-008");
        tx.set_server_name("example.com");

        assert_eq!(tx.server_name.get(), "example.com");
    }

    #[test]
    fn test_time_variables() {
        for (seconds, expected) in [
            (0, ["00:00:00", "1", "1", "1970", "4"]),
            (951_782_400, ["00:00:00", "29", "2", "2000", "2"]),
            (1_700_000_000, ["22:13:20", "14", "11", "2023", "2"]),
        ] {
            let time = TimeVariables::since_epoch(seconds);
            let actual = [&time.time, &time.day, &time.mon, &time.year, &time.wday]
                .map(|single| single.get().to_string());
            assert_eq!(actual, expected, "{seconds}");
            assert_eq!(time.epoch.get(), seconds.to_string());
        }
    }

    #[test]
    fn test_process_uri_simple() {
        let mut tx = Transaction::new("tx-009");
        tx.process_uri("/api/users", "GET", "HTTP/1.1");

        assert_eq!(tx.request_method.get(), "GET");
        assert_eq!(tx.request_protocol.get(), "HTTP/1.1");
        assert_eq!(tx.request_uri_raw.get(), "/api/users");
        assert_eq!(tx.request_line.get(), "GET /api/users HTTP/1.1");
        assert_eq!(tx.request_uri.get(), "/api/users");
        assert_eq!(tx.request_filename.get(), "/api/users");
        assert_eq!(tx.request_basename.get(), "users");
        assert_eq!(tx.query_string.get(), "");
    }

    #[test]
    fn test_process_uri_with_query() {
        let mut tx = Transaction::new("tx-010");
        tx.process_uri("/search?q=test&page=2", "POST", "HTTP/2.0");

        // REQUEST_URI keeps the query string, as in ModSecurity and Go Coraza
        assert_eq!(tx.request_uri.get(), "/search?q=test&page=2");
        assert_eq!(tx.request_filename.get(), "/search");
        assert_eq!(tx.request_basename.get(), "search");
        assert_eq!(tx.query_string.get(), "q=test&page=2");

        // Check ARGS_GET populated
        assert_eq!(tx.args_get().get("q"), vec!["test"]);
        assert_eq!(tx.args_get().get("page"), vec!["2"]);
    }

    #[test]
    fn test_process_uri_decodes_the_path() {
        // As Go Coraza: the path of the URL `url.ParseRequestURI` reads, %-decoded ('+'
        // stays), or the raw path when the URI doesn't parse
        for (uri, filename, basename) in [
            (
                "/path/with/%3Bid%20-a+b?x=%3B",
                "/path/with/;id -a+b",
                ";id -a+b",
            ),
            ("http://example.com/a%2Fb/c?x", "/a/b/c", "c"),
            ("http://example.com", "", ""),
            ("/bad/%zz", "/bad/%zz", "%zz"),
            ("/dir/", "/dir/", "/dir/"),
        ] {
            let mut tx = Transaction::new("tx");
            tx.process_uri(uri, "GET", "HTTP/1.1");
            assert_eq!(tx.request_filename.get(), filename, "{uri}");
            assert_eq!(tx.request_basename.get(), basename, "{uri}");
        }
    }

    #[test]
    fn test_process_uri_with_anchor() {
        let mut tx = Transaction::new("tx-011");
        tx.process_uri("/page?a=1#section", "GET", "HTTP/1.1");

        assert_eq!(tx.request_uri_raw.get(), "/page?a=1#section");
        assert_eq!(tx.request_uri.get(), "/page?a=1"); // Anchor removed
    }

    #[test]
    fn test_process_uri_url_decoding() {
        let mut tx = Transaction::new("tx-012");
        tx.process_uri("/search?q=hello+world&tag=%23rust", "GET", "HTTP/1.1");

        // Check URL decoding
        assert_eq!(tx.args_get().get("q"), vec!["hello world"]); // + -> space
        assert_eq!(tx.args_get().get("tag"), vec!["#rust"]); // %23 -> #
    }

    #[test]
    fn test_process_uri_key_without_value() {
        let mut tx = Transaction::new("tx-013");
        tx.process_uri("/api?flag", "GET", "HTTP/1.1");

        assert_eq!(tx.args_get().get("flag"), vec![""]);
    }

    #[test]
    fn test_add_request_header() {
        let mut tx = Transaction::new("tx-014");
        tx.add_request_header("User-Agent", "Mozilla/5.0");
        tx.add_request_header("Content-Type", "application/json");

        assert_eq!(tx.request_headers().get("user-agent"), vec!["Mozilla/5.0"]);
        assert_eq!(
            tx.request_headers().get("content-type"),
            vec!["application/json"]
        );
    }

    #[test]
    fn test_add_request_header_cookie() {
        let mut tx = Transaction::new("tx-015");
        tx.add_request_header("Cookie", "session=abc123; user=admin; theme=dark");

        assert_eq!(tx.request_cookies().get("session"), vec!["abc123"]);
        assert_eq!(tx.request_cookies().get("user"), vec!["admin"]);
        assert_eq!(tx.request_cookies().get("theme"), vec!["dark"]);
    }

    #[test]
    fn test_add_request_header_empty_key() {
        let mut tx = Transaction::new("tx-016");
        tx.add_request_header("", "value");

        // Should not add header with empty key
        assert!(tx.request_headers().find_all().is_empty());
    }

    #[test]
    fn test_parse_cookies_with_spaces() {
        let mut tx = Transaction::new("tx-017");
        tx.add_request_header("Cookie", " session = abc123 ; user = admin ");

        assert_eq!(tx.request_cookies().get("session"), vec!["abc123"]);
        assert_eq!(tx.request_cookies().get("user"), vec!["admin"]);
    }

    #[test]
    fn test_add_response_header() {
        let mut tx = Transaction::new("tx-018");
        tx.add_response_header("Content-Type", "application/json; charset=utf-8");
        tx.add_response_header("Server", "nginx/1.18");

        assert_eq!(
            tx.response_headers().get("content-type"),
            vec!["application/json; charset=utf-8"]
        );
        assert_eq!(tx.response_headers().get("server"), vec!["nginx/1.18"]);

        // RESPONSE_CONTENT_TYPE should have just the MIME type
        assert_eq!(tx.response_content_type.get(), "application/json");
    }

    #[test]
    fn test_add_response_header_empty_key() {
        let mut tx = Transaction::new("tx-019");
        tx.add_response_header("", "value");

        // Should not add header with empty key
        assert!(tx.response_headers().find_all().is_empty());
    }

    #[test]
    fn test_process_request_body_urlencoded() {
        let mut tx = Transaction::new("tx-020");
        tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");

        let body = b"username=admin&password=secret&role=admin";
        let result = tx.process_request_body(body);

        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // No interruption

        // Check ARGS_POST populated
        assert_eq!(tx.args_post().get("username"), vec!["admin"]);
        assert_eq!(tx.args_post().get("password"), vec!["secret"]);
        assert_eq!(tx.args_post().get("role"), vec!["admin"]);

        // Check REQUEST_BODY stored
        assert_eq!(
            tx.request_body.get(),
            "username=admin&password=secret&role=admin"
        );
        assert_eq!(tx.request_body_length.get(), "41");

        // Check phase updated
        assert_eq!(tx.last_phase, Some(RulePhase::RequestBody));
    }

    #[test]
    fn test_process_request_body_json() {
        let mut tx = Transaction::new("tx-021");
        tx.add_request_header("Content-Type", "application/json");
        // As in Go, the content type alone selects no JSON or XML processor
        tx.set_request_body_processor(BodyProcessorKind::Json);

        let body = br#"{"user": "admin", "id": 123}"#;
        let result = tx.process_request_body(body);

        assert!(result.is_ok());

        // Check JSON flattening in ARGS_POST
        assert_eq!(tx.args_post().get("json.user"), vec!["admin"]);
        assert_eq!(tx.args_post().get("json.id"), vec!["123"]);
    }

    #[test]
    fn test_process_request_body_xml() {
        let mut tx = Transaction::new("tx-022");
        tx.add_request_header("Content-Type", "application/xml");
        // As in Go, the content type alone selects no JSON or XML processor
        tx.set_request_body_processor(BodyProcessorKind::Xml);

        let body = br#"<user name="admin"><id>123</id></user>"#;
        let result = tx.process_request_body(body);

        assert!(result.is_ok());

        // Check REQUEST_XML populated
        assert_eq!(tx.request_xml.get("//@*"), vec!["admin"]);
        assert_eq!(tx.request_xml.get("/*"), vec!["123"]);
    }

    #[test]
    fn test_process_request_body_multipart() {
        let mut tx = Transaction::new("tx-023");
        tx.add_request_header(
            "Content-Type",
            "multipart/form-data; boundary=----WebKitFormBoundary",
        );

        let body = b"------WebKitFormBoundary\r\n\
Content-Disposition: form-data; name=\"field1\"\r\n\
\r\n\
value1\r\n\
------WebKitFormBoundary--\r\n";

        let result = tx.process_request_body(body);

        assert!(result.is_ok());

        // Check ARGS_POST populated from multipart
        assert_eq!(tx.args_post().get("field1"), vec!["value1"]);
    }

    #[test]
    fn test_process_request_body_no_content_type() {
        let mut tx = Transaction::new("tx-024");
        // No Content-Type header

        let body = b"some data";
        let result = tx.process_request_body(body);

        assert!(result.is_ok());

        // Without a body processor, as in Go Coraza and ModSecurity, the body is
        // neither parsed nor kept in REQUEST_BODY
        assert_eq!(tx.request_body.get(), "");
        assert_eq!(tx.request_body_length.get(), "0");
    }

    #[test]
    fn test_request_body_variable_only_from_urlencoded_and_raw() {
        let body = br#"{"a":"b"}"#;
        for (content_type, forced, request_body) in [
            ("application/x-www-form-urlencoded", false, r#"{"a":"b"}"#),
            ("text/plain", true, r#"{"a":"b"}"#),
            ("text/plain", false, ""),
            ("application/json", false, ""),
        ] {
            let mut tx = Transaction::new("tx");
            tx.add_request_header("Content-Type", content_type);
            tx.force_request_body_variable = forced;
            tx.process_request_headers();
            tx.process_request_body(body).unwrap();
            assert_eq!(tx.request_body.get(), request_body, "{content_type}");
            let length = if request_body.is_empty() { "0" } else { "9" };
            assert_eq!(tx.request_body_length.get(), length, "{content_type}");
        }
    }

    #[test]
    fn test_process_request_body_already_processed() {
        let mut tx = Transaction::new("tx-025");
        tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");

        let body1 = b"key1=value1";
        tx.process_request_body(body1).unwrap();

        // Try to process again
        let body2 = b"key2=value2";
        tx.process_request_body(body2).unwrap();

        // Should still have first body only
        assert_eq!(tx.request_body.get(), "key1=value1");
        assert_eq!(tx.args_post().get("key1"), vec!["value1"]);
        assert!(tx.args_post().get("key2").is_empty());
    }

    #[test]
    fn test_process_response_headers() {
        let mut tx = Transaction::new("tx-026");
        tx.add_response_header("Content-Type", "application/json; charset=utf-8");
        tx.add_response_header("Server", "nginx");

        let result = tx.process_response_headers(200, "HTTP/1.1");

        assert!(result.is_none()); // No interruption

        // Check variables populated
        assert_eq!(tx.response_status.get(), "200");
        assert_eq!(tx.response_protocol.get(), "HTTP/1.1");
        assert_eq!(tx.response_content_type.get(), "application/json");

        // Check phase updated
        assert_eq!(tx.last_phase, Some(RulePhase::ResponseHeaders));
    }

    #[test]
    fn test_process_response_headers_already_processed() {
        let mut tx = Transaction::new("tx-027");

        tx.process_response_headers(200, "HTTP/1.1");

        // Try to process again
        tx.process_response_headers(500, "HTTP/2.0");

        // Should still have first values
        assert_eq!(tx.response_status.get(), "200");
        assert_eq!(tx.response_protocol.get(), "HTTP/1.1");
    }

    /// A transaction inspecting `application/json` response bodies.
    fn json_response_transaction(id: &str) -> Transaction {
        let mut tx = Transaction::new(id);
        tx.set_config(Arc::new(WafConfig {
            response_body_access: true,
            response_body_mime_types: vec!["application/json".to_string()],
            ..WafConfig::default()
        }));
        tx.add_response_header("Content-Type", "application/json");
        tx
    }

    #[test]
    fn test_process_response_body() {
        let mut tx = json_response_transaction("tx-028");
        tx.process_response_headers(200, "HTTP/1.1");

        let body = b"{\"status\":\"ok\",\"data\":123}";
        let result = tx.process_response_body(body);

        assert!(result.is_none()); // No interruption

        // Check body stored
        assert_eq!(tx.response_body.get(), r#"{"status":"ok","data":123}"#);
        assert_eq!(tx.response_content_length.get(), "26");

        // Check phase updated
        assert_eq!(tx.last_phase, Some(RulePhase::ResponseBody));
    }

    #[test]
    fn test_process_response_body_already_processed() {
        let mut tx = json_response_transaction("tx-029");
        tx.process_response_headers(200, "HTTP/1.1");

        tx.process_response_body(b"body1");

        // Try to process again
        tx.process_response_body(b"body2");

        // Should still have first body
        assert_eq!(tx.response_body.get(), "body1");
    }

    #[test]
    fn test_response_body_of_unlisted_type_is_not_stored() {
        let mut tx = json_response_transaction("tx-029b");
        tx.add_response_header("Content-Type", "image/png");
        tx.process_response_headers(200, "HTTP/1.1");

        tx.process_response_body(b"\x89PNG");

        assert_eq!(tx.response_body.get(), "");
        assert_eq!(tx.last_phase, Some(RulePhase::ResponseBody));
    }

    #[test]
    fn test_process_logging() {
        let mut tx = Transaction::new("tx-030");

        tx.process_logging().unwrap();

        // Check phase updated
        assert_eq!(tx.last_phase, Some(RulePhase::Logging));
    }

    #[test]
    fn test_interruption_struct() {
        let interruption = Interruption {
            rule_id: 123,
            action: "deny".to_string(),
            status: 403,
            data: String::new(),
        };

        assert_eq!(interruption.rule_id, 123);
        assert_eq!(interruption.action, "deny");
        assert_eq!(interruption.status, 403);
    }

    #[test]
    fn test_phase_progression() {
        let mut tx = Transaction::new("tx-031");

        // Initially no phase
        assert_eq!(tx.last_phase, None);

        // Process connection
        tx.process_connection("127.0.0.1", 54321, "10.0.0.1", 8080);
        // Connection processing doesn't update phase (it's before phase 1)

        // Process request body
        tx.add_request_header("Content-Type", "application/x-www-form-urlencoded");
        tx.process_request_body(b"key=value").unwrap();
        assert_eq!(tx.last_phase, Some(RulePhase::RequestBody));

        // Process response headers
        tx.process_response_headers(200, "HTTP/1.1");
        assert_eq!(tx.last_phase, Some(RulePhase::ResponseHeaders));

        // Process response body
        tx.process_response_body(b"response");
        assert_eq!(tx.last_phase, Some(RulePhase::ResponseBody));

        // Process logging
        tx.process_logging().unwrap();
        assert_eq!(tx.last_phase, Some(RulePhase::Logging));
    }

    #[test]
    fn test_query_arguments_decode_utf8() {
        let mut tx = Transaction::new("utf8");
        tx.process_uri("/?name=%C3%A9t%C3%A9&q=a+b", "GET", "HTTP/1.1");

        assert_eq!(tx.args_get().get("name"), vec!["été"]);
        assert_eq!(tx.args().get("q"), vec!["a b"]);
    }
}
