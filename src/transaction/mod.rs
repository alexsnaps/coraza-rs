//! Transaction management for request/response processing.
//!
//! A transaction represents a single HTTP request/response pair and holds
//! all the data (headers, arguments, cookies, etc.) that rules operate on.

pub mod variables;

use std::sync::Arc;

use crate::RuleVariable;
use crate::collection::{Keyed, Map, MapCollection, Single, SingleCollection};
use crate::operators::TransactionState;
use crate::rules::RuleGroup;
use crate::types::{RuleEngineStatus, RulePhase};

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

/// A transaction represents a single HTTP request/response being processed.
///
/// Transactions store all request and response data in collections that
/// can be queried by rules. Each transaction is isolated and not thread-safe.
///
/// # Examples
///
/// ```
/// use coraza::transaction::Transaction;
/// use coraza::collection::{Keyed, MapCollection};
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
    /// Transaction ID
    id: String,

    /// Combined ARGS (GET + POST parameters)
    args: Map,

    /// GET/query parameters
    args_get: Map,

    /// POST body parameters
    args_post: Map,

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

    /// FILES - Original file names from multipart/form-data
    pub(crate) files: Map,

    /// FILES_TMP_NAMES - Temporary file paths for uploaded files
    pub(crate) files_tmp_names: Map,

    /// FILES_SIZES - Sizes of uploaded files
    pub(crate) files_sizes: Map,

    /// FILES_NAMES - Form field names for uploaded files
    pub(crate) files_names: Map,

    /// FILES_COMBINED_SIZE - Total size of all uploaded files
    pub(crate) files_combined_size: Single,

    /// MULTIPART_PART_HEADERS - Headers from each multipart part
    pub(crate) multipart_part_headers: Map,

    /// MULTIPART_STRICT_ERROR - Set to "1" when multipart parsing fails
    pub(crate) multipart_strict_error: Single,

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

    // ===== CTL-Modifiable Settings =====
    /// Rule engine status (controlled by ctl:ruleEngine)
    pub(crate) rule_engine: RuleEngineStatus,

    /// Request body access enabled (controlled by ctl:requestBodyAccess)
    pub(crate) request_body_access: bool,

    /// Request body size limit in bytes (controlled by ctl:requestBodyLimit)
    pub(crate) request_body_limit: i64,

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

    /// Captured values from operators (rx, pm)
    captures: Vec<Option<String>>,

    /// Whether capturing is enabled
    capturing: bool,

    // ===== CTL Runtime Exclusions =====
    /// Rules with these IDs will be skipped for this transaction
    /// (set by ctl:ruleRemoveById, ctl:ruleRemoveByTag, ctl:ruleRemoveByMsg)
    rule_remove_by_id: std::collections::BTreeSet<i32>,

    /// Variable exclusions per rule ID
    /// (set by ctl:ruleRemoveTargetById, ctl:ruleRemoveTargetByTag, ctl:ruleRemoveTargetByMsg)
    /// Map: rule_id -> Vec<(variable, key)>
    rule_remove_target_by_id: std::collections::BTreeMap<i32, Vec<(RuleVariable, String)>>,

    /// Reference to WAF's rule group for CTL tag/msg-based exclusions
    /// Optional because transactions created via Transaction::new() don't have a WAF reference
    rules: Option<Arc<RuleGroup>>,
}

impl Default for Transaction {
    fn default() -> Self {
        Self::new("default")
    }
}

impl Transaction {
    /// Create a new transaction with the given ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            args: Map::new_case_sensitive(RuleVariable::Args),
            args_get: Map::new_case_sensitive(RuleVariable::ArgsGet),
            args_post: Map::new_case_sensitive(RuleVariable::ArgsPost),
            request_headers: Map::new(RuleVariable::RequestHeaders),
            request_cookies: Map::new(RuleVariable::RequestCookies),
            response_headers: Map::new(RuleVariable::ResponseHeaders),
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
            request_body_length: Single::new(RuleVariable::RequestBodyLength),
            files: Map::new_case_sensitive(RuleVariable::Files),
            files_tmp_names: Map::new_case_sensitive(RuleVariable::FilesTmpNames),
            files_sizes: Map::new_case_sensitive(RuleVariable::FilesSizes),
            files_names: Map::new_case_sensitive(RuleVariable::FilesNames),
            files_combined_size: Single::new(RuleVariable::FilesCombinedSize),
            multipart_part_headers: Map::new_case_sensitive(RuleVariable::MultipartPartHeaders),
            multipart_strict_error: Single::new(RuleVariable::MultipartStrictError),
            request_xml: Map::new_case_sensitive(RuleVariable::RequestXML),
            response_status: Single::new(RuleVariable::ResponseStatus),
            response_protocol: Single::new(RuleVariable::ResponseProtocol),
            response_content_type: Single::new(RuleVariable::ResponseContentType),
            response_content_length: Single::new(RuleVariable::ResponseContentLength),
            response_body: Single::new(RuleVariable::ResponseBody),
            response_args: Map::new_case_sensitive(RuleVariable::ResponseArgs),
            response_xml: Map::new_case_sensitive(RuleVariable::ResponseXML),
            rule_engine: RuleEngineStatus::On,
            request_body_access: true,
            request_body_limit: 131072, // 128KB default
            force_request_body_variable: false,
            response_body_access: false,
            response_body_limit: 524288, // 512KB default
            force_response_body_variable: false,
            last_phase: None,
            interruption: None,
            skip: 0,
            skip_after: String::new(),
            captures: Vec::new(),
            capturing: false,
            rule_remove_by_id: std::collections::BTreeSet::new(),
            rule_remove_target_by_id: std::collections::BTreeMap::new(),
            rules: None, // No WAF reference for standalone transactions
        }
    }

    /// Get the transaction ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Set the rules reference (called by WAF when creating transactions).
    ///
    /// This allows the transaction to access the WAF's rule set for CTL actions
    /// like `ctl:ruleRemoveByTag` and `ctl:ruleRemoveByMsg`.
    pub(crate) fn set_rules(&mut self, rules: Arc<RuleGroup>) {
        self.rules = Some(rules);
    }

    /// Get a collection by variable type.
    ///
    /// Returns a reference to the collection trait object for the given variable.
    /// This is used by rule variable extraction to get the collection to query.
    ///
    /// # Arguments
    ///
    /// * `variable` - The variable type to get the collection for
    ///
    /// # Returns
    ///
    /// Option containing a reference to the Collection trait object, or None if
    /// the variable is not supported or not yet populated.
    pub fn get_collection(
        &self,
        variable: RuleVariable,
    ) -> Option<&dyn crate::collection::Collection> {
        use crate::collection::Collection;

        match variable {
            RuleVariable::Args => Some(&self.args as &dyn Collection),
            RuleVariable::ArgsGet => Some(&self.args_get as &dyn Collection),
            RuleVariable::ArgsPost => Some(&self.args_post as &dyn Collection),
            RuleVariable::RequestHeaders => Some(&self.request_headers as &dyn Collection),
            RuleVariable::RequestCookies => Some(&self.request_cookies as &dyn Collection),
            RuleVariable::ResponseHeaders => Some(&self.response_headers as &dyn Collection),
            RuleVariable::RequestURI => Some(&self.request_uri as &dyn Collection),
            RuleVariable::RequestMethod => Some(&self.request_method as &dyn Collection),
            RuleVariable::RemoteAddr => Some(&self.remote_addr as &dyn Collection),
            _ => None, // Not yet implemented or not available
        }
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

    /// Get the FILES_TMP_NAMES collection.
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

    /// Enable or disable capturing for operators.
    pub fn set_capturing(&mut self, enabled: bool) {
        self.capturing = enabled;
        if !enabled {
            self.captures.clear();
        }
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
    /// use coraza::collection::Keyed;
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

        // Set cleaned request URI (path only, without query string)
        self.request_uri.set(path);

        // Extract basename (last component of path)
        if let Some(last_slash) = path.rfind(['/', '\\']) {
            let basename = &path[last_slash + 1..];
            self.request_basename.set(basename);
        } else {
            self.request_basename.set(path);
        }

        self.request_filename.set(path);
        self.query_string.set(query);

        // Parse query string into ARGS_GET
        if !query.is_empty() {
            self.extract_get_arguments(query);
        }
    }

    /// Extract GET arguments from a query string.
    ///
    /// Parses URL-encoded query string like "key1=value1&key2=value2"
    /// and adds to ARGS_GET collection.
    fn extract_get_arguments(&mut self, query: &str) {
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }

            if let Some(eq_pos) = pair.find('=') {
                let key = &pair[..eq_pos];
                let value = &pair[eq_pos + 1..];

                // URL decode key and value
                let key = Self::url_decode(key);
                let value = Self::url_decode(value);

                self.args_get_mut().add(&key, &value);
                self.args_mut().add(&key, &value);
            } else {
                // Key without value (e.g., "?flag")
                let key = Self::url_decode(pair);
                self.args_get_mut().add(&key, "");
                self.args_mut().add(&key, "");
            }
        }
    }

    /// Simple URL decoder (decodes %XX sequences).
    fn url_decode(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        let mut chars = s.chars();

        while let Some(ch) = chars.next() {
            if ch == '%' {
                // Try to decode %XX sequence
                let hex: String = chars.by_ref().take(2).collect();
                if hex.len() == 2
                    && let Ok(byte) = u8::from_str_radix(&hex, 16)
                {
                    result.push(byte as char);
                    continue;
                }
                // If decoding failed, just keep the %
                result.push('%');
                result.push_str(&hex);
            } else if ch == '+' {
                // '+' decodes to space in query strings
                result.push(' ');
            } else {
                result.push(ch);
            }
        }

        result
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
    /// use coraza::collection::Keyed;
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
        if key_lower.as_str() == "cookie" {
            // Parse cookies: "key1=value1; key2=value2"
            self.parse_cookies(value);
        }
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
    /// use coraza::collection::SingleCollection;
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
        if let Some(rules) = self.rules.clone() {
            let rule_engine_on = self.rule_engine == RuleEngineStatus::On;
            rules.eval(RulePhase::RequestHeaders, self, rule_engine_on);
        }

        self.interruption.clone()
    }

    /// Process request body with appropriate body processor.
    ///
    /// This method:
    /// 1. Stores the raw body in REQUEST_BODY and REQUEST_BODY_LENGTH
    /// 2. Determines the body processor from Content-Type
    /// 3. Calls the appropriate body processor to parse the body
    /// 4. Updates last_phase to RequestBody
    ///
    /// Returns an interruption if a disruptive action was triggered.
    ///
    /// # Example
    ///
    /// ```
    /// use coraza::transaction::Transaction;
    /// use coraza::collection::Keyed;
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

        // Store raw body
        let body_str = String::from_utf8_lossy(body).to_string();
        self.request_body.set(&body_str);
        self.request_body_length.set(body.len().to_string());

        // Get Content-Type to determine body processor
        let content_type_values = self.request_headers().get("content-type");
        let content_type = content_type_values
            .first()
            .map(|s| s.as_str())
            .unwrap_or("");

        // Determine body processor
        let processor_name = if content_type.starts_with("application/x-www-form-urlencoded") {
            Some("urlencoded")
        } else if content_type.starts_with("multipart/form-data") {
            Some("multipart")
        } else if content_type.starts_with("application/json") {
            Some("json")
        } else if content_type.starts_with("application/xml")
            || content_type.starts_with("text/xml")
        {
            Some("xml")
        } else {
            None
        };

        // Process body if we have a processor
        if let Some(processor_name) = processor_name {
            use crate::body_processors::{BodyProcessorOptions, get_body_processor};

            match get_body_processor(processor_name) {
                Ok(processor) => {
                    let options = BodyProcessorOptions {
                        mime: content_type.to_string(),
                        ..Default::default()
                    };

                    if let Err(e) = processor.process_request(body, self, &options) {
                        // Log error but don't fail the transaction
                        eprintln!("Body processor error: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to get body processor: {}", e);
                }
            }
        }

        // Update phase
        self.last_phase = Some(RulePhase::RequestBody);

        // Evaluate rules for Phase 2 (Request Body)
        if let Some(rules) = self.rules.clone() {
            let rule_engine_on = self.rule_engine == RuleEngineStatus::On;
            rules.eval(RulePhase::RequestBody, self, rule_engine_on);
        }

        Ok(self.interruption.clone())
    }

    /// Process response headers and populate response variables.
    ///
    /// # Example
    ///
    /// ```
    /// use coraza::transaction::Transaction;
    /// use coraza::collection::SingleCollection;
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
        if let Some(rules) = self.rules.clone() {
            let rule_engine_on = self.rule_engine == RuleEngineStatus::On;
            rules.eval(RulePhase::ResponseHeaders, self, rule_engine_on);
        }

        self.interruption.clone()
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

        // Store raw response body
        let body_str = String::from_utf8_lossy(body).to_string();
        self.response_body.set(&body_str);
        self.response_content_length.set(body.len().to_string());

        // Update phase
        self.last_phase = Some(RulePhase::ResponseBody);

        // Evaluate rules for Phase 4 (Response Body)
        if let Some(rules) = self.rules.clone() {
            let rule_engine_on = self.rule_engine == RuleEngineStatus::On;
            rules.eval(RulePhase::ResponseBody, self, rule_engine_on);
        }

        self.interruption.clone()
    }

    /// Process logging phase (final phase).
    ///
    /// This is the last phase where logging and audit actions occur.
    ///
    /// # Example
    ///
    /// ```
    /// use coraza::transaction::Transaction;
    ///
    /// let mut tx = Transaction::new("tx-1");
    /// // ... process request and response ...
    /// tx.process_logging();
    /// ```
    pub fn process_logging(&mut self) {
        // Update phase
        self.last_phase = Some(RulePhase::Logging);

        // Evaluate rules for Phase 5 (Logging)
        // Note: Logging phase rules run even if transaction is disrupted
        if let Some(rules) = self.rules.clone() {
            let rule_engine_on = self.rule_engine == RuleEngineStatus::On;
            rules.eval(RulePhase::Logging, self, rule_engine_on);
        }

        // TODO: Audit logging will go here
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

impl TransactionState for Transaction {
    fn get_variable(&self, variable: RuleVariable, key: Option<&str>) -> Option<String> {
        match (variable, key) {
            // Single-value variables
            (RuleVariable::RequestURI, None) => Some(self.request_uri.get().to_string()),
            (RuleVariable::RequestMethod, None) => Some(self.request_method.get().to_string()),
            (RuleVariable::RemoteAddr, None) => Some(self.remote_addr.get().to_string()),

            // Keyed variables - return first value if key specified
            (RuleVariable::Args, Some(k)) => self.args.get(k).first().cloned(),
            (RuleVariable::ArgsGet, Some(k)) => self.args_get.get(k).first().cloned(),
            (RuleVariable::ArgsPost, Some(k)) => self.args_post.get(k).first().cloned(),
            (RuleVariable::RequestHeaders, Some(k)) => self.request_headers.get(k).first().cloned(),
            (RuleVariable::RequestCookies, Some(k)) => self.request_cookies.get(k).first().cloned(),
            (RuleVariable::ResponseHeaders, Some(k)) => {
                self.response_headers.get(k).first().cloned()
            }

            // Unsupported combinations
            _ => None,
        }
    }

    fn capturing(&self) -> bool {
        self.capturing
    }

    fn capture_field(&mut self, index: usize, value: &str) {
        if !self.capturing {
            return;
        }

        // Extend captures array if needed
        if index >= self.captures.len() {
            self.captures.resize(index + 1, None);
        }

        self.captures[index] = Some(value.to_string());
    }

    fn interrupt(&mut self, rule_id: i32, action: &str, status: i32, data: &str) {
        self.interruption = Some(Interruption {
            rule_id: rule_id as usize,
            action: action.to_string(),
            status: status as u16,
            data: data.to_string(),
        });
    }

    // ===== CTL Action Methods =====

    fn ctl_set_rule_engine(&mut self, status: RuleEngineStatus) {
        self.set_rule_engine(status);
    }

    fn ctl_set_request_body_access(&mut self, enabled: bool) {
        self.set_request_body_access(enabled);
    }

    fn ctl_set_request_body_limit(&mut self, limit: i64) {
        self.set_request_body_limit(limit);
    }

    fn ctl_set_force_request_body_variable(&mut self, enabled: bool) {
        self.set_force_request_body_variable(enabled);
    }

    fn ctl_set_response_body_access(&mut self, enabled: bool) {
        self.set_response_body_access(enabled);
    }

    fn ctl_set_response_body_limit(&mut self, limit: i64) {
        self.set_response_body_limit(limit);
    }

    fn ctl_set_force_response_body_variable(&mut self, enabled: bool) {
        self.set_force_response_body_variable(enabled);
    }

    fn ctl_last_phase(&self) -> Option<RulePhase> {
        self.last_phase
    }

    fn ctl_remove_rule_by_id(&mut self, rule_id: i32) {
        self.remove_rule_by_id(rule_id);
    }

    fn ctl_remove_rule_target_by_id(&mut self, rule_id: i32, variable: RuleVariable, key: &str) {
        self.remove_rule_target_by_id(rule_id, variable, key);
    }

    fn ctl_get_rules(&self) -> Option<&Arc<RuleGroup>> {
        self.rules.as_ref()
    }

    // ===== Flow Control Methods =====

    fn set_skip(&mut self, count: i32) {
        self.skip = count;
    }

    fn set_skip_after(&mut self, marker: &str) {
        self.skip_after = marker.to_string();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collection::{Collection, MapCollection};

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
        tx.capture_field(1, "match2");
        tx.capture_field(5, "match6"); // Sparse indexing

        assert_eq!(tx.captures[0], Some("match1".to_string()));
        assert_eq!(tx.captures[1], Some("match2".to_string()));
        assert_eq!(tx.captures[2], None);
        assert_eq!(tx.captures[5], Some("match6".to_string()));

        // Disabling capturing clears captures
        tx.set_capturing(false);
        assert!(tx.captures.is_empty());
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

        // REQUEST_URI should be path only (without query string)
        assert_eq!(tx.request_uri.get(), "/search");
        assert_eq!(tx.request_filename.get(), "/search");
        assert_eq!(tx.request_basename.get(), "search");
        assert_eq!(tx.query_string.get(), "q=test&page=2");

        // Check ARGS_GET populated
        assert_eq!(tx.args_get().get("q"), vec!["test"]);
        assert_eq!(tx.args_get().get("page"), vec!["2"]);
    }

    #[test]
    fn test_process_uri_with_anchor() {
        let mut tx = Transaction::new("tx-011");
        tx.process_uri("/page#section", "GET", "HTTP/1.1");

        assert_eq!(tx.request_uri_raw.get(), "/page#section");
        assert_eq!(tx.request_uri.get(), "/page"); // Anchor removed
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

        // Body is stored but not parsed
        assert_eq!(tx.request_body.get(), "some data");
        assert_eq!(tx.request_body_length.get(), "9");
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

    #[test]
    fn test_process_response_body() {
        let mut tx = Transaction::new("tx-028");
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
        let mut tx = Transaction::new("tx-029");
        tx.process_response_headers(200, "HTTP/1.1");

        tx.process_response_body(b"body1");

        // Try to process again
        tx.process_response_body(b"body2");

        // Should still have first body
        assert_eq!(tx.response_body.get(), "body1");
    }

    #[test]
    fn test_process_logging() {
        let mut tx = Transaction::new("tx-030");

        tx.process_logging();

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
        tx.process_logging();
        assert_eq!(tx.last_phase, Some(RulePhase::Logging));
    }
}
