//! Transaction management for request/response processing.
//!
//! A transaction represents a single HTTP request/response pair and holds
//! all the data (headers, arguments, cookies, etc.) that rules operate on.

pub mod variables;

use crate::RuleVariable;
use crate::collection::{Keyed, Map, MapCollection, Single, SingleCollection};
use crate::operators::TransactionState;

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

    /// Captured values from operators (rx, pm)
    captures: Vec<Option<String>>,

    /// Whether capturing is enabled
    capturing: bool,
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
            captures: Vec::new(),
            capturing: false,
        }
    }

    /// Get the transaction ID.
    pub fn id(&self) -> &str {
        &self.id
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

    /// Set the REQUEST_URI value.
    pub fn set_request_uri(&mut self, uri: impl Into<String>) {
        self.request_uri.set(uri);
    }

    /// Set the REQUEST_METHOD value.
    pub fn set_request_method(&mut self, method: impl Into<String>) {
        self.request_method.set(method);
    }

    /// Set the REMOTE_ADDR value.
    pub fn set_remote_addr(&mut self, addr: impl Into<String>) {
        self.remote_addr.set(addr);
    }

    /// Enable or disable capturing for operators.
    pub fn set_capturing(&mut self, enabled: bool) {
        self.capturing = enabled;
        if !enabled {
            self.captures.clear();
        }
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

        // Set cleaned request URI
        self.request_uri.set(uri_without_anchor);

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

        assert_eq!(tx.request_uri.get(), "/search?q=test&page=2");
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
}
