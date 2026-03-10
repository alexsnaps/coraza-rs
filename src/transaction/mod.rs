//! Transaction management for request/response processing.
//!
//! A transaction represents a single HTTP request/response pair and holds
//! all the data (headers, arguments, cookies, etc.) that rules operate on.

pub mod variables;

use crate::RuleVariable;
use crate::collection::{Keyed, Map, Single, SingleCollection};
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

    /// Captured values from operators (rx, pm)
    captures: Vec<Option<String>>,

    /// Whether capturing is enabled
    capturing: bool,
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
            captures: Vec::new(),
            capturing: false,
        }
    }

    /// Get the transaction ID.
    pub fn id(&self) -> &str {
        &self.id
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
    use crate::collection::MapCollection;

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
}
