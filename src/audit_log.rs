// SPDX-License-Identifier: Apache-2.0

//! Audit logging, as Go Coraza does it: what a transaction's entry holds ([`AuditLog`],
//! built by [`crate::transaction::Transaction::audit_log`]), how it is written out
//! ([`AuditLogFormat`]) and where to ([`AuditLogType`]).

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use regex::Regex;
use serde_json::{Value, json};

use crate::config::WafConfig;
use crate::types::{AuditLogFormat, AuditLogPart, AuditLogParts, AuditLogType};
use crate::utils::time::UtcTime;

/// A transaction's audit log entry.
#[derive(Debug, Clone, Default)]
pub struct AuditLog {
    /// The parts the entry holds, in the order they are written
    pub parts: AuditLogParts,
    /// The transaction, as far as `parts` include it
    pub transaction: AuditTransaction,
    /// What the rules with `auditlog` that matched have to say: one per value they
    /// matched with part `K`, or one per rule with only part `H`
    pub messages: Vec<AuditMessage>,
}

/// The transaction an [`AuditLog`] is about.
#[derive(Debug, Clone, Default)]
pub struct AuditTransaction {
    /// When the transaction started, as `2006/01/02 15:04:05`, in UTC
    pub timestamp: String,
    /// When the transaction started, in nanoseconds since the Unix epoch
    pub unix_timestamp: i64,
    /// UNIQUE_ID
    pub id: String,
    /// REMOTE_ADDR
    pub client_ip: String,
    /// REMOTE_PORT; 0 if unknown
    pub client_port: u16,
    /// SERVER_ADDR
    pub host_ip: String,
    /// SERVER_PORT; 0 if unknown
    pub host_port: u16,
    /// SERVER_NAME
    pub server_id: String,
    /// The request
    pub request: AuditRequest,
    /// The response, with part `E` or `F`
    pub response: Option<AuditResponse>,
    /// Who logged it, with part `H`
    pub producer: Option<AuditProducer>,
    /// HIGHEST_SEVERITY
    pub highest_severity: String,
    /// Whether a disruptive action interrupted the transaction
    pub is_interrupted: bool,
}

/// The request of an [`AuditTransaction`].
#[derive(Debug, Clone, Default)]
pub struct AuditRequest {
    /// REQUEST_METHOD
    pub method: String,
    /// REQUEST_PROTOCOL, e.g. `HTTP/1.1`
    pub protocol: String,
    /// REQUEST_URI
    pub uri: String,
    /// Empty, as in Go Coraza, which never sets it
    pub http_version: String,
    /// The headers by lowercase name, with part `B`
    pub headers: Option<BTreeMap<String, Vec<String>>>,
    /// REQUEST_BODY, with part `C`
    pub body: String,
    /// The uploaded files, with part `J`
    pub files: Option<Vec<AuditFile>>,
    /// FULL_REQUEST_LENGTH
    pub length: i32,
    /// ARGS, as key and value pairs
    pub args: Vec<(String, String)>,
}

/// A file uploaded with an [`AuditRequest`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditFile {
    /// Its name, as the client gave it
    pub name: String,
    /// Its size, in bytes
    pub size: i64,
    /// Its MIME type, from its name's extension; empty if unknown
    pub mime: String,
}

/// The response of an [`AuditTransaction`].
#[derive(Debug, Clone, Default)]
pub struct AuditResponse {
    /// Empty, as in Go Coraza, which never sets it; the native format writes `HTTP/1.1`
    pub protocol: String,
    /// RESPONSE_STATUS, with part `F`; 0 otherwise
    pub status: u16,
    /// The headers by lowercase name, with part `F`
    pub headers: Option<BTreeMap<String, Vec<String>>>,
    /// RESPONSE_BODY, with part `E`
    pub body: String,
}

/// Who wrote an [`AuditLog`].
#[derive(Debug, Clone, Default)]
pub struct AuditProducer {
    /// The connector; empty here
    pub connector: String,
    /// The connector's version; empty here
    pub version: String,
    /// Empty, as in Go Coraza
    pub server: String,
    /// The transaction's rule engine status, e.g. `On`
    pub rule_engine: String,
    /// When the transaction started and how long it has taken, both in nanoseconds,
    /// then the time spent in each phase, as Go Coraza writes them (0: not measured)
    pub stopwatch: String,
    /// `SecComponentSignature`s
    pub rulesets: Vec<String>,
}

/// One message of an [`AuditLog`].
#[derive(Debug, Clone, Default)]
pub struct AuditMessage {
    /// `SecComponentSignature`s, space-separated
    pub actionset: String,
    /// The rule's `msg`, as expanded for this match
    pub message: String,
    /// The rule's error log line, with part `H`
    pub error_message: String,
    /// The rule and match
    pub data: AuditMessageData,
}

/// The rule and match behind an [`AuditMessage`].
#[derive(Debug, Clone, Default)]
pub struct AuditMessageData {
    /// The rule's file
    pub file: String,
    /// The rule's line
    pub line: usize,
    /// The rule's id
    pub id: i32,
    /// The rule's `rev`
    pub rev: String,
    /// The rule's `msg`, as expanded for this match
    pub msg: String,
    /// The rule's `logdata`, as expanded for this match
    pub data: String,
    /// The rule's severity, 0 (emergency) to 7 (debug); -1 if unset
    pub severity: i8,
    /// The rule's `ver`
    pub ver: String,
    /// The rule's `maturity`; 0 if unset
    pub maturity: u8,
    /// The rule's `accuracy`; 0 if unset
    pub accuracy: u8,
    /// The rule's tags
    pub tags: Vec<String>,
    /// The rule's directives, its chain's included
    pub raw: String,
}

impl AuditLog {
    /// The entry written out in `format`; empty when there is nothing to write.
    pub fn format(&self, format: AuditLogFormat) -> String {
        match format {
            AuditLogFormat::Native => self.native(),
            AuditLogFormat::Json => self.json().to_string(),
            AuditLogFormat::JsonLegacy => self.json_legacy().to_string(),
            AuditLogFormat::Ocsf => self.ocsf().to_string(),
        }
    }

    /// ModSecurity's native format: a section per part, each opened by a boundary.
    fn native(&self) -> String {
        if self.parts.is_empty() {
            return String::new();
        }
        let tx = &self.transaction;
        let boundary = format!("--{}-", crate::utils::strings::random_string(16));
        let mut out = String::new();
        for part in &self.parts {
            out.push_str(&boundary);
            out.push(*part as u8 as char);
            out.push_str("--\n");
            match part {
                AuditLogPart::Header => out.push_str(&format!(
                    "[{}] {} {} {} {} {}\n",
                    tx.timestamp,
                    escape(&tx.id),
                    escape(&tx.client_ip),
                    tx.client_port,
                    escape(&tx.host_ip),
                    tx.host_port
                )),
                AuditLogPart::RequestHeaders => {
                    let request = &tx.request;
                    out.push_str(&format!(
                        "{} {} {}",
                        escape(&request.method),
                        escape(&request.uri),
                        escape(&request.protocol)
                    ));
                    for (name, values) in request.headers.iter().flatten() {
                        for value in values {
                            out.push_str(&format!("\n{}: {}", escape(name), escape(value)));
                        }
                    }
                    out.push('\n');
                }
                AuditLogPart::RequestBody if !tx.request.body.is_empty() => {
                    out.push_str(&escape(&tx.request.body));
                    out.push('\n');
                }
                AuditLogPart::IntermediaryResponseBody => {
                    if let Some(response) = tx.response.as_ref().filter(|r| !r.body.is_empty()) {
                        out.push_str(&escape(&response.body));
                        out.push('\n');
                    }
                }
                AuditLogPart::ResponseHeaders => {
                    if let Some(response) = &tx.response {
                        let protocol = match response.protocol.as_str() {
                            "" => "HTTP/1.1",
                            protocol => protocol,
                        };
                        out.push_str(&format!(
                            "{} {} {}\n",
                            escape(protocol),
                            response.status,
                            status_text(response.status)
                        ));
                        for (name, values) in response.headers.iter().flatten() {
                            for value in values {
                                out.push_str(&format!("{}: {}\n", escape(name), escape(value)));
                            }
                        }
                    }
                }
                AuditLogPart::Trailer => {
                    for message in self.messages.iter().filter(|m| !m.error_message.is_empty()) {
                        out.push_str(&escape(&message.error_message));
                        out.push('\n');
                    }
                }
                AuditLogPart::UploadedFiles => {
                    let files = tx.request.files.as_deref().unwrap_or_default();
                    for (index, file) in files.iter().enumerate() {
                        let mime = match file.mime.as_str() {
                            "" => "<Unknown Content-Type>",
                            mime => mime,
                        };
                        out.push_str(&format!(
                            "{},{},{:?},{:?}\n",
                            index + 1,
                            file.size,
                            file.name,
                            mime
                        ));
                    }
                    let total: i64 = files.iter().map(|file| file.size).sum();
                    out.push_str(&format!("Total,{total}\n"));
                }
                AuditLogPart::RulesMatched => {
                    for message in &self.messages {
                        out.push_str(&escape(&message.data.raw));
                        out.push('\n');
                    }
                }
                _ => {}
            }
            if *part != AuditLogPart::Header {
                out.push('\n');
            }
        }
        out
    }

    /// Go Coraza's JSON format.
    fn json(&self) -> Value {
        let tx = &self.transaction;
        let request = &tx.request;
        let mut transaction = json!({
            "timestamp": tx.timestamp,
            "unix_timestamp": tx.unix_timestamp,
            "id": tx.id,
            "client_ip": tx.client_ip,
            "client_port": tx.client_port,
            "host_ip": tx.host_ip,
            "host_port": tx.host_port,
            "server_id": tx.server_id,
            "request": {
                "method": request.method,
                "protocol": request.protocol,
                "uri": request.uri,
                "http_version": request.http_version,
                "headers": request.headers,
                "body": request.body,
                "files": request.files.as_ref().map(|files| {
                    files
                        .iter()
                        .map(|file| json!({"name": file.name, "size": file.size, "mime": file.mime}))
                        .collect::<Vec<_>>()
                }),
                // Go Coraza serializes its argument collection as an empty object
                "args": {},
                "length": request.length,
            },
            "highest_severity": tx.highest_severity,
            "is_interrupted": tx.is_interrupted,
        });
        if let Some(response) = &tx.response {
            transaction["response"] = json!({
                "protocol": response.protocol,
                "status": response.status,
                "headers": response.headers,
                "body": response.body,
            });
        }
        if let Some(producer) = &tx.producer {
            transaction["producer"] = json!({
                "connector": producer.connector,
                "version": producer.version,
                "server": producer.server,
                "rule_engine": producer.rule_engine,
                "stopwatch": producer.stopwatch,
                "rulesets": producer.rulesets,
            });
        }

        let mut entry = json!({ "transaction": transaction });
        if !self.messages.is_empty() {
            entry["messages"] = self
                .messages
                .iter()
                .map(|message| {
                    let data = &message.data;
                    json!({
                        "actionset": message.actionset,
                        "message": message.message,
                        "error_message": message.error_message,
                        "data": message_data_json(data),
                    })
                })
                .collect();
        }
        entry
    }

    /// The Open Cybersecurity Schema Framework's Web Resources Activity event (OCSF
    /// 1.2.0), as Go Coraza fills it in, without the fields that are zero or empty, as
    /// its protobuf types leave them out.
    ///
    /// Its severity is the transaction's highest: Go Coraza always writes `emergency`, as
    /// it never sets the highest severity of its entries.
    fn ocsf(&self) -> Value {
        let tx = &self.transaction;
        let request = &tx.request;
        let header_values = |headers: &Option<BTreeMap<String, Vec<String>>>, name: &str| {
            headers
                .iter()
                .flatten()
                .find(|(header, _)| *header == name)
                .map(|(_, values)| values.clone())
                .unwrap_or_default()
        };
        let header_list = |headers: &Option<BTreeMap<String, Vec<String>>>| {
            headers
                .iter()
                .flatten()
                .flat_map(|(name, values)| {
                    values
                        .iter()
                        .map(move |value| json!({"name": name, "value": value}))
                })
                .collect::<Vec<_>>()
        };
        let producer = tx.producer.clone().unwrap_or_default();
        let (action_id, action) = if tx.is_interrupted {
            (2, "Denied")
        } else {
            (1, "Allowed")
        };
        // As Go Coraza writes them, each followed by a comma
        let args: String = request
            .args
            .iter()
            .map(|(key, value)| format!("{key}={value},"))
            .collect();
        let logged_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_micros());
        // As Go's ParseRuleSeverity reads it, falling back to its zero value
        let severity = tx
            .highest_severity
            .parse::<crate::types::RuleSeverity>()
            .map_or("emergency", |severity| severity.as_str());
        let response = tx.response.clone().unwrap_or_default();

        let mut observables = Vec::new();
        if !tx.server_id.is_empty() {
            observables.push(json!({
                "name": "ServerID", "type": "ServerID", "type_id": 99, "value": tx.server_id,
            }));
        }
        for file in request.files.iter().flatten() {
            observables.push(json!({
                "name": file.name, "type": "File Name", "type_id": 7, "value": file.name,
            }));
            observables.push(json!({
                "name": file.name, "type": "Size", "type_id": 99, "value": file.size.to_string(),
            }));
            observables.push(json!({
                "name": file.name, "type": "Mime", "type_id": 99, "value": file.mime,
            }));
        }

        omit_empty(json!({
            "activity_id": 2,
            "activity_name": "Read",
            "category_name": "Application Activity",
            "class_name": "Web Resources Activity",
            "category_uid": 6,
            "class_uid": 6001,
            "time": tx.unix_timestamp,
            "action_id": action_id,
            "action": action,
            "metadata": {
                "log_provider": producer.connector,
                "log_version": producer.version,
                "logged_time": logged_time,
                "product": {"vendor_name": "OWASP Coraza Web Application Firewall"},
                "version": "1.2.0",
            },
            "type_uid": 600_102,
            "enrichments": self.messages.iter().map(|message| json!({
                "data": message_data_json(&message.data).to_string(),
                "name": message.data.msg,
                "value": message.data.data,
            })).collect::<Vec<_>>(),
            "http_request": {
                "version": request.protocol,
                "args": args,
                "http_method": request.method,
                "uid": tx.id,
                "url": {"url_string": request.uri},
                "http_headers": header_list(&request.headers),
                "length": request.length,
                "user_agent": header_values(&request.headers, "user-agent").first(),
                "referrer": header_values(&request.headers, "referer").first(),
                "x_forwarded_for": header_values(&request.headers, "x-forwarded-for"),
            },
            "http_response": {
                "code": response.status,
                "http_headers": header_list(&response.headers),
            },
            "src_endpoint": {"ip": tx.client_ip, "port": tx.client_port},
            "dst_endpoint": {"ip": tx.host_ip, "port": tx.host_port},
            "web_resources": [{"url_string": request.uri}],
            "message": self.messages.first().map(|message| &message.message),
            "severity": severity,
            "severity_id": 99,
            "start_time": tx.unix_timestamp,
            "type_name": "Read",
            "observables": observables,
        }))
    }

    /// The JSON format of ModSecurity 2, as Go Coraza writes it.
    fn json_legacy(&self) -> Value {
        let tx = &self.transaction;
        let joined = |headers: &Option<BTreeMap<String, Vec<String>>>| {
            headers
                .iter()
                .flatten()
                .map(|(name, values)| (name.clone(), Value::from(values.join(", "))))
                .collect::<serde_json::Map<_, _>>()
        };
        let request = &tx.request;
        let mut entry = json!({
            "transaction": {
                "time": tx.timestamp,
                "transaction_id": tx.id,
                "remote_address": tx.client_ip,
                "remote_port": tx.client_port,
                "local_address": tx.host_ip,
                "local_port": tx.host_port,
            },
            "request": {
                "request_line": format!("{} {} {}", request.method, request.uri, request.http_version),
                "headers": joined(&request.headers),
            },
        });
        if let Some(response) = &tx.response {
            entry["response"] = json!({
                "status": response.status,
                "protocol": response.protocol,
                "headers": joined(&response.headers),
            });
        }

        let messages: Vec<&str> = self.messages.iter().map(|m| m.message.as_str()).collect();
        if tx.producer.is_some() || !messages.is_empty() {
            let producer = tx.producer.clone().unwrap_or_default();
            let producers: Vec<&str> = std::iter::once(producer.connector.as_str())
                .filter(|connector| !connector.is_empty())
                .chain(producer.rulesets.iter().map(String::as_str))
                .collect();
            let stopwatch: serde_json::Map<_, _> = [
                "Combined", "P1", "P2", "P3", "P4", "P5", "Sr", "Sw", "L", "Gc",
            ]
            .into_iter()
            .map(|name| (name.to_string(), Value::from(0)))
            .collect();
            entry["audit_data"] = json!({
                "messages": if messages.is_empty() { Value::Null } else { json!(messages) },
                "error_messages": null,
                "handler": "",
                "stopwatch": stopwatch,
                "response_body_dechunked": false,
                "producer": if producers.is_empty() { Value::Null } else { json!(producers) },
                "server": "",
                "engine_mode": producer.rule_engine,
            });
        }
        entry
    }
}

/// The data of a message, as Go Coraza writes it in JSON.
fn message_data_json(data: &AuditMessageData) -> Value {
    json!({
        "file": data.file,
        "line": data.line,
        "id": data.id,
        "rev": data.rev,
        "msg": data.msg,
        "data": data.data,
        "severity": data.severity,
        "ver": data.ver,
        "maturity": data.maturity,
        "accuracy": data.accuracy,
        "tags": data.tags,
        "raw": data.raw,
    })
}

/// `value` without the object fields that are null, `""`, `0`, `false` or `[]`, at any
/// depth, as protobuf's JSON tags leave them out in Go.
fn omit_empty(value: Value) -> Value {
    let is_empty = |value: &Value| match value {
        Value::Null => true,
        Value::Bool(set) => !set,
        Value::Number(number) => number.as_f64() == Some(0.0),
        Value::String(text) => text.is_empty(),
        Value::Array(items) => items.is_empty(),
        Value::Object(_) => false,
    };
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .into_iter()
                .map(|(name, value)| (name, omit_empty(value)))
                .filter(|(_, value)| !is_empty(value))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(omit_empty).collect()),
        other => other,
    }
}

/// `text` with `\`, CR and LF escaped, as the native format writes values.
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

/// The reason phrase of an HTTP status code, as Go's `http.StatusText` gives it; empty
/// for an unknown code.
fn status_text(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Request Entity Too Large",
        414 => "Request URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Requested Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Entity",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => "",
    }
}

/// The MIME type of a file named `name`, from its extension, as Go's built-in table has
/// it; empty if unknown.
pub(crate) fn mime_type_of(name: &str) -> &'static str {
    let extension = name
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase());
    match extension.as_deref() {
        Some("avif") => "image/avif",
        Some("css") => "text/css; charset=utf-8",
        Some("gif") => "image/gif",
        Some("htm" | "html") => "text/html; charset=utf-8",
        Some("jpeg" | "jpg") => "image/jpeg",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("pdf") => "application/pdf",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("wasm") => "application/wasm",
        Some("webp") => "image/webp",
        Some("xml") => "text/xml; charset=utf-8",
        _ => "",
    }
}

/// Writes audit log entries in `SecAuditLogFormat` where `SecAuditLogType` says, and
/// knows which transactions `SecAuditEngine RelevantOnly` keeps.
#[derive(Debug)]
pub(crate) struct AuditLogger {
    format: AuditLogFormat,
    /// `SecAuditLogRelevantStatus`, if set
    relevant_status: Option<Regex>,
    writer: Writer,
}

/// Where audit log entries go.
enum Writer {
    /// Nowhere: without `SecAuditLog`, as in Go Coraza
    Discard,
    /// One after the other, into one file or stream
    Serial(Mutex<Box<dyn Write + Send>>),
    /// One file each, under `dir`, listed in an index
    Concurrent {
        index: Mutex<File>,
        dir: PathBuf,
        dir_mode: u32,
        file_mode: u32,
    },
    /// One message each, to syslog
    Syslog(Mutex<Syslog>),
}

impl fmt::Debug for Writer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discard => f.write_str("Discard"),
            Self::Serial(_) => f.write_str("Serial"),
            Self::Concurrent { dir, .. } => f.debug_struct("Concurrent").field("dir", dir).finish(),
            Self::Syslog(_) => f.write_str("Syslog"),
        }
    }
}

impl AuditLogger {
    /// Opens the audit log `config` describes: its file is created if missing.
    ///
    /// # Errors
    ///
    /// If the file or syslog can't be opened, `SecAuditLogRelevantStatus` isn't a
    /// regular expression, or the writer is `HTTPS`, which isn't supported here.
    pub(crate) fn open(config: &WafConfig) -> Result<Self, String> {
        let relevant_status = match config.audit_log_relevant_status.as_str() {
            "" => None,
            pattern => Some(
                Regex::new(pattern)
                    .map_err(|e| format!("invalid SecAuditLogRelevantStatus {pattern:?}: {e}"))?,
            ),
        };
        let target = config.audit_log.as_str();
        let writer = match (config.audit_log_type, target) {
            // HTTPS needs an HTTP client with TLS, which no dependency provides
            (AuditLogType::Https, _) => {
                return Err("audit log type HTTPS is not supported".to_string());
            }
            (AuditLogType::Syslog, target) => Writer::Syslog(Mutex::new(
                Syslog::connect(target).map_err(|e| format!("syslog dial failure: {e}"))?,
            )),
            (_, "") => Writer::Discard,
            (AuditLogType::Serial, "/dev/stdout") => {
                Writer::Serial(Mutex::new(Box::new(io::stdout())))
            }
            (AuditLogType::Serial, "/dev/stderr") => {
                Writer::Serial(Mutex::new(Box::new(io::stderr())))
            }
            (AuditLogType::Serial, path) => Writer::Serial(Mutex::new(Box::new(open_append(
                path,
                config.audit_log_file_mode,
            )?))),
            (AuditLogType::Concurrent, path) => Writer::Concurrent {
                index: Mutex::new(open_append(path, config.audit_log_file_mode)?),
                dir: PathBuf::from(&config.audit_log_storage_dir),
                dir_mode: config.audit_log_dir_mode,
                file_mode: config.audit_log_file_mode,
            },
        };
        Ok(Self {
            format: config.audit_log_format,
            relevant_status,
            writer,
        })
    }

    /// Whether a `RelevantOnly` audit engine logs a transaction: one where a rule with
    /// `auditlog` matched (`audited`) is logged unless its `status` falls outside
    /// `SecAuditLogRelevantStatus`; any other only if its status falls inside it.
    pub(crate) fn is_relevant(&self, audited: bool, status: &str) -> bool {
        match &self.relevant_status {
            Some(relevant) => relevant.is_match(status),
            None => audited,
        }
    }

    /// Writes `entry`.
    ///
    /// # Errors
    ///
    /// If writing fails.
    pub(crate) fn write(&self, entry: &AuditLog) -> io::Result<()> {
        let formatted = entry.format(self.format);
        if formatted.is_empty() {
            return Ok(());
        }
        match &self.writer {
            Writer::Discard => Ok(()),
            Writer::Syslog(syslog) => syslog
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .send(&formatted, entry.transaction.is_interrupted),
            Writer::Serial(output) => {
                let mut output = output
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                writeln!(output, "{formatted}")?;
                output.flush()
            }
            Writer::Concurrent {
                index,
                dir,
                dir_mode,
                file_mode,
            } => {
                let tx = &entry.transaction;
                let at = UtcTime::from_unix((tx.unix_timestamp / 1_000_000_000) as u64);
                let day = format!("{:04}{:02}{:02}", at.year, at.month, at.day);
                let minute = format!("{day}-{:02}{:02}", at.hour, at.minute);
                let entry_dir = dir.join(&day).join(&minute);
                create_dir_all(&entry_dir, *dir_mode)?;
                let path = entry_dir.join(format!("{minute}{:02}-{}", at.second, tx.id));
                write_new(&path, formatted.as_bytes(), *file_mode)?;

                // The index lines, as Go Coraza's logger writes them
                let mut index = index
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                writeln!(
                    index,
                    "{} {} - - [{}]",
                    tx.client_ip, tx.host_ip, tx.timestamp
                )?;
                let request = &tx.request;
                writeln!(
                    index,
                    " \"{} {} {}\"",
                    request.method, request.uri, request.http_version
                )?;
                if let Some(response) = &tx.response {
                    writeln!(index, " {}", response.status)?;
                }
                writeln!(index, "{} - {}", tx.id, path.display())?;
                index.flush()
            }
        }
    }
}

/// A connection to syslog, as Go's `log/syslog` dials it with facility `local0` and tag
/// `com.coraza.waf`.
struct Syslog {
    socket: SyslogSocket,
    /// Whether it is the local syslog, which takes a shorter header
    local: bool,
}

enum SyslogSocket {
    Udp(std::net::UdpSocket),
    Tcp(std::net::TcpStream),
    #[cfg(unix)]
    UnixStream(std::os::unix::net::UnixStream),
    #[cfg(unix)]
    UnixDatagram(std::os::unix::net::UnixDatagram),
}

impl Syslog {
    /// Connects to `target` as Go Coraza reads it: `scheme://address`, where the scheme
    /// is `udp`, `tcp`, `unix` or `unixgram`; an address alone, over TCP; or, empty, the
    /// local syslog.
    fn connect(target: &str) -> io::Result<Self> {
        let unsupported = |network: &str| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported network {network:?}"),
            )
        };
        let (network, address) = match target.split_once("://") {
            Some((network, address)) => (network, address),
            None => ("tcp", target),
        };
        let socket = match (network, address) {
            #[cfg(unix)]
            (_, "") => return Self::connect_local(),
            ("udp" | "udp4" | "udp6", address) => {
                let socket = std::net::UdpSocket::bind(if address.starts_with('[') {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                })?;
                socket.connect(address)?;
                SyslogSocket::Udp(socket)
            }
            ("tcp" | "tcp4" | "tcp6", address) => {
                SyslogSocket::Tcp(std::net::TcpStream::connect(address)?)
            }
            #[cfg(unix)]
            ("unix", path) => {
                SyslogSocket::UnixStream(std::os::unix::net::UnixStream::connect(path)?)
            }
            #[cfg(unix)]
            ("unixgram", path) => {
                let socket = std::os::unix::net::UnixDatagram::unbound()?;
                socket.connect(path)?;
                SyslogSocket::UnixDatagram(socket)
            }
            (network, _) => return Err(unsupported(network)),
        };
        Ok(Self {
            socket,
            local: false,
        })
    }

    /// The local syslog, at the first of Go's known socket paths that answers.
    #[cfg(unix)]
    fn connect_local() -> io::Result<Self> {
        let mut last_error = io::Error::new(io::ErrorKind::NotFound, "no local syslog");
        for path in ["/dev/log", "/var/run/syslog", "/var/run/log"] {
            let datagram = std::os::unix::net::UnixDatagram::unbound()
                .and_then(|socket| socket.connect(path).map(|()| socket));
            let socket = match datagram {
                Ok(socket) => SyslogSocket::UnixDatagram(socket),
                Err(_) => match std::os::unix::net::UnixStream::connect(path) {
                    Ok(stream) => SyslogSocket::UnixStream(stream),
                    Err(e) => {
                        last_error = e;
                        continue;
                    }
                },
            };
            return Ok(Self {
                socket,
                local: true,
            });
        }
        Err(last_error)
    }

    /// Sends `message` at severity `err` if `error`, `info` otherwise, framed as Go's
    /// `log/syslog` does.
    fn send(&mut self, message: &str, error: bool) -> io::Result<()> {
        // local0 (16) times 8, plus the severity
        let priority = 16 * 8 + if error { 3 } else { 6 };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let at = UtcTime::from_unix(now);
        let tag = format!("com.coraza.waf[{}]", std::process::id());
        let newline = if message.ends_with('\n') { "" } else { "\n" };
        let framed = if self.local {
            const MONTHS: [&str; 12] = [
                "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
            ];
            format!(
                "<{priority}>{} {:>2} {:02}:{:02}:{:02} {tag}: {message}{newline}",
                MONTHS[(at.month - 1) as usize],
                at.day,
                at.hour,
                at.minute,
                at.second
            )
        } else {
            format!(
                "<{priority}>{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z {} {tag}: {message}{newline}",
                at.year,
                at.month,
                at.day,
                at.hour,
                at.minute,
                at.second,
                hostname()
            )
        };
        match &mut self.socket {
            SyslogSocket::Udp(socket) => socket.send(framed.as_bytes()).map(|_| ()),
            SyslogSocket::Tcp(stream) => stream.write_all(framed.as_bytes()),
            #[cfg(unix)]
            SyslogSocket::UnixStream(stream) => stream.write_all(framed.as_bytes()),
            #[cfg(unix)]
            SyslogSocket::UnixDatagram(socket) => socket.send(framed.as_bytes()).map(|_| ()),
        }
    }
}

/// This host's name, as the kernel has it; `localhost` if unknown.
fn hostname() -> String {
    ["/proc/sys/kernel/hostname", "/etc/hostname"]
        .into_iter()
        .find_map(|path| fs::read_to_string(path).ok())
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

fn open_append(path: &str, mode: u32) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode);
    #[cfg(not(unix))]
    let _ = mode;
    options
        .open(path)
        .map_err(|e| format!("cannot open audit log {path}: {e}"))
}

fn create_dir_all(dir: &Path, mode: u32) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, mode);
    #[cfg(not(unix))]
    let _ = mode;
    builder.create(dir)
}

fn write_new(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode);
    #[cfg(not(unix))]
    let _ = mode;
    options.open(path)?.write_all(contents)
}
