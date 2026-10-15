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
            AuditLogFormat::Ocsf => String::new(),
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
                        "data": {
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
                        },
                    })
                })
                .collect();
        }
        entry
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
}

impl fmt::Debug for Writer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discard => f.write_str("Discard"),
            Self::Serial(_) => f.write_str("Serial"),
            Self::Concurrent { dir, .. } => f.debug_struct("Concurrent").field("dir", dir).finish(),
        }
    }
}

impl AuditLogger {
    /// Opens the audit log `config` describes: its file is created if missing.
    ///
    /// # Errors
    ///
    /// If the file can't be opened, `SecAuditLogRelevantStatus` isn't a regular
    /// expression, or the writer isn't supported here (`HTTPS`, `Syslog`).
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
            (AuditLogType::Syslog, _) => {
                return Err("audit log type Syslog is not supported".to_string());
            }
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
