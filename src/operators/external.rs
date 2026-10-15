// SPDX-License-Identifier: Apache-2.0

//! Operators that ask outside the WAF: a program (`@inspectFile`) or DNS (`@rbl`).
//!
//! Both block the transaction until they have an answer or time out, as in Go Coraza.

use std::io::Read;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::operators::{Operator, Outputs};
use crate::transaction::Transaction;

/// How long `@inspectFile` waits for its program.
const INSPECT_FILE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long `@rbl` waits for DNS.
const RBL_TIMEOUT: Duration = Duration::from_millis(500);

/// `@inspectFile PROGRAM`: runs PROGRAM with the value (usually an uploaded file's
/// path) as its only argument.
///
/// Matches, as in Go Coraza, when the program exits successfully within 10 seconds and
/// its output (standard output, then standard error) is not empty and doesn't start
/// with `1`; a program that runs longer is killed. The program runs with the WAF's
/// privileges: only name one that is safe to run on any value a client sends.
#[derive(Debug, Clone)]
pub struct InspectFile {
    program: PathBuf,
}

impl Operator for InspectFile {
    fn evaluate(&self, _tx: &Transaction, input: &str, _out: &mut Outputs) -> bool {
        let Ok(mut child) = Command::new(&self.program)
            .arg(input)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        else {
            return false;
        };
        // Read as the program writes, so that it can't block on a full pipe
        let read = |stream: Option<Box<dyn Read + Send>>| {
            thread::spawn(move || {
                let mut output = Vec::new();
                if let Some(mut stream) = stream {
                    let _ = stream.read_to_end(&mut output);
                }
                output
            })
        };
        let stdout = read(
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn Read + Send>),
        );
        let stderr = read(
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn Read + Send>),
        );

        let deadline = Instant::now() + INSPECT_FILE_TIMEOUT;
        let succeeded = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status.success(),
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break false;
                }
            }
        };
        let mut output = stdout.join().unwrap_or_default();
        output.extend(stderr.join().unwrap_or_default());
        succeeded && output.first().is_some_and(|&first| first != b'1')
    }
}

/// Creates an `@inspectFile` operator running `program`.
pub fn inspect_file(program: &str) -> InspectFile {
    InspectFile {
        program: PathBuf::from(program),
    }
}

/// `@rbl ZONE`: whether `VALUE.ZONE` resolves, VALUE being an IP address, as a DNS
/// block list answers.
///
/// As in Go Coraza, the address is not reversed (ModSecurity reverses its octets), and
/// a name that doesn't resolve within 500 ms doesn't match. Unlike Go, the list's TXT
/// record isn't read, so nothing is captured: the standard library resolves addresses
/// only. A lookup that times out finishes in the background.
#[derive(Debug, Clone)]
pub struct Rbl {
    zone: String,
}

impl Operator for Rbl {
    fn evaluate(&self, _tx: &Transaction, input: &str, _out: &mut Outputs) -> bool {
        let name = format!("{input}.{}", self.zone);
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let resolves = (name.as_str(), 0)
                .to_socket_addrs()
                .is_ok_and(|mut addresses| addresses.next().is_some());
            let _ = sender.send(resolves);
        });
        receiver.recv_timeout(RBL_TIMEOUT).unwrap_or(false)
    }
}

/// Creates an `@rbl` operator for the block list at `zone`.
pub fn rbl(zone: &str) -> Rbl {
    Rbl {
        zone: zone.to_string(),
    }
}
