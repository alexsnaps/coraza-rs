//! SQL injection and XSS detection operators.
//!
//! Both detect attacks with libperfusion, a port of libinjection, as Coraza does with
//! libinjection-go.

use crate::operators::{Operator, Outputs};
use crate::transaction::Transaction;

/// SQL injection detection operator.
///
/// Detects SQL injection attempts using libinjection's SQLi detection algorithm.
/// Returns true if SQL injection patterns are detected in the input. When a match
/// is found, the SQL fingerprint (such as `s&sos`) is captured in field 0.
///
/// # Arguments
///
/// None. Operates on the target variable specified in the rule.
///
/// # Returns
///
/// `true` if SQL injection detected, `false` otherwise.
///
/// # Examples
///
/// ```
/// # use coraza::operators::detection::detect_sqli;
/// # use coraza::operators::Operator;
/// let op = detect_sqli();
///
/// // SQL injection patterns
/// let tx = coraza::transaction::Transaction::default();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(op.evaluate(&tx, "1' OR '1'='1", &mut out));
/// assert!(op.evaluate(&tx, "admin'--", &mut out));
/// assert!(op.evaluate(&tx, "1 UNION SELECT", &mut out));
///
/// // Normal input
/// assert!(!op.evaluate(&tx, "hello world", &mut out));
/// ```
#[derive(Debug, Clone, Copy)]
pub struct DetectSQLi;

impl Operator for DetectSQLi {
    fn evaluate(&self, _tx: &Transaction, input: &str, out: &mut Outputs) -> bool {
        let Some(fingerprint) = libperfusion::sqli(input.as_bytes()) else {
            return false;
        };
        out.capture(0, fingerprint.as_str());
        true
    }
}

/// Creates a new `detectSQLi` operator.
///
/// # Examples
///
/// ```
/// # use coraza::operators::detection::detect_sqli;
/// # use coraza::operators::Operator;
/// let op = detect_sqli();
/// let tx = coraza::transaction::Transaction::default();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(op.evaluate(&tx, "1' OR '1'='1", &mut out));
/// ```
pub fn detect_sqli() -> DetectSQLi {
    DetectSQLi
}

/// XSS detection operator.
///
/// Detects cross-site scripting (XSS) attempts using libinjection's XSS detection
/// algorithm. Returns true if XSS patterns are detected in the input.
///
/// # Arguments
///
/// None. Operates on the target variable specified in the rule.
///
/// # Returns
///
/// `true` if XSS detected, `false` otherwise.
///
/// # Examples
///
/// ```
/// # use coraza::operators::detection::detect_xss;
/// # use coraza::operators::Operator;
/// let op = detect_xss();
///
/// // XSS patterns
/// let tx = coraza::transaction::Transaction::default();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(op.evaluate(&tx, "<script>alert(1)</script>", &mut out));
/// assert!(op.evaluate(&tx, "<a href=\"javascript:alert(1)\">", &mut out));
/// assert!(op.evaluate(&tx, "<img src=x onerror=alert(1)>", &mut out));
///
/// // Normal input
/// assert!(!op.evaluate(&tx, "hello world", &mut out));
/// ```
#[derive(Debug, Clone, Copy)]
pub struct DetectXSS;

impl Operator for DetectXSS {
    fn evaluate(&self, _tx: &Transaction, input: &str, _out: &mut Outputs) -> bool {
        libperfusion::xss(input.as_bytes())
    }
}

/// Creates a new `detectXSS` operator.
///
/// # Examples
///
/// ```
/// # use coraza::operators::detection::detect_xss;
/// # use coraza::operators::Operator;
/// let op = detect_xss();
/// let tx = coraza::transaction::Transaction::default();
/// let mut out = coraza::operators::Outputs::default();
/// assert!(op.evaluate(&tx, "<script>alert(1)</script>", &mut out));
/// ```
pub fn detect_xss() -> DetectXSS {
    DetectXSS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::{Matches, evaluate_in};
    use crate::transaction::Transaction;

    #[test]
    fn test_detect_sqli_basic() {
        let op = detect_sqli();

        // SQL injection patterns
        assert!(op.matches("1' OR '1'='1"));
        assert!(op.matches("admin'--"));
        assert!(op.matches("1 UNION SELECT"));
        assert!(op.matches("1; DROP TABLE users"));

        // Normal input
        assert!(!op.matches("hello world"));
        assert!(!op.matches("test@example.com"));
        assert!(!op.matches(""));
    }

    #[test]
    fn test_detect_sqli_with_capture() {
        let op = detect_sqli();
        let mut tx = Transaction::default();

        // Detect SQL injection and capture fingerprint
        assert!(evaluate_in(&op, &mut tx, "1' OR '1'='1", true));

        // The fingerprint is captured into TX.0
        assert_eq!(
            tx.get_variable(crate::RuleVariable::TX, Some("0"))
                .as_deref(),
            Some("s&sos")
        );
    }

    #[test]
    fn test_detect_xss_basic() {
        let op = detect_xss();

        // XSS patterns (HTML context)
        assert!(op.matches("<script>alert(1)</script>"));
        assert!(op.matches("<img src=x onerror=alert(1)>"));
        assert!(op.matches("<svg/onload=alert(1)>"));

        // Normal input
        assert!(!op.matches("hello world"));
        assert!(!op.matches("<p>Normal HTML</p>"));
        assert!(!op.matches(""));

        // A javascript: URL is only flagged as the value of an attribute that takes a URL
        assert!(!op.matches("javascript:alert(1)"));
        assert!(op.matches("<a href=\"javascript:alert(1)\">"));
    }

    #[test]
    fn test_detect_xss_edge_cases() {
        let op = detect_xss();

        // More sophisticated XSS
        assert!(op.matches("<body onload=alert(1)>"));
        assert!(op.matches("<iframe src=javascript:alert(1)>"));

        // Not XSS
        assert!(!op.matches("test"));
        assert!(!op.matches("a < b && c > d"));
    }
}
