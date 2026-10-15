//! SQL injection and XSS detection operators.
//!
//! Both detect attacks with libperfusion, a port of libinjection, as Coraza does with
//! libinjection-go.

use crate::operators::Operator;
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
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "1' OR '1'='1"));
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "admin'--"));
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "1 UNION SELECT"));
///
/// // Normal input
/// assert!(!op.evaluate(None::<&mut coraza::transaction::Transaction>, "hello world"));
/// ```
#[derive(Debug, Clone, Copy)]
pub struct DetectSQLi;

impl Operator for DetectSQLi {
    fn evaluate(&self, tx: Option<&mut Transaction>, input: &str) -> bool {
        let Some(fingerprint) = libperfusion::sqli(input.as_bytes()) else {
            return false;
        };
        if let Some(tx) = tx {
            tx.capture_field(0, fingerprint.as_str());
        }
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
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "1' OR '1'='1"));
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
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "<script>alert(1)</script>"));
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "<a href=\"javascript:alert(1)\">"));
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "<img src=x onerror=alert(1)>"));
///
/// // Normal input
/// assert!(!op.evaluate(None::<&mut coraza::transaction::Transaction>, "hello world"));
/// ```
#[derive(Debug, Clone, Copy)]
pub struct DetectXSS;

impl Operator for DetectXSS {
    fn evaluate(&self, _tx: Option<&mut Transaction>, input: &str) -> bool {
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
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "<script>alert(1)</script>"));
/// ```
pub fn detect_xss() -> DetectXSS {
    DetectXSS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::Transaction;

    #[test]
    fn test_detect_sqli_basic() {
        let op = detect_sqli();

        // SQL injection patterns
        assert!(op.evaluate(None::<&mut Transaction>, "1' OR '1'='1"));
        assert!(op.evaluate(None::<&mut Transaction>, "admin'--"));
        assert!(op.evaluate(None::<&mut Transaction>, "1 UNION SELECT"));
        assert!(op.evaluate(None::<&mut Transaction>, "1; DROP TABLE users"));

        // Normal input
        assert!(!op.evaluate(None::<&mut Transaction>, "hello world"));
        assert!(!op.evaluate(None::<&mut Transaction>, "test@example.com"));
        assert!(!op.evaluate(None::<&mut Transaction>, ""));
    }

    #[test]
    fn test_detect_sqli_with_capture() {
        let op = detect_sqli();
        let mut tx = Transaction::default();

        // Enable capturing
        tx.set_capturing(true);

        // Detect SQL injection and capture fingerprint
        assert!(op.evaluate(Some(&mut tx), "1' OR '1'='1"));

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
        assert!(op.evaluate(None::<&mut Transaction>, "<script>alert(1)</script>"));
        assert!(op.evaluate(None::<&mut Transaction>, "<img src=x onerror=alert(1)>"));
        assert!(op.evaluate(None::<&mut Transaction>, "<svg/onload=alert(1)>"));

        // Normal input
        assert!(!op.evaluate(None::<&mut Transaction>, "hello world"));
        assert!(!op.evaluate(None::<&mut Transaction>, "<p>Normal HTML</p>"));
        assert!(!op.evaluate(None::<&mut Transaction>, ""));

        // A javascript: URL is only flagged as the value of an attribute that takes a URL
        assert!(!op.evaluate(None::<&mut Transaction>, "javascript:alert(1)"));
        assert!(op.evaluate(None::<&mut Transaction>, "<a href=\"javascript:alert(1)\">"));
    }

    #[test]
    fn test_detect_xss_edge_cases() {
        let op = detect_xss();

        // More sophisticated XSS
        assert!(op.evaluate(None::<&mut Transaction>, "<body onload=alert(1)>"));
        assert!(op.evaluate(None::<&mut Transaction>, "<iframe src=javascript:alert(1)>"));

        // Not XSS
        assert!(!op.evaluate(None::<&mut Transaction>, "test"));
        assert!(!op.evaluate(None::<&mut Transaction>, "a < b && c > d"));
    }
}
