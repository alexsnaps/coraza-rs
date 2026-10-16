//! IP address matching operators.
//!
//! This module provides operators for matching IP addresses against CIDR blocks
//! and IP ranges, compatible with ModSecurity's @ipMatch family of operators.

use crate::operators::{Datasets, Operator, Outputs};
use crate::transaction::Transaction;
use ipnet::IpNet;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

/// IP address matching operator.
///
/// Performs fast IPv4 or IPv6 address matching with support for CIDR notation.
/// Can match individual IPs or IP ranges. Automatically adds appropriate subnet masks
/// (/32 for IPv4, /128 for IPv6) when not specified.
///
/// # Arguments
///
/// Comma-separated list of IP addresses with optional CIDR blocks (e.g., "192.168.1.0/24, 10.0.0.1").
///
/// # Returns
///
/// `true` if the input IP address matches any of the provided IPs or ranges, `false` otherwise.
#[derive(Debug, Clone)]
pub struct IpMatch {
    /// List of IP networks (CIDR blocks) to match against
    subnets: Vec<IpNet>,
}

impl IpMatch {
    /// Creates a new `IpMatch` operator from a comma-separated list of IPs/CIDRs.
    ///
    /// # Arguments
    ///
    /// * `ips` - Comma-separated list of IP addresses with optional CIDR notation
    ///
    /// # Returns
    ///
    /// `Ok(IpMatch)` if at least one valid IP/CIDR was parsed, `Err` otherwise.
    pub fn new(ips: &str) -> Result<Self, String> {
        let mut subnets = Vec::new();

        for ip_str in ips.split(',') {
            let ip_str = ip_str.trim();
            if ip_str.is_empty() {
                continue;
            }

            // Auto-add CIDR suffix if not present
            let ip_with_cidr = if ip_str.contains(':') && !ip_str.contains('/') {
                // IPv6 without CIDR - add /128
                format!("{}/128", ip_str)
            } else if ip_str.contains('.') && !ip_str.contains('/') {
                // IPv4 without CIDR - add /32
                format!("{}/32", ip_str)
            } else {
                ip_str.to_string()
            };

            // Parse CIDR notation
            match IpNet::from_str(&ip_with_cidr) {
                Ok(net) => subnets.push(net),
                Err(_) => {
                    // Silently skip invalid IPs (matches Go behavior)
                    continue;
                }
            }
        }

        if subnets.is_empty() {
            return Err("no valid IP addresses or CIDR blocks provided".to_string());
        }

        Ok(IpMatch { subnets })
    }
}

impl Operator for IpMatch {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        // Parse the input IP address
        let ip = match std::str::from_utf8(input).map(IpAddr::from_str) {
            Ok(Ok(ip)) => ip,
            _ => return false,
        };

        // Check if the IP is contained in any of the configured subnets
        for subnet in &self.subnets {
            if subnet.contains(&ip) {
                return true;
            }
        }

        false
    }
}

/// Creates a new `ipMatch` operator.
///
/// # Arguments
///
/// * `ips` - Comma-separated list of IP addresses with optional CIDR blocks
pub fn ip_match(ips: &str) -> Result<IpMatch, String> {
    IpMatch::new(ips)
}

/// IP address matching operator (from a `SecDataset`).
///
/// Matches the IPs and CIDR blocks of a dataset as `@ipMatch` matches its own.
#[derive(Debug, Clone)]
pub struct IpMatchFromDataset {
    ips: IpMatch,
}

impl Operator for IpMatchFromDataset {
    fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        self.ips.evaluate(tx, input, out)
    }
}

/// Creates a new `@ipMatchFromDataset` operator from the dataset `name` of `datasets`.
///
/// # Errors
///
/// If `datasets` has no dataset `name`, or an empty one, or it holds no valid IP.
pub fn ip_match_from_dataset(
    name: &str,
    datasets: &Datasets,
) -> Result<IpMatchFromDataset, String> {
    let items = datasets
        .get(name)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| format!("dataset \"{}\" not found", name))?;
    Ok(IpMatchFromDataset {
        ips: IpMatch::new(&items.join(","))?,
    })
}

/// IP address matching operator (from file).
///
/// Loads IP addresses and CIDR blocks from a file, then performs matching
/// identical to `@ipMatch`. Each line in the file should contain one IP
/// address or CIDR block. Empty lines and lines starting with `#` are ignored.
///
/// # File Format
///
/// ```text
/// # Internal networks
/// 10.0.0.0/8
/// 172.16.0.0/12
/// 192.168.0.0/16
///
/// # Specific IPs
/// 203.0.113.42
/// ```
///
/// # Arguments
///
/// File path to load IP addresses from.
#[derive(Debug, Clone)]
pub struct IpMatchFromFile {
    /// List of IP networks (CIDR blocks) loaded from file
    subnets: Vec<IpNet>,
}

impl IpMatchFromFile {
    /// Creates a new `IpMatchFromFile` operator by loading IPs from a file.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to file containing IP addresses (one per line); a relative
    ///   path is relative to the working directory
    ///
    /// # Returns
    ///
    /// `Ok(IpMatchFromFile)` if file was read and at least one valid IP was parsed,
    /// `Err` if file couldn't be read or no valid IPs were found.
    ///
    /// # File Format
    ///
    /// - One IP address or CIDR block per line
    /// - Empty lines are ignored
    /// - Lines starting with `#` are treated as comments and ignored
    /// - Invalid IP addresses are silently skipped
    pub fn new(file_path: impl AsRef<Path>) -> Result<Self, String> {
        let file_path = file_path.as_ref();
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read file {}: {}", file_path.display(), e))?;

        let mut subnets = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Auto-add CIDR suffix if not present
            let ip_with_cidr = if line.contains(':') && !line.contains('/') {
                // IPv6 without CIDR - add /128
                format!("{}/128", line)
            } else if line.contains('.') && !line.contains('/') {
                // IPv4 without CIDR - add /32
                format!("{}/32", line)
            } else {
                line.to_string()
            };

            // Parse CIDR notation
            match IpNet::from_str(&ip_with_cidr) {
                Ok(net) => subnets.push(net),
                Err(_) => {
                    // Silently skip invalid IPs (matches Go behavior)
                    continue;
                }
            }
        }

        if subnets.is_empty() {
            return Err(format!(
                "No valid IP addresses found in {}",
                file_path.display()
            ));
        }

        Ok(Self { subnets })
    }
}

impl Operator for IpMatchFromFile {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        // Parse input IP address
        let ip = match std::str::from_utf8(input).map(IpAddr::from_str) {
            Ok(Ok(ip)) => ip,
            _ => return false,
        };

        // Check if IP is in any of the subnets
        self.subnets.iter().any(|subnet| subnet.contains(&ip))
    }
}

/// Creates a new `@ipMatchFromFile` operator.
///
/// # Arguments
///
/// * `file_path` - Path to file containing IP addresses (one per line); a relative path
///   is relative to the working directory
pub fn ip_match_from_file(file_path: impl AsRef<Path>) -> Result<IpMatchFromFile, String> {
    IpMatchFromFile::new(file_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::Matches;

    #[test]
    fn test_ip_match_single_address() {
        // Test from Go: TestOneAddress
        let op = ip_match("127.0.0.1/32").unwrap();

        assert!(op.matches("127.0.0.1"));
        assert!(!op.matches("127.0.0.2"));
    }

    #[test]
    fn test_ip_match_multiple_addresses() {
        // Test from Go: TestMultipleAddress
        let op = ip_match("127.0.0.1, 192.168.0.0/24").unwrap();

        // Should match
        let addrs_ok = ["127.0.0.1", "192.168.0.1", "192.168.0.253"];
        for addr in &addrs_ok {
            assert!(op.matches(addr), "Expected {} to match", addr);
        }

        // Should not match
        let addrs_fail = ["127.0.0.2", "192.168.1.1"];
        for addr in &addrs_fail {
            assert!(!op.matches(addr), "Expected {} to not match", addr);
        }
    }

    #[test]
    fn test_ip_match_auto_cidr_ipv4() {
        // Test auto-adding /32 for IPv4 without CIDR
        let op = ip_match("192.168.1.100").unwrap();

        assert!(op.matches("192.168.1.100"));
        assert!(!op.matches("192.168.1.101"));
    }

    #[test]
    fn test_ip_match_auto_cidr_ipv6() {
        // Test auto-adding /128 for IPv6 without CIDR
        let op = ip_match("::1").unwrap();

        assert!(op.matches("::1"));
        assert!(!op.matches("::2"));
    }

    #[test]
    fn test_ip_match_ipv6_with_cidr() {
        let op = ip_match("2001:db8::/32").unwrap();

        assert!(op.matches("2001:db8::1"));
        assert!(op.matches("2001:db8:ffff::1"));
        assert!(!op.matches("2001:db9::1"));
    }

    #[test]
    fn test_ip_match_mixed_ipv4_ipv6() {
        let op = ip_match("127.0.0.1, ::1, 192.168.0.0/24, 2001:db8::/32").unwrap();

        // IPv4
        assert!(op.matches("127.0.0.1"));
        assert!(op.matches("192.168.0.50"));

        // IPv6
        assert!(op.matches("::1"));
        assert!(op.matches("2001:db8::1"));

        // Should not match
        assert!(!op.matches("127.0.0.2"));
        assert!(!op.matches("::2"));
    }

    #[test]
    fn test_ip_match_invalid_input() {
        let op = ip_match("192.168.1.0/24").unwrap();

        // Invalid IP addresses should return false
        assert!(!op.matches("not-an-ip"));
        assert!(!op.matches("999.999.999.999"));
        assert!(!op.matches(""));
    }

    #[test]
    fn test_ip_match_empty_list() {
        // Empty list should error
        let result = ip_match("");
        assert!(result.is_err());

        // Only whitespace should also error
        let result = ip_match("   ");
        assert!(result.is_err());
    }

    #[test]
    fn test_ip_match_skip_invalid_entries() {
        // Should skip invalid entries and continue (matches Go behavior)
        let op = ip_match("invalid, 192.168.1.0/24, also-invalid").unwrap();

        assert!(op.matches("192.168.1.100"));
        assert!(!op.matches("10.0.0.1"));
    }

    #[test]
    fn test_ip_match_whitespace_handling() {
        // Should handle whitespace properly
        let op = ip_match("  192.168.1.100  ,  10.0.0.0/8  ").unwrap();

        assert!(op.matches("192.168.1.100"));
        assert!(op.matches("10.5.10.20"));
    }

    #[test]
    fn test_ip_match_large_cidr_blocks() {
        // Test common network ranges
        let op = ip_match("10.0.0.0/8,172.16.0.0/12,192.168.0.0/16").unwrap();

        // Class A private
        assert!(op.matches("10.0.0.1"));
        assert!(op.matches("10.255.255.254"));

        // Class B private
        assert!(op.matches("172.16.0.1"));
        assert!(op.matches("172.31.255.254"));

        // Class C private
        assert!(op.matches("192.168.0.1"));
        assert!(op.matches("192.168.255.254"));

        // Public IP should not match
        assert!(!op.matches("8.8.8.8"));
    }

    #[test]
    fn test_ip_match_from_file() {
        use std::io::Write;

        // Create temporary file with IP addresses
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(temp_file, "# Comment line").unwrap();
        writeln!(temp_file).unwrap(); // Empty line
        writeln!(temp_file, "192.168.1.0/24").unwrap();
        writeln!(temp_file, "10.0.0.1").unwrap();
        writeln!(temp_file, "# Another comment").unwrap();
        writeln!(temp_file, "172.16.0.0/16").unwrap();
        temp_file.flush().unwrap();

        let op = ip_match_from_file(temp_file.path().to_str().unwrap()).unwrap();

        // Should match IPs from file
        assert!(op.matches("192.168.1.100"));
        assert!(op.matches("10.0.0.1"));
        assert!(op.matches("172.16.50.25"));

        // Should not match other IPs
        assert!(!op.matches("192.168.2.1"));
        assert!(!op.matches("8.8.8.8"));
    }

    #[test]
    fn test_ip_match_from_file_empty() {
        use std::io::Write;

        // Create file with only comments and empty lines
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(temp_file, "# Just comments").unwrap();
        writeln!(temp_file).unwrap();
        temp_file.flush().unwrap();

        let result = ip_match_from_file(temp_file.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No valid IP addresses"));
    }

    #[test]
    fn test_ip_match_from_file_not_found() {
        let result = ip_match_from_file("/nonexistent/file.txt");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to read file"));
    }

    /// The doc example of `operators::ip::IpMatch`, before it became internal.
    #[test]
    fn doc_ip_match_type() {
        use crate::operators::Operator;
        use crate::operators::ip::ip_match;
        // Block specific IPs and ranges
        let op = ip_match("192.168.1.100,192.168.1.50,10.10.50.0/24").unwrap();
        let tx = crate::waf::Waf::default().new_transaction();
        let mut out = crate::operators::Outputs::default();
        assert!(op.evaluate(&tx, "192.168.1.100".as_bytes(), &mut out));
        assert!(op.evaluate(&tx, "10.10.50.25".as_bytes(), &mut out));
        assert!(!op.evaluate(&tx, "192.168.1.101".as_bytes(), &mut out));

        // Match internal network
        let op = ip_match("10.0.0.0/8,172.16.0.0/12").unwrap();
        assert!(op.evaluate(&tx, "10.5.10.20".as_bytes(), &mut out));
        assert!(op.evaluate(&tx, "172.16.0.1".as_bytes(), &mut out));
        assert!(!op.evaluate(&tx, "192.168.1.1".as_bytes(), &mut out));

        // IPv6 support
        let op = ip_match("::1,2001:db8::/32").unwrap();
        assert!(op.evaluate(&tx, "::1".as_bytes(), &mut out));
        assert!(op.evaluate(&tx, "2001:db8::1".as_bytes(), &mut out));
        assert!(!op.evaluate(&tx, "::2".as_bytes(), &mut out));
    }

    /// The doc example of `operators::ip::ip_match`, before it became internal.
    #[test]
    fn doc_ip_match() {
        use crate::operators::Operator;
        use crate::operators::ip::ip_match;
        let op = ip_match("192.168.1.0/24").unwrap();
        let tx = crate::waf::Waf::default().new_transaction();
        let mut out = crate::operators::Outputs::default();
        assert!(op.evaluate(&tx, "192.168.1.100".as_bytes(), &mut out));
    }
}
