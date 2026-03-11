//! IP address matching operators.
//!
//! This module provides operators for matching IP addresses against CIDR blocks
//! and IP ranges, compatible with ModSecurity's @ipMatch family of operators.

use crate::operators::Operator;
use crate::operators::macros::TransactionState;
use ipnet::IpNet;
use std::net::IpAddr;
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
///
/// # Examples
///
/// ```
/// # use coraza::operators::ip::ip_match;
/// # use coraza::operators::Operator;
/// // Block specific IPs and ranges
/// let op = ip_match("192.168.1.100,192.168.1.50,10.10.50.0/24").unwrap();
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "192.168.1.100"));
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "10.10.50.25"));
/// assert!(!op.evaluate(None::<&mut coraza::transaction::Transaction>, "192.168.1.101"));
///
/// // Match internal network
/// let op = ip_match("10.0.0.0/8,172.16.0.0/12").unwrap();
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "10.5.10.20"));
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "172.16.0.1"));
/// assert!(!op.evaluate(None::<&mut coraza::transaction::Transaction>, "192.168.1.1"));
///
/// // IPv6 support
/// let op = ip_match("::1,2001:db8::/32").unwrap();
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "::1"));
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "2001:db8::1"));
/// assert!(!op.evaluate(None::<&mut coraza::transaction::Transaction>, "::2"));
/// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// # use coraza::operators::ip::IpMatch;
    /// let op = IpMatch::new("192.168.1.0/24,10.0.0.1").unwrap();
    /// ```
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
    fn evaluate<TX: TransactionState>(&self, _tx: Option<&mut TX>, input: &str) -> bool {
        // Parse the input IP address
        let ip = match IpAddr::from_str(input) {
            Ok(ip) => ip,
            Err(_) => return false,
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
///
/// # Examples
///
/// ```
/// # use coraza::operators::ip::ip_match;
/// # use coraza::operators::Operator;
/// let op = ip_match("192.168.1.0/24").unwrap();
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "192.168.1.100"));
/// ```
pub fn ip_match(ips: &str) -> Result<IpMatch, String> {
    IpMatch::new(ips)
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
///
/// # Examples
///
/// ```no_run
/// # use coraza::operators::ip::ip_match_from_file;
/// # use coraza::operators::Operator;
/// let op = ip_match_from_file("/etc/coraza/blocked-ips.txt").unwrap();
/// assert!(op.evaluate(None::<&mut coraza::transaction::Transaction>, "10.0.0.1"));
/// ```
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
    /// * `file_path` - Path to file containing IP addresses (one per line)
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
    pub fn new(file_path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read file {}: {}", file_path, e))?;

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
            return Err(format!("No valid IP addresses found in {}", file_path));
        }

        Ok(Self { subnets })
    }
}

impl Operator for IpMatchFromFile {
    fn evaluate<TX: TransactionState>(&self, _tx: Option<&mut TX>, input: &str) -> bool {
        // Parse input IP address
        let ip = match IpAddr::from_str(input) {
            Ok(ip) => ip,
            Err(_) => return false,
        };

        // Check if IP is in any of the subnets
        self.subnets.iter().any(|subnet| subnet.contains(&ip))
    }
}

/// Creates a new `@ipMatchFromFile` operator.
///
/// # Arguments
///
/// * `file_path` - Path to file containing IP addresses (one per line)
///
/// # Examples
///
/// ```no_run
/// # use coraza::operators::ip_match_from_file;
/// let op = ip_match_from_file("/etc/coraza/blocked-ips.txt").unwrap();
/// ```
pub fn ip_match_from_file(file_path: &str) -> Result<IpMatchFromFile, String> {
    IpMatchFromFile::new(file_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::Transaction;

    #[test]
    fn test_ip_match_single_address() {
        // Test from Go: TestOneAddress
        let op = ip_match("127.0.0.1/32").unwrap();

        assert!(op.evaluate(None::<&mut Transaction>, "127.0.0.1"));
        assert!(!op.evaluate(None::<&mut Transaction>, "127.0.0.2"));
    }

    #[test]
    fn test_ip_match_multiple_addresses() {
        // Test from Go: TestMultipleAddress
        let op = ip_match("127.0.0.1, 192.168.0.0/24").unwrap();

        // Should match
        let addrs_ok = ["127.0.0.1", "192.168.0.1", "192.168.0.253"];
        for addr in &addrs_ok {
            assert!(
                op.evaluate(None::<&mut Transaction>, addr),
                "Expected {} to match",
                addr
            );
        }

        // Should not match
        let addrs_fail = ["127.0.0.2", "192.168.1.1"];
        for addr in &addrs_fail {
            assert!(
                !op.evaluate(None::<&mut Transaction>, addr),
                "Expected {} to not match",
                addr
            );
        }
    }

    #[test]
    fn test_ip_match_auto_cidr_ipv4() {
        // Test auto-adding /32 for IPv4 without CIDR
        let op = ip_match("192.168.1.100").unwrap();

        assert!(op.evaluate(None::<&mut Transaction>, "192.168.1.100"));
        assert!(!op.evaluate(None::<&mut Transaction>, "192.168.1.101"));
    }

    #[test]
    fn test_ip_match_auto_cidr_ipv6() {
        // Test auto-adding /128 for IPv6 without CIDR
        let op = ip_match("::1").unwrap();

        assert!(op.evaluate(None::<&mut Transaction>, "::1"));
        assert!(!op.evaluate(None::<&mut Transaction>, "::2"));
    }

    #[test]
    fn test_ip_match_ipv6_with_cidr() {
        let op = ip_match("2001:db8::/32").unwrap();

        assert!(op.evaluate(None::<&mut Transaction>, "2001:db8::1"));
        assert!(op.evaluate(None::<&mut Transaction>, "2001:db8:ffff::1"));
        assert!(!op.evaluate(None::<&mut Transaction>, "2001:db9::1"));
    }

    #[test]
    fn test_ip_match_mixed_ipv4_ipv6() {
        let op = ip_match("127.0.0.1, ::1, 192.168.0.0/24, 2001:db8::/32").unwrap();

        // IPv4
        assert!(op.evaluate(None::<&mut Transaction>, "127.0.0.1"));
        assert!(op.evaluate(None::<&mut Transaction>, "192.168.0.50"));

        // IPv6
        assert!(op.evaluate(None::<&mut Transaction>, "::1"));
        assert!(op.evaluate(None::<&mut Transaction>, "2001:db8::1"));

        // Should not match
        assert!(!op.evaluate(None::<&mut Transaction>, "127.0.0.2"));
        assert!(!op.evaluate(None::<&mut Transaction>, "::2"));
    }

    #[test]
    fn test_ip_match_invalid_input() {
        let op = ip_match("192.168.1.0/24").unwrap();

        // Invalid IP addresses should return false
        assert!(!op.evaluate(None::<&mut Transaction>, "not-an-ip"));
        assert!(!op.evaluate(None::<&mut Transaction>, "999.999.999.999"));
        assert!(!op.evaluate(None::<&mut Transaction>, ""));
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

        assert!(op.evaluate(None::<&mut Transaction>, "192.168.1.100"));
        assert!(!op.evaluate(None::<&mut Transaction>, "10.0.0.1"));
    }

    #[test]
    fn test_ip_match_whitespace_handling() {
        // Should handle whitespace properly
        let op = ip_match("  192.168.1.100  ,  10.0.0.0/8  ").unwrap();

        assert!(op.evaluate(None::<&mut Transaction>, "192.168.1.100"));
        assert!(op.evaluate(None::<&mut Transaction>, "10.5.10.20"));
    }

    #[test]
    fn test_ip_match_large_cidr_blocks() {
        // Test common network ranges
        let op = ip_match("10.0.0.0/8,172.16.0.0/12,192.168.0.0/16").unwrap();

        // Class A private
        assert!(op.evaluate(None::<&mut Transaction>, "10.0.0.1"));
        assert!(op.evaluate(None::<&mut Transaction>, "10.255.255.254"));

        // Class B private
        assert!(op.evaluate(None::<&mut Transaction>, "172.16.0.1"));
        assert!(op.evaluate(None::<&mut Transaction>, "172.31.255.254"));

        // Class C private
        assert!(op.evaluate(None::<&mut Transaction>, "192.168.0.1"));
        assert!(op.evaluate(None::<&mut Transaction>, "192.168.255.254"));

        // Public IP should not match
        assert!(!op.evaluate(None::<&mut Transaction>, "8.8.8.8"));
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
        assert!(op.evaluate(None::<&mut Transaction>, "192.168.1.100"));
        assert!(op.evaluate(None::<&mut Transaction>, "10.0.0.1"));
        assert!(op.evaluate(None::<&mut Transaction>, "172.16.50.25"));

        // Should not match other IPs
        assert!(!op.evaluate(None::<&mut Transaction>, "192.168.2.1"));
        assert!(!op.evaluate(None::<&mut Transaction>, "8.8.8.8"));
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
}
