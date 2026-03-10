//! Complex text processing transformations.
//!
//! This module provides advanced transformations for decoding various formats
//! and normalizing file paths.

// Note: This module doesn't use string utils directly, but escape.rs does

/// HTML entity decoding transformation.
///
/// Decodes HTML entities (both named entities like `&lt;` and numeric entities
/// like `&#60;` or `&#x3C;`) into their corresponding characters.
///
/// # Arguments
///
/// * `input` - Input string that may contain HTML entities
///
/// # Returns
///
/// Returns `(output, changed)` where:
/// - `output` is the decoded string
/// - `changed` is `true` if any entities were decoded, `false` otherwise
///
/// # Examples
///
/// ```
/// # use coraza::transformations::complex::html_entity_decode;
/// let (result, changed) = html_entity_decode("&lt;script&gt;");
/// assert_eq!(result, "<script>");
/// assert!(changed);
///
/// let (result, changed) = html_entity_decode("no entities here");
/// assert_eq!(result, "no entities here");
/// assert!(!changed);
///
/// let (result, changed) = html_entity_decode("&#60;&#x3E;");
/// assert_eq!(result, "<>");
/// assert!(changed);
/// ```
pub fn html_entity_decode(input: &str) -> (String, bool) {
    let decoded = htmlescape::decode_html(input).unwrap_or_else(|_| input.to_string());
    let changed = decoded != input;
    (decoded, changed)
}

/// Path normalization transformation (Unix-style).
///
/// Normalizes file paths by:
/// - Removing redundant slashes (`//` → `/`)
/// - Resolving `.` (current directory)
/// - Resolving `..` (parent directory)
/// - Converting `.` to empty string
/// - Preserving trailing slashes
///
/// # Arguments
///
/// * `input` - Input path string
///
/// # Returns
///
/// Returns `(output, changed)` where:
/// - `output` is the normalized path
/// - `changed` is `true` if the path was modified, `false` otherwise
///
/// # Examples
///
/// ```
/// # use coraza::transformations::complex::normalise_path;
/// let (result, changed) = normalise_path("/foo//bar");
/// assert_eq!(result, "/foo/bar");
/// assert!(changed);
///
/// let (result, changed) = normalise_path("dir/../foo");
/// assert_eq!(result, "foo");
/// assert!(changed);
///
/// let (result, changed) = normalise_path("/foo/bar/");
/// assert_eq!(result, "/foo/bar/");
/// assert!(!changed);
///
/// // Special case: "." becomes empty string
/// let (result, changed) = normalise_path(".");
/// assert_eq!(result, "");
/// assert!(changed);
/// ```
pub fn normalise_path(input: &str) -> (String, bool) {
    if input.is_empty() {
        return (String::new(), false);
    }

    // Use path_clean to normalize the path and convert to string
    let clean_path = path_clean::clean(input);
    let clean = clean_path.to_string_lossy().to_string();

    // Special case: "." becomes empty string (ModSecurity behavior)
    if clean == "." {
        return (String::new(), true);
    }

    // Preserve trailing slash if original had one
    let result = if input.ends_with('/') && !clean.ends_with('/') {
        format!("{}/", clean)
    } else {
        clean
    };

    let changed = result != input;
    (result, changed)
}

/// Path normalization transformation (Windows-style).
///
/// Normalizes Windows file paths by:
/// - Converting backslashes (`\`) to forward slashes (`/`)
/// - Then applying Unix-style normalization
///
/// # Arguments
///
/// * `input` - Input path string (Windows-style with backslashes)
///
/// # Returns
///
/// Returns `(output, changed)` where:
/// - `output` is the normalized path with forward slashes
/// - `changed` is `true` if the path was modified, `false` otherwise
///
/// # Examples
///
/// ```
/// # use coraza::transformations::complex::normalise_path_win;
/// let (result, changed) = normalise_path_win("\\foo\\bar\\baz");
/// assert_eq!(result, "/foo/bar/baz");
/// assert!(changed);
///
/// let (result, changed) = normalise_path_win("dir\\..\\foo");
/// assert_eq!(result, "foo");
/// assert!(changed);
///
/// let (result, changed) = normalise_path_win("dir\\\\foo\\\\bar");
/// assert_eq!(result, "dir/foo/bar");
/// assert!(changed);
/// ```
pub fn normalise_path_win(input: &str) -> (String, bool) {
    if input.is_empty() {
        return (String::new(), false);
    }

    // Convert backslashes to forward slashes
    let converted = input.replace('\\', "/");
    let backslash_converted = converted != input;

    // Apply Unix-style normalization
    let (result, path_normalized) = normalise_path(&converted);

    // Changed if either backslashes were converted OR path was normalized
    let changed = backslash_converted || path_normalized;

    (result, changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test cases from htmlEntityDecode.json
    #[test]
    fn test_html_entity_decode_empty() {
        let (result, changed) = html_entity_decode("");
        assert_eq!(result, "");
        assert!(!changed);
    }

    #[test]
    fn test_html_entity_decode_no_entities() {
        let (result, changed) = html_entity_decode("TestCase");
        assert_eq!(result, "TestCase");
        assert!(!changed);
    }

    #[test]
    fn test_html_entity_decode_with_null() {
        let (result, changed) = html_entity_decode("Test\u{0000}Case");
        assert_eq!(result, "Test\u{0000}Case");
        assert!(!changed);
    }

    #[test]
    fn test_html_entity_decode_named_entities() {
        let (result, changed) = html_entity_decode("&lt;script&gt;");
        assert_eq!(result, "<script>");
        assert!(changed);
    }

    #[test]
    fn test_html_entity_decode_numeric_entities() {
        let (result, changed) = html_entity_decode("&#60;&#62;");
        assert_eq!(result, "<>");
        assert!(changed);
    }

    #[test]
    fn test_html_entity_decode_hex_entities() {
        let (result, changed) = html_entity_decode("&#x3C;&#x3E;");
        assert_eq!(result, "<>");
        assert!(changed);
    }

    // Test cases from normalisePath.json
    #[test]
    fn test_normalise_path_empty() {
        let (result, changed) = normalise_path("");
        assert_eq!(result, "");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_simple() {
        let (result, changed) = normalise_path("/foo/bar/baz");
        assert_eq!(result, "/foo/bar/baz");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_with_null() {
        let (result, changed) = normalise_path("/foo/bar\u{0000}/baz");
        assert_eq!(result, "/foo/bar\u{0000}/baz");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_single_char() {
        let (result, changed) = normalise_path("x");
        assert_eq!(result, "x");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_dot() {
        let (result, changed) = normalise_path(".");
        assert_eq!(result, "");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_dot_slash() {
        let (result, changed) = normalise_path("./");
        assert_eq!(result, "");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_dot_dotdot() {
        let (result, changed) = normalise_path("./..");
        assert_eq!(result, "..");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_dot_dotdot_slash() {
        let (result, changed) = normalise_path("./../");
        assert_eq!(result, "../");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_dotdot() {
        let (result, changed) = normalise_path("..");
        assert_eq!(result, "..");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_dotdot_slash() {
        let (result, changed) = normalise_path("../");
        assert_eq!(result, "../");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_dotdot_dot() {
        let (result, changed) = normalise_path("../.");
        assert_eq!(result, "..");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_dotdot_dot_slash() {
        let (result, changed) = normalise_path(".././");
        assert_eq!(result, "../");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_dotdot_dotdot() {
        let (result, changed) = normalise_path("../..");
        assert_eq!(result, "../..");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_dotdot_dotdot_slash() {
        let (result, changed) = normalise_path("../../");
        assert_eq!(result, "../../");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_double_slash() {
        let (result, changed) = normalise_path("/dir/foo//bar");
        assert_eq!(result, "/dir/foo/bar");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_double_slash_trailing() {
        let (result, changed) = normalise_path("dir/foo//bar/");
        assert_eq!(result, "dir/foo/bar/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_parent_dir() {
        let (result, changed) = normalise_path("dir/../foo");
        assert_eq!(result, "foo");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_double_parent() {
        let (result, changed) = normalise_path("dir/../../foo");
        assert_eq!(result, "../foo");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_complex1() {
        let (result, changed) = normalise_path("dir/./.././../../foo/bar");
        assert_eq!(result, "../../foo/bar");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_complex2() {
        let (result, changed) = normalise_path("dir/./.././../../foo/bar/.");
        assert_eq!(result, "../../foo/bar");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_complex3() {
        let (result, changed) = normalise_path("dir/./.././../../foo/bar/./");
        assert_eq!(result, "../../foo/bar/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_complex4() {
        let (result, changed) = normalise_path("dir/./.././../../foo/bar/..");
        assert_eq!(result, "../../foo");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_complex5() {
        let (result, changed) = normalise_path("dir/./.././../../foo/bar/../");
        assert_eq!(result, "../../foo/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_complex6() {
        let (result, changed) = normalise_path("dir/./.././../../foo/bar/");
        assert_eq!(result, "../../foo/bar/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_complex7() {
        let (result, changed) = normalise_path("dir//.//..//.//..//..//foo//bar");
        assert_eq!(result, "../../foo/bar");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_complex8() {
        let (result, changed) = normalise_path("dir//.//..//.//..//..//foo//bar//");
        assert_eq!(result, "../../foo/bar/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_multiple_parent1() {
        let (result, changed) = normalise_path("dir/subdir/subsubdir/subsubsubdir/../../..");
        assert_eq!(result, "dir");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_multiple_parent2() {
        let (result, changed) = normalise_path("dir/./subdir/./subsubdir/./subsubsubdir/../../..");
        assert_eq!(result, "dir");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_multiple_parent3() {
        let (result, changed) = normalise_path("dir/./subdir/../subsubdir/../subsubsubdir/..");
        assert_eq!(result, "dir");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_multiple_parent4() {
        let (result, changed) = normalise_path("/dir/./subdir/../subsubdir/../subsubsubdir/../");
        assert_eq!(result, "/dir/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_path_traversal() {
        let (result, changed) =
            normalise_path("/./.././../../../../../../../\u{0000}/../etc/./passwd");
        assert_eq!(result, "/etc/passwd");
        assert!(changed);
    }

    // Test cases from normalisePathWin.json
    #[test]
    fn test_normalise_path_win_empty() {
        let (result, changed) = normalise_path_win("");
        assert_eq!(result, "");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_win_backslash() {
        let (result, changed) = normalise_path_win("\\foo\\bar\\baz");
        assert_eq!(result, "/foo/bar/baz");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_with_null() {
        let (result, changed) = normalise_path_win("\\foo\\bar\u{0000}\\baz");
        assert_eq!(result, "/foo/bar\u{0000}/baz");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_single_char() {
        let (result, changed) = normalise_path_win("x");
        assert_eq!(result, "x");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_win_dot() {
        let (result, changed) = normalise_path_win(".");
        assert_eq!(result, "");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_dot_backslash() {
        let (result, changed) = normalise_path_win(".\\");
        assert_eq!(result, "");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_dot_dotdot() {
        let (result, changed) = normalise_path_win(".\\..");
        assert_eq!(result, "..");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_dot_dotdot_backslash() {
        let (result, changed) = normalise_path_win(".\\..\\");
        assert_eq!(result, "../");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_dotdot() {
        let (result, changed) = normalise_path_win("..");
        assert_eq!(result, "..");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_win_dotdot_backslash() {
        let (result, changed) = normalise_path_win("..\\");
        assert_eq!(result, "../");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_dotdot_dot() {
        let (result, changed) = normalise_path_win("..\\.");
        assert_eq!(result, "..");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_dotdot_dot_backslash() {
        let (result, changed) = normalise_path_win("..\\.\\");
        assert_eq!(result, "../");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_dotdot_dotdot() {
        let (result, changed) = normalise_path_win("..\\..");
        assert_eq!(result, "../..");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_dotdot_dotdot_backslash() {
        let (result, changed) = normalise_path_win("..\\..\\");
        assert_eq!(result, "../../");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_double_backslash() {
        let (result, changed) = normalise_path_win("\\dir\\foo\\\\bar");
        assert_eq!(result, "/dir/foo/bar");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_double_backslash_trailing() {
        let (result, changed) = normalise_path_win("dir\\foo\\\\bar\\");
        assert_eq!(result, "dir/foo/bar/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_parent_dir() {
        let (result, changed) = normalise_path_win("dir\\..\\foo");
        assert_eq!(result, "foo");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_double_parent() {
        let (result, changed) = normalise_path_win("dir\\..\\..\\foo");
        assert_eq!(result, "../foo");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_complex1() {
        let (result, changed) = normalise_path_win("dir\\.\\..\\.\\..\\..\\foo\\bar");
        assert_eq!(result, "../../foo/bar");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_complex2() {
        let (result, changed) = normalise_path_win("dir\\.\\..\\.\\..\\..\\foo\\bar\\.");
        assert_eq!(result, "../../foo/bar");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_complex3() {
        let (result, changed) = normalise_path_win("dir\\.\\..\\.\\..\\..\\foo\\bar\\.\\");
        assert_eq!(result, "../../foo/bar/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_complex4() {
        let (result, changed) = normalise_path_win("dir\\.\\..\\.\\..\\..\\foo\\bar\\..");
        assert_eq!(result, "../../foo");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_complex5() {
        let (result, changed) = normalise_path_win("dir\\.\\..\\.\\..\\..\\foo\\bar\\..\\");
        assert_eq!(result, "../../foo/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_complex6() {
        let (result, changed) = normalise_path_win("dir\\.\\..\\.\\..\\..\\foo\\bar\\");
        assert_eq!(result, "../../foo/bar/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_complex7() {
        let (result, changed) = normalise_path_win("dir\\\\.\\\\..\\\\.\\\\..\\\\..\\\\foo\\\\bar");
        assert_eq!(result, "../../foo/bar");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_complex8() {
        let (result, changed) =
            normalise_path_win("dir\\\\.\\\\..\\\\.\\\\..\\\\..\\\\foo\\\\bar\\\\");
        assert_eq!(result, "../../foo/bar/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_multiple_parent1() {
        let (result, changed) =
            normalise_path_win("dir\\subdir\\subsubdir\\subsubsubdir\\..\\..\\..");
        assert_eq!(result, "dir");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_multiple_parent2() {
        let (result, changed) =
            normalise_path_win("dir\\.\\subdir\\.\\subsubdir\\.\\subsubsubdir\\..\\..\\..");
        assert_eq!(result, "dir");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_multiple_parent3() {
        let (result, changed) =
            normalise_path_win("dir\\.\\subdir\\..\\subsubdir\\..\\subsubsubdir\\..");
        assert_eq!(result, "dir");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_multiple_parent4() {
        let (result, changed) =
            normalise_path_win("\\dir\\.\\subdir\\..\\subsubdir\\..\\subsubsubdir\\..\\");
        assert_eq!(result, "/dir/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_path_traversal() {
        let (result, changed) =
            normalise_path_win("\\.\\..\\.\\..\\..\\..\\..\\..\\..\\..\\\\0\\..\\etc\\.\\passwd");
        assert_eq!(result, "/etc/passwd");
        assert!(changed);
    }
}
