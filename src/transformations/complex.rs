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

/// Command line normalization transformation.
///
/// Normalizes command-line input by applying the following transformations:
/// - Deletes backslashes (`\`), double quotes (`"`), single quotes (`'`), carets (`^`)
/// - Replaces commas (`,`), semicolons (`;`), and whitespace with single space
/// - Removes spaces before slashes (`/`) and open parentheses (`(`)
/// - Compresses multiple spaces into one
/// - Converts to lowercase
///
/// This transformation is useful for detecting command injection attempts.
///
/// # Arguments
///
/// * `input` - Input string to normalize
///
/// # Returns
///
/// Returns `(output, changed)` where:
/// - `output` is the normalized string
/// - `changed` is `true` if any transformations were applied, `false` otherwise
///
/// # Examples
///
/// ```
/// # use coraza::transformations::complex::cmd_line;
/// let (result, changed) = cmd_line("cmd.exe /c \"whoami\"");
/// assert_eq!(result, "cmd.exe/c whoami");
/// assert!(changed);
///
/// let (result, changed) = cmd_line("SELECT * FROM users WHERE id=1;");
/// assert_eq!(result, "select * from users where id=1 ");
/// assert!(changed);
/// ```
pub fn cmd_line(input: &str) -> (String, bool) {
    // Check if transformation is needed
    if let Some(pos) = input.bytes().position(needs_cmd_transform) {
        (do_cmd_line(input, pos), true)
    } else {
        (input.to_string(), false)
    }
}

fn do_cmd_line(input: &str, pos: usize) -> String {
    let mut result = String::with_capacity(input.len());

    // Copy prefix before first transformable character
    result.push_str(&input[..pos]);

    let mut space = false;

    for c in input[pos..].bytes() {
        match c {
            // Remove these characters
            b'"' | b'\'' | b'\\' | b'^' => {
                // Skip these characters entirely
            }
            // Replace with space (compress multiple)
            b' ' | b',' | b';' | b'\t' | b'\r' | b'\n' => {
                if !space {
                    result.push(' ');
                    space = true;
                }
            }
            // Remove space before / or (
            b'/' | b'(' => {
                if space && !result.is_empty() {
                    result.pop(); // Remove the trailing space
                }
                space = false;
                result.push(c as char);
            }
            // Regular character - lowercase if needed
            _ => {
                let lower = if c.is_ascii_uppercase() {
                    c + (b'a' - b'A')
                } else {
                    c
                };
                result.push(lower as char);
                space = false;
            }
        }
    }

    result
}

/// Check if a byte needs command-line transformation
fn needs_cmd_transform(c: u8) -> bool {
    c.is_ascii_uppercase()
        || matches!(
            c,
            b'"' | b'\'' | b'\\' | b'^' | b' ' | b',' | b';' | b'\t' | b'\r' | b'\n' | b'/' | b'('
        )
}

/// Remove comment markers from text.
///
/// Removes the following comment styles:
/// - C-style: `/* comment */`
/// - HTML-style: `<!-- comment -->`
/// - SQL/shell single-line: `--` (removes rest of line)
/// - Shell/Perl: `#` (removes rest of line)
///
/// Content between comment delimiters is removed, and end-of-line comments
/// are replaced with a space. Following ModSecurity behavior, when a comment
/// ends exactly at the end of the input, a null byte is appended.
///
/// # Arguments
///
/// * `input` - Input string that may contain comments
///
/// # Returns
///
/// Returns `(output, changed)` where:
/// - `output` is the string with comments removed
/// - `changed` is `true` if any comments were found, `false` otherwise
///
/// # Examples
///
/// ```
/// # use coraza::transformations::complex::remove_comments;
/// let (result, changed) = remove_comments("SELECT * FROM users /* comment */ WHERE id=1");
/// assert_eq!(result, "SELECT * FROM users  WHERE id=1");
/// assert!(changed);
///
/// let (result, changed) = remove_comments("<!-- HTML comment --> <div>content</div>");
/// assert_eq!(result, " <div>content</div>");
/// assert!(changed);
/// ```
pub fn remove_comments(input: &str) -> (String, bool) {
    // Add null byte padding to match ModSecurity behavior
    let mut input_with_padding = input.as_bytes().to_vec();
    input_with_padding.push(b'\0');

    let input_len = input.len(); // Original length without padding
    let mut result = Vec::with_capacity(input_len);

    let mut i = 0;
    let mut in_comment = false;
    let mut changed = false;

    while i < input_len {
        if !in_comment {
            if i + 1 < input_len
                && input_with_padding[i] == b'/'
                && input_with_padding[i + 1] == b'*'
            {
                // Start of C-style comment /*
                in_comment = true;
                changed = true;
                i += 2;
            } else if i + 3 < input_len
                && input_with_padding[i] == b'<'
                && input_with_padding[i + 1] == b'!'
                && input_with_padding[i + 2] == b'-'
                && input_with_padding[i + 3] == b'-'
            {
                // Start of HTML comment <!--
                in_comment = true;
                changed = true;
                i += 4;
            } else if i + 1 < input_len
                && input_with_padding[i] == b'-'
                && input_with_padding[i + 1] == b'-'
            {
                // SQL-style comment -- (rest of line)
                result.push(b' ');
                changed = true;
                break;
            } else if input_with_padding[i] == b'#' {
                // Shell-style comment # (rest of line)
                result.push(b' ');
                changed = true;
                break;
            } else {
                // Regular character
                result.push(input_with_padding[i]);
                i += 1;
            }
        } else {
            // Inside a comment
            if i + 1 < input_len
                && input_with_padding[i] == b'*'
                && input_with_padding[i + 1] == b'/'
            {
                // End of C-style comment */
                in_comment = false;
                i += 2;
                // Copy the next character after comment (may be null byte padding)
                result.push(input_with_padding[i]);
                i += 1;
            } else if i + 2 < input_len
                && input_with_padding[i] == b'-'
                && input_with_padding[i + 1] == b'-'
                && input_with_padding[i + 2] == b'>'
            {
                // End of HTML comment -->
                in_comment = false;
                i += 3;
                // Copy the next character after comment (may be null byte padding)
                result.push(input_with_padding[i]);
                i += 1;
            } else {
                // Skip characters inside comment
                i += 1;
            }
        }
    }

    // If still in comment at end, add space
    if in_comment {
        changed = true;
        result.push(b' ');
    }

    (String::from_utf8_lossy(&result).into_owned(), changed)
}

/// Replace C-style comments with spaces.
///
/// Replaces C-style comments (`/* comment */`) with a single space.
/// Unlike `remove_comments`, this only handles C-style comments and
/// replaces them with a space rather than removing them entirely.
///
/// # Arguments
///
/// * `input` - Input string that may contain C-style comments
///
/// # Returns
///
/// Returns `(output, changed)` where:
/// - `output` is the string with comments replaced by spaces
/// - `changed` is `true` if any comments were found, `false` otherwise
///
/// # Examples
///
/// ```
/// # use coraza::transformations::complex::replace_comments;
/// let (result, changed) = replace_comments("SELECT * FROM users /* comment */ WHERE id=1");
/// assert_eq!(result, "SELECT * FROM users   WHERE id=1");
/// assert!(changed);
///
/// let (result, changed) = replace_comments("no comments here");
/// assert_eq!(result, "no comments here");
/// assert!(!changed);
/// ```
pub fn replace_comments(input: &str) -> (String, bool) {
    let input_bytes = input.as_bytes();
    let input_len = input_bytes.len();
    let mut result = Vec::with_capacity(input_len);

    let mut i = 0;
    let mut in_comment = false;
    let mut changed = false;

    while i < input_len {
        if !in_comment {
            if i + 1 < input_len && input_bytes[i] == b'/' && input_bytes[i + 1] == b'*' {
                // Start of C-style comment /*
                in_comment = true;
                changed = true;
                i += 2;
            } else {
                // Regular character
                result.push(input_bytes[i]);
                i += 1;
            }
        } else {
            // Inside a comment
            if i + 1 < input_len && input_bytes[i] == b'*' && input_bytes[i + 1] == b'/' {
                // End of C-style comment */
                in_comment = false;
                i += 2;
                result.push(b' ');
            } else {
                // Skip characters inside comment
                i += 1;
            }
        }
    }

    // If still in comment at end, add space
    if in_comment {
        result.push(b' ');
    }

    (String::from_utf8_lossy(&result).into_owned(), changed)
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

    // Test cases from cmdLine.json

    #[test]
    fn test_cmd_line_empty() {
        let (result, changed) = cmd_line("");
        assert_eq!(result, "");
        assert!(!changed);
    }

    #[test]
    fn test_cmd_line_no_transform() {
        let (result, changed) = cmd_line("test");
        assert_eq!(result, "test");
        assert!(!changed);
    }

    #[test]
    fn test_cmd_line_caret_and_case() {
        let (result, changed) = cmd_line("C^OMMAND /C DIR");
        assert_eq!(result, "command/c dir");
        assert!(changed);
    }

    #[test]
    fn test_cmd_line_mixed_case() {
        let (result, changed) = cmd_line("C^oMMaNd /C DiR");
        assert_eq!(result, "command/c dir");
        assert!(changed);
    }

    #[test]
    fn test_cmd_line_comma() {
        let (result, changed) = cmd_line("cmd,/c DiR");
        assert_eq!(result, "cmd/c dir");
        assert!(changed);
    }

    #[test]
    fn test_cmd_line_quotes() {
        let (result, changed) = cmd_line("\"command\" /c DiR");
        assert_eq!(result, "command/c dir");
        assert!(changed);
    }

    // Test cases from removeComments.json

    #[test]
    fn test_remove_comments_empty() {
        let (result, changed) = remove_comments("");
        assert_eq!(result, "");
        assert!(!changed);
    }

    #[test]
    fn test_remove_comments_no_comments() {
        let (result, changed) = remove_comments("TestCase");
        assert_eq!(result, "TestCase");
        assert!(!changed);
    }

    #[test]
    fn test_remove_comments_with_null() {
        let (result, changed) = remove_comments("Test\u{0000}Case");
        assert_eq!(result, "Test\u{0000}Case");
        assert!(!changed);
    }

    #[test]
    fn test_remove_comments_full_comment() {
        let (result, changed) = remove_comments("/* TestCase */");
        assert_eq!(result, "\u{0000}");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_no_spaces() {
        let (result, changed) = remove_comments("/*TestCase*/");
        assert_eq!(result, "\u{0000}");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_space_before() {
        let (result, changed) = remove_comments("/* TestCase*/");
        assert_eq!(result, "\u{0000}");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_space_after() {
        let (result, changed) = remove_comments("/*TestCase */");
        assert_eq!(result, "\u{0000}");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_before_after() {
        let (result, changed) = remove_comments("Before/* TestCase */After");
        assert_eq!(result, "BeforeAfter");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_orphan_end() {
        let (result, changed) = remove_comments("Before TestCase */ After");
        assert_eq!(result, "Before TestCase */ After");
        assert!(!changed);
    }

    #[test]
    fn test_remove_comments_newline() {
        let (result, changed) = remove_comments("/* Test\nCase */");
        assert_eq!(result, "\u{0000}");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_crlf() {
        let (result, changed) = remove_comments("/* Test\r\nCase */");
        assert_eq!(result, "\u{0000}");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_unclosed() {
        let (result, changed) = remove_comments("/*Before/* Test\r\nCase ");
        assert_eq!(result, " ");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_unclosed_after_text() {
        let (result, changed) = remove_comments("Before /* Test\nCase ");
        assert_eq!(result, "Before  ");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_multiple() {
        let (result, changed) = remove_comments("Before/* T*/ /* e */ /* s */ /* t */\r\nCase ");
        assert_eq!(result, "Before   \r\nCase ");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_nested_markers() {
        let (result, changed) = remove_comments("Before /* */ ops */ Test\nCase ");
        assert_eq!(result, "Before  ops */ Test\nCase ");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_comment_then_text() {
        let (result, changed) = remove_comments("/*Test\r\nCase */After");
        assert_eq!(result, "After");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_empty_comment() {
        let (result, changed) = remove_comments("Test\nCase /**/ After");
        assert_eq!(result, "Test\nCase  After");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_end_marker_without_start() {
        let (result, changed) = remove_comments("Test\r\nCase */After");
        assert_eq!(result, "Test\r\nCase */After");
        assert!(!changed);
    }

    #[test]
    fn test_remove_comments_with_newline_after() {
        let (result, changed) = remove_comments("Test/*\nCase */ After");
        assert_eq!(result, "Test After");
        assert!(changed);
    }

    // Test cases from replaceComments.json

    #[test]
    fn test_replace_comments_empty() {
        let (result, changed) = replace_comments("");
        assert_eq!(result, "");
        assert!(!changed);
    }

    #[test]
    fn test_replace_comments_no_comments() {
        let (result, changed) = replace_comments("TestCase");
        assert_eq!(result, "TestCase");
        assert!(!changed);
    }

    #[test]
    fn test_replace_comments_with_null() {
        let (result, changed) = replace_comments("Test\u{0000}Case");
        assert_eq!(result, "Test\u{0000}Case");
        assert!(!changed);
    }

    #[test]
    fn test_replace_comments_full_comment() {
        let (result, changed) = replace_comments("/* TestCase */");
        assert_eq!(result, " ");
        assert!(changed);
    }

    #[test]
    fn test_replace_comments_no_spaces() {
        let (result, changed) = replace_comments("/*TestCase*/");
        assert_eq!(result, " ");
        assert!(changed);
    }

    #[test]
    fn test_replace_comments_space_before() {
        let (result, changed) = replace_comments("/* TestCase*/");
        assert_eq!(result, " ");
        assert!(changed);
    }

    #[test]
    fn test_replace_comments_space_after() {
        let (result, changed) = replace_comments("/*TestCase */");
        assert_eq!(result, " ");
        assert!(changed);
    }

    #[test]
    fn test_replace_comments_before_after() {
        let (result, changed) = replace_comments("Before/* TestCase */After");
        assert_eq!(result, "Before After");
        assert!(changed);
    }

    #[test]
    fn test_replace_comments_with_spaces() {
        let (result, changed) = replace_comments("Before /* TestCase */ After");
        assert_eq!(result, "Before   After");
        assert!(changed);
    }

    #[test]
    fn test_replace_comments_newline() {
        let (result, changed) = replace_comments("/* Test\nCase */");
        assert_eq!(result, " ");
        assert!(changed);
    }

    #[test]
    fn test_replace_comments_crlf() {
        let (result, changed) = replace_comments("/* Test\r\nCase */");
        assert_eq!(result, " ");
        assert!(changed);
    }

    #[test]
    fn test_replace_comments_unclosed_1() {
        let (result, changed) = replace_comments("Before/* Test\r\nCase ");
        assert_eq!(result, "Before ");
        assert!(changed);
    }

    #[test]
    fn test_replace_comments_unclosed_2() {
        let (result, changed) = replace_comments("Before /* Test\nCase ");
        assert_eq!(result, "Before  ");
        assert!(changed);
    }

    #[test]
    fn test_replace_comments_orphan_end() {
        let (result, changed) = replace_comments("Test\r\nCase */After");
        assert_eq!(result, "Test\r\nCase */After");
        assert!(!changed);
    }

    #[test]
    fn test_replace_comments_orphan_end_2() {
        let (result, changed) = replace_comments("Test\nCase */ After");
        assert_eq!(result, "Test\nCase */ After");
        assert!(!changed);
    }
}
