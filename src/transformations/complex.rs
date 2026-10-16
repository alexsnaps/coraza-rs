//! Complex text processing transformations.
//!
//! This module provides advanced transformations for decoding various formats
//! and normalizing file paths.

use super::TransformationResult;

/// HTML entity decoding transformation.
///
/// Decodes HTML entities (both named entities like `&lt;` and numeric entities
/// like `&#60;` or `&#x3C;`) into their corresponding characters, as Go Coraza does with
/// Go's `html.UnescapeString`: HTML5's names, legacy ones (`&lt`) also without `;`, and
/// anything that isn't a reference left as it is.
///
/// # Arguments
///
/// * `input` - Input that may contain HTML entities; bytes that aren't UTF-8 are kept
///
/// # Returns
///
/// Returns `(output, changed)` where:
/// - `output` is the decoded string
/// - `changed` is `true` if the output's length differs, as Go Coraza reports it
pub fn html_entity_decode(input: &[u8]) -> TransformationResult {
    let decoded = super::html_entities::unescape(input);
    let changed = decoded.len() != input.len();
    (decoded, changed, None)
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
pub fn normalise_path(input: &[u8]) -> TransformationResult {
    if input.is_empty() {
        return (Vec::new(), false, None);
    }

    let clean = clean_path(input);

    // Special case: "." becomes empty string (ModSecurity behavior)
    if clean == b"." {
        return (Vec::new(), true, None);
    }

    // Preserve trailing slash if original had one
    let result = if input.ends_with(b"/") && !clean.ends_with(b"/") {
        [clean.as_slice(), b"/"].concat()
    } else {
        clean
    };

    let changed = result != input;
    (result, changed, None)
}

/// `path`, slash-separated whatever the platform, with its `.` and empty elements
/// removed and each `..` removing the element before it, as Go's `path.Clean` does:
/// `..` at the root stays at the root, and an empty result is `.`.
fn clean_path(path: &[u8]) -> Vec<u8> {
    let rooted = path.first() == Some(&b'/');
    let mut clean = Vec::with_capacity(path.len());
    // Where `..` can no longer remove an element
    let mut floor = 0;
    if rooted {
        clean.push(b'/');
        floor = 1;
    }

    for element in path.split(|&byte| byte == b'/') {
        match element {
            b"" | b"." => {}
            b".." if clean.len() > floor => {
                let parent = clean[floor..]
                    .iter()
                    .rposition(|&byte| byte == b'/')
                    .map_or(floor, |slash| floor + slash);
                clean.truncate(parent);
            }
            b".." if rooted => {}
            _ => {
                if clean.len() > usize::from(rooted) {
                    clean.push(b'/');
                }
                clean.extend_from_slice(element);
                if element == b".." {
                    floor = clean.len();
                }
            }
        }
    }

    if clean.is_empty() {
        clean.push(b'.');
    }
    clean
}

/// Path normalization transformation (Windows-style).
///
/// Normalizes Windows file paths, as Go Coraza does, by:
/// - Converting backslashes (`\`) to forward slashes (`/`)
/// - Then applying Unix-style normalization
/// - Removing an NTFS alternate data stream from the last element (`file.txt::$DATA`
///   and `file.txt:hidden` are `file.txt`), and trailing dots and spaces from each
///   element (`file.txt.`), as Windows does when it opens a file
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
pub fn normalise_path_win(input: &[u8]) -> TransformationResult {
    if input.is_empty() {
        return (Vec::new(), false, None);
    }

    // Convert backslashes to forward slashes
    let converted: Vec<u8> = input
        .iter()
        .map(|&byte| if byte == b'\\' { b'/' } else { byte })
        .collect();

    // Apply Unix-style normalization
    let (normalized, _, _) = normalise_path(&converted);
    let result = strip_trailing_dots_and_spaces(&strip_alternate_data_stream(&normalized));

    let changed = result != input;
    (result, changed, None)
}

/// `path` without the NTFS alternate data stream of its last element, from the first
/// `:` on (`file.txt::$DATA` and `file.txt:hidden` open `file.txt`); a drive letter
/// (`C:`) isn't one.
fn strip_alternate_data_stream(path: &[u8]) -> Vec<u8> {
    let (drive, rest) = match path {
        [letter, b':', ..] if letter.is_ascii_alphabetic() => path.split_at(2),
        _ => (&[][..], path),
    };
    // A trailing slash keeps the last element last
    let (rest, trailing_slash): (&[u8], &[u8]) = match rest.strip_suffix(b"/") {
        Some(rest) => (rest, b"/"),
        None => (rest, b""),
    };
    let last_element = rest
        .iter()
        .rposition(|&byte| byte == b'/')
        .map_or(0, |slash| slash + 1);
    let end = rest[last_element..]
        .iter()
        .position(|&byte| byte == b':')
        .map_or(rest.len(), |colon| last_element + colon);
    [drive, &rest[..end], trailing_slash].concat()
}

/// `path` with the trailing dots and spaces of each element removed, as Windows ignores
/// them (`file.txt.` opens `file.txt`); an element that is all dots (`..`) is kept, one
/// that is nothing else is dropped.
fn strip_trailing_dots_and_spaces(path: &[u8]) -> Vec<u8> {
    let mut stripped = Vec::with_capacity(path.len());
    let mut first = true;
    for element in path.split(|&byte| byte == b'/') {
        let element = if element.iter().all(|&byte| byte == b'.') {
            element
        } else {
            let end = element
                .iter()
                .rposition(|&byte| byte != b'.' && byte != b' ')
                .map_or(0, |last| last + 1);
            if end == 0 {
                continue;
            }
            &element[..end]
        };
        if !first {
            stripped.push(b'/');
        }
        stripped.extend_from_slice(element);
        first = false;
    }
    stripped
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
/// - `changed` is `true` if a byte was removed or changed, `false` otherwise
pub fn cmd_line(input: &[u8]) -> TransformationResult {
    // Check if transformation is needed
    let Some(pos) = input.iter().copied().position(needs_cmd_transform) else {
        return (input.to_vec(), false, None);
    };
    let output = do_cmd_line(input, pos);
    // A space is left as it is, as in Go Coraza that is no change
    let changed = output != input;
    (output, changed, None)
}

fn do_cmd_line(input: &[u8], pos: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(input.len());

    // Copy prefix before first transformable character
    result.extend_from_slice(&input[..pos]);

    let mut space = false;

    for &c in &input[pos..] {
        match c {
            // Remove these characters
            b'"' | b'\'' | b'\\' | b'^' => {
                // Skip these characters entirely
            }
            // Replace with space (compress multiple)
            b' ' | b',' | b';' | b'\t' | b'\r' | b'\n' => {
                if !space {
                    result.push(b' ');
                    space = true;
                }
            }
            // Remove space before / or (
            b'/' | b'(' => {
                if space && !result.is_empty() {
                    result.pop(); // Remove the trailing space
                }
                space = false;
                result.push(c);
            }
            // Regular character - lowercase if needed
            _ => {
                let lower = if c.is_ascii_uppercase() {
                    c + (b'a' - b'A')
                } else {
                    c
                };
                result.push(lower);
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
pub fn remove_comments(input: &[u8]) -> TransformationResult {
    // Add null byte padding to match ModSecurity behavior
    let mut input_with_padding = input.to_vec();
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

    (result, changed, None)
}

/// Removes comment markers, keeping what they enclose: `/*`, `*/`, `<!--`, `-->`, `--`
/// and `#`.
///
/// Unlike [`remove_comments`], the text between markers stays, so
/// `SELECT/**/1` becomes `SELECT1`, and a lone marker is removed too.
pub fn remove_comments_char(input: &[u8]) -> TransformationResult {
    const MARKERS: [&[u8]; 6] = [b"/*", b"*/", b"<!--", b"-->", b"--", b"#"];

    let mut rest = input;
    let mut output = Vec::with_capacity(rest.len());
    while let Some((&byte, after)) = rest.split_first() {
        match MARKERS.iter().find(|marker| rest.starts_with(marker)) {
            Some(marker) => rest = &rest[marker.len()..],
            None => {
                output.push(byte);
                rest = after;
            }
        }
    }

    let changed = output.len() != input.len();
    (output, changed, None)
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
pub fn replace_comments(input: &[u8]) -> TransformationResult {
    let input_len = input.len();
    let mut result = Vec::with_capacity(input_len);

    let mut i = 0;
    let mut in_comment = false;
    let mut changed = false;

    while i < input_len {
        if !in_comment {
            if i + 1 < input_len && input[i] == b'/' && input[i + 1] == b'*' {
                // Start of C-style comment /*
                in_comment = true;
                changed = true;
                i += 2;
            } else {
                // Regular character
                result.push(input[i]);
                i += 1;
            }
        } else {
            // Inside a comment
            if i + 1 < input_len && input[i] == b'*' && input[i + 1] == b'/' {
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

    (result, changed, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transformations::on_text;

    #[test]
    fn test_remove_comments_char() {
        // Go Coraza's testdata/removeCommentsChar.json, and the markers it doesn't cover
        for (input, output) in [
            ("", ""),
            ("TestCase", "TestCase"),
            ("Test\\u0000Case", "Test\\u0000Case"),
            ("/* TestCase */", " TestCase "),
            ("/*TestCase*/", "TestCase"),
            ("/* TestCase*/", " TestCase"),
            ("/*TestCase */", "TestCase "),
            ("Before/* TestCase */After", "Before TestCase After"),
            ("Before /* TestCase */ After", "Before  TestCase  After"),
            ("/* Test\r\nCase */", " Test\r\nCase "),
            ("Before /* Test\nCase ", "Before  Test\nCase "),
            ("Test\r\nCase */After", "Test\r\nCase After"),
            ("Test\nCase */ After", "Test\nCase  After"),
            ("a<!--b-->c", "abc"),
            ("1--2", "12"),
            ("x#y", "xy"),
            ("é--ü", "éü"),
        ] {
            let (result, changed, error) = on_text(remove_comments_char, input);
            assert_eq!(result, output, "{input:?}");
            assert_eq!(changed, input != output, "{input:?}");
            assert!(error.is_none());
        }
    }

    // Test cases from htmlEntityDecode.json
    #[test]
    fn test_html_entity_decode_empty() {
        let (result, changed, _) = on_text(html_entity_decode, "");
        assert_eq!(result, "");
        assert!(!changed);
    }

    #[test]
    fn test_html_entity_decode_no_entities() {
        let (result, changed, _) = on_text(html_entity_decode, "TestCase");
        assert_eq!(result, "TestCase");
        assert!(!changed);
    }

    #[test]
    fn test_html_entity_decode_with_null() {
        let (result, changed, _) = on_text(html_entity_decode, "Test\u{0000}Case");
        assert_eq!(result, "Test\u{0000}Case");
        assert!(!changed);
    }

    #[test]
    fn test_html_entity_decode_named_entities() {
        let (result, changed, _) = on_text(html_entity_decode, "&lt;script&gt;");
        assert_eq!(result, "<script>");
        assert!(changed);
    }

    #[test]
    fn test_html_entity_decode_numeric_entities() {
        let (result, changed, _) = on_text(html_entity_decode, "&#60;&#62;");
        assert_eq!(result, "<>");
        assert!(changed);
    }

    #[test]
    fn test_html_entity_decode_hex_entities() {
        let (result, changed, _) = on_text(html_entity_decode, "&#x3C;&#x3E;");
        assert_eq!(result, "<>");
        assert!(changed);
    }

    // Test cases from normalisePath.json
    #[test]
    fn test_normalise_path_empty() {
        let (result, changed, _) = on_text(normalise_path, "");
        assert_eq!(result, "");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_simple() {
        let (result, changed, _) = on_text(normalise_path, "/foo/bar/baz");
        assert_eq!(result, "/foo/bar/baz");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_with_null() {
        let (result, changed, _) = on_text(normalise_path, "/foo/bar\u{0000}/baz");
        assert_eq!(result, "/foo/bar\u{0000}/baz");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_single_char() {
        let (result, changed, _) = on_text(normalise_path, "x");
        assert_eq!(result, "x");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_dot() {
        let (result, changed, _) = on_text(normalise_path, ".");
        assert_eq!(result, "");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_dot_slash() {
        let (result, changed, _) = on_text(normalise_path, "./");
        assert_eq!(result, "");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_dot_dotdot() {
        let (result, changed, _) = on_text(normalise_path, "./..");
        assert_eq!(result, "..");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_dot_dotdot_slash() {
        let (result, changed, _) = on_text(normalise_path, "./../");
        assert_eq!(result, "../");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_dotdot() {
        let (result, changed, _) = on_text(normalise_path, "..");
        assert_eq!(result, "..");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_dotdot_slash() {
        let (result, changed, _) = on_text(normalise_path, "../");
        assert_eq!(result, "../");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_dotdot_dot() {
        let (result, changed, _) = on_text(normalise_path, "../.");
        assert_eq!(result, "..");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_dotdot_dot_slash() {
        let (result, changed, _) = on_text(normalise_path, ".././");
        assert_eq!(result, "../");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_dotdot_dotdot() {
        let (result, changed, _) = on_text(normalise_path, "../..");
        assert_eq!(result, "../..");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_dotdot_dotdot_slash() {
        let (result, changed, _) = on_text(normalise_path, "../../");
        assert_eq!(result, "../../");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_double_slash() {
        let (result, changed, _) = on_text(normalise_path, "/dir/foo//bar");
        assert_eq!(result, "/dir/foo/bar");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_double_slash_trailing() {
        let (result, changed, _) = on_text(normalise_path, "dir/foo//bar/");
        assert_eq!(result, "dir/foo/bar/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_parent_dir() {
        let (result, changed, _) = on_text(normalise_path, "dir/../foo");
        assert_eq!(result, "foo");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_double_parent() {
        let (result, changed, _) = on_text(normalise_path, "dir/../../foo");
        assert_eq!(result, "../foo");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_complex1() {
        let (result, changed, _) = on_text(normalise_path, "dir/./.././../../foo/bar");
        assert_eq!(result, "../../foo/bar");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_complex2() {
        let (result, changed, _) = on_text(normalise_path, "dir/./.././../../foo/bar/.");
        assert_eq!(result, "../../foo/bar");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_complex3() {
        let (result, changed, _) = on_text(normalise_path, "dir/./.././../../foo/bar/./");
        assert_eq!(result, "../../foo/bar/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_complex4() {
        let (result, changed, _) = on_text(normalise_path, "dir/./.././../../foo/bar/..");
        assert_eq!(result, "../../foo");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_complex5() {
        let (result, changed, _) = on_text(normalise_path, "dir/./.././../../foo/bar/../");
        assert_eq!(result, "../../foo/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_complex6() {
        let (result, changed, _) = on_text(normalise_path, "dir/./.././../../foo/bar/");
        assert_eq!(result, "../../foo/bar/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_complex7() {
        let (result, changed, _) = on_text(normalise_path, "dir//.//..//.//..//..//foo//bar");
        assert_eq!(result, "../../foo/bar");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_complex8() {
        let (result, changed, _) = on_text(normalise_path, "dir//.//..//.//..//..//foo//bar//");
        assert_eq!(result, "../../foo/bar/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_multiple_parent1() {
        let (result, changed, _) =
            on_text(normalise_path, "dir/subdir/subsubdir/subsubsubdir/../../..");
        assert_eq!(result, "dir");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_multiple_parent2() {
        let (result, changed, _) = on_text(
            normalise_path,
            "dir/./subdir/./subsubdir/./subsubsubdir/../../..",
        );
        assert_eq!(result, "dir");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_multiple_parent3() {
        let (result, changed, _) = on_text(
            normalise_path,
            "dir/./subdir/../subsubdir/../subsubsubdir/..",
        );
        assert_eq!(result, "dir");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_multiple_parent4() {
        let (result, changed, _) = on_text(
            normalise_path,
            "/dir/./subdir/../subsubdir/../subsubsubdir/../",
        );
        assert_eq!(result, "/dir/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_path_traversal() {
        let (result, changed, _) = on_text(
            normalise_path,
            "/./.././../../../../../../../\u{0000}/../etc/./passwd",
        );
        assert_eq!(result, "/etc/passwd");
        assert!(changed);
    }

    // Test cases from normalisePathWin.json
    #[test]
    fn test_normalise_path_win_empty() {
        let (result, changed, _) = on_text(normalise_path_win, "");
        assert_eq!(result, "");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_win_backslash() {
        let (result, changed, _) = on_text(normalise_path_win, "\\foo\\bar\\baz");
        assert_eq!(result, "/foo/bar/baz");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_with_null() {
        let (result, changed, _) = on_text(normalise_path_win, "\\foo\\bar\u{0000}\\baz");
        assert_eq!(result, "/foo/bar\u{0000}/baz");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_single_char() {
        let (result, changed, _) = on_text(normalise_path_win, "x");
        assert_eq!(result, "x");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_win_dot() {
        let (result, changed, _) = on_text(normalise_path_win, ".");
        assert_eq!(result, "");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_dot_backslash() {
        let (result, changed, _) = on_text(normalise_path_win, ".\\");
        assert_eq!(result, "");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_dot_dotdot() {
        let (result, changed, _) = on_text(normalise_path_win, ".\\..");
        assert_eq!(result, "..");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_dot_dotdot_backslash() {
        let (result, changed, _) = on_text(normalise_path_win, ".\\..\\");
        assert_eq!(result, "../");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_dotdot() {
        let (result, changed, _) = on_text(normalise_path_win, "..");
        assert_eq!(result, "..");
        assert!(!changed);
    }

    #[test]
    fn test_normalise_path_win_dotdot_backslash() {
        let (result, changed, _) = on_text(normalise_path_win, "..\\");
        assert_eq!(result, "../");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_dotdot_dot() {
        let (result, changed, _) = on_text(normalise_path_win, "..\\.");
        assert_eq!(result, "..");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_dotdot_dot_backslash() {
        let (result, changed, _) = on_text(normalise_path_win, "..\\.\\");
        assert_eq!(result, "../");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_dotdot_dotdot() {
        let (result, changed, _) = on_text(normalise_path_win, "..\\..");
        assert_eq!(result, "../..");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_dotdot_dotdot_backslash() {
        let (result, changed, _) = on_text(normalise_path_win, "..\\..\\");
        assert_eq!(result, "../../");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_double_backslash() {
        let (result, changed, _) = on_text(normalise_path_win, "\\dir\\foo\\\\bar");
        assert_eq!(result, "/dir/foo/bar");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_double_backslash_trailing() {
        let (result, changed, _) = on_text(normalise_path_win, "dir\\foo\\\\bar\\");
        assert_eq!(result, "dir/foo/bar/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_parent_dir() {
        let (result, changed, _) = on_text(normalise_path_win, "dir\\..\\foo");
        assert_eq!(result, "foo");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_double_parent() {
        let (result, changed, _) = on_text(normalise_path_win, "dir\\..\\..\\foo");
        assert_eq!(result, "../foo");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_complex1() {
        let (result, changed, _) = on_text(normalise_path_win, "dir\\.\\..\\.\\..\\..\\foo\\bar");
        assert_eq!(result, "../../foo/bar");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_complex2() {
        let (result, changed, _) =
            on_text(normalise_path_win, "dir\\.\\..\\.\\..\\..\\foo\\bar\\.");
        assert_eq!(result, "../../foo/bar");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_complex3() {
        let (result, changed, _) =
            on_text(normalise_path_win, "dir\\.\\..\\.\\..\\..\\foo\\bar\\.\\");
        assert_eq!(result, "../../foo/bar/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_complex4() {
        let (result, changed, _) =
            on_text(normalise_path_win, "dir\\.\\..\\.\\..\\..\\foo\\bar\\..");
        assert_eq!(result, "../../foo");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_complex5() {
        let (result, changed, _) =
            on_text(normalise_path_win, "dir\\.\\..\\.\\..\\..\\foo\\bar\\..\\");
        assert_eq!(result, "../../foo/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_complex6() {
        let (result, changed, _) = on_text(normalise_path_win, "dir\\.\\..\\.\\..\\..\\foo\\bar\\");
        assert_eq!(result, "../../foo/bar/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_complex7() {
        let (result, changed, _) = on_text(
            normalise_path_win,
            "dir\\\\.\\\\..\\\\.\\\\..\\\\..\\\\foo\\\\bar",
        );
        assert_eq!(result, "../../foo/bar");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_complex8() {
        let (result, changed, _) = on_text(
            normalise_path_win,
            "dir\\\\.\\\\..\\\\.\\\\..\\\\..\\\\foo\\\\bar\\\\",
        );
        assert_eq!(result, "../../foo/bar/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_multiple_parent1() {
        let (result, changed, _) = on_text(
            normalise_path_win,
            "dir\\subdir\\subsubdir\\subsubsubdir\\..\\..\\..",
        );
        assert_eq!(result, "dir");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_multiple_parent2() {
        let (result, changed, _) = on_text(
            normalise_path_win,
            "dir\\.\\subdir\\.\\subsubdir\\.\\subsubsubdir\\..\\..\\..",
        );
        assert_eq!(result, "dir");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_multiple_parent3() {
        let (result, changed, _) = on_text(
            normalise_path_win,
            "dir\\.\\subdir\\..\\subsubdir\\..\\subsubsubdir\\..",
        );
        assert_eq!(result, "dir");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_multiple_parent4() {
        let (result, changed, _) = on_text(
            normalise_path_win,
            "\\dir\\.\\subdir\\..\\subsubdir\\..\\subsubsubdir\\..\\",
        );
        assert_eq!(result, "/dir/");
        assert!(changed);
    }

    #[test]
    fn test_normalise_path_win_path_traversal() {
        let (result, changed, _) = on_text(
            normalise_path_win,
            "\\.\\..\\.\\..\\..\\..\\..\\..\\..\\..\\\\0\\..\\etc\\.\\passwd",
        );
        assert_eq!(result, "/etc/passwd");
        assert!(changed);
    }

    // Test cases from cmdLine.json

    #[test]
    fn test_cmd_line_empty() {
        let (result, changed, _) = on_text(cmd_line, "");
        assert_eq!(result, "");
        assert!(!changed);
    }

    #[test]
    fn test_cmd_line_no_transform() {
        let (result, changed, _) = on_text(cmd_line, "test");
        assert_eq!(result, "test");
        assert!(!changed);
    }

    #[test]
    fn test_cmd_line_caret_and_case() {
        let (result, changed, _) = on_text(cmd_line, "C^OMMAND /C DIR");
        assert_eq!(result, "command/c dir");
        assert!(changed);
    }

    #[test]
    fn test_cmd_line_mixed_case() {
        let (result, changed, _) = on_text(cmd_line, "C^oMMaNd /C DiR");
        assert_eq!(result, "command/c dir");
        assert!(changed);
    }

    #[test]
    fn test_cmd_line_comma() {
        let (result, changed, _) = on_text(cmd_line, "cmd,/c DiR");
        assert_eq!(result, "cmd/c dir");
        assert!(changed);
    }

    #[test]
    fn test_cmd_line_quotes() {
        let (result, changed, _) = on_text(cmd_line, "\"command\" /c DiR");
        assert_eq!(result, "command/c dir");
        assert!(changed);
    }

    #[test]
    fn test_cmd_line_non_ascii() {
        let (result, changed, _) = on_text(cmd_line, "C^OPY é");
        assert_eq!(result, "copy é");
        assert!(changed);
    }

    // Test cases from removeComments.json

    #[test]
    fn test_remove_comments_empty() {
        let (result, changed, _) = on_text(remove_comments, "");
        assert_eq!(result, "");
        assert!(!changed);
    }

    #[test]
    fn test_remove_comments_no_comments() {
        let (result, changed, _) = on_text(remove_comments, "TestCase");
        assert_eq!(result, "TestCase");
        assert!(!changed);
    }

    #[test]
    fn test_remove_comments_with_null() {
        let (result, changed, _) = on_text(remove_comments, "Test\u{0000}Case");
        assert_eq!(result, "Test\u{0000}Case");
        assert!(!changed);
    }

    #[test]
    fn test_remove_comments_full_comment() {
        let (result, changed, _) = on_text(remove_comments, "/* TestCase */");
        assert_eq!(result, "\u{0000}");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_no_spaces() {
        let (result, changed, _) = on_text(remove_comments, "/*TestCase*/");
        assert_eq!(result, "\u{0000}");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_space_before() {
        let (result, changed, _) = on_text(remove_comments, "/* TestCase*/");
        assert_eq!(result, "\u{0000}");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_space_after() {
        let (result, changed, _) = on_text(remove_comments, "/*TestCase */");
        assert_eq!(result, "\u{0000}");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_before_after() {
        let (result, changed, _) = on_text(remove_comments, "Before/* TestCase */After");
        assert_eq!(result, "BeforeAfter");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_orphan_end() {
        let (result, changed, _) = on_text(remove_comments, "Before TestCase */ After");
        assert_eq!(result, "Before TestCase */ After");
        assert!(!changed);
    }

    #[test]
    fn test_remove_comments_newline() {
        let (result, changed, _) = on_text(remove_comments, "/* Test\nCase */");
        assert_eq!(result, "\u{0000}");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_crlf() {
        let (result, changed, _) = on_text(remove_comments, "/* Test\r\nCase */");
        assert_eq!(result, "\u{0000}");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_unclosed() {
        let (result, changed, _) = on_text(remove_comments, "/*Before/* Test\r\nCase ");
        assert_eq!(result, " ");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_unclosed_after_text() {
        let (result, changed, _) = on_text(remove_comments, "Before /* Test\nCase ");
        assert_eq!(result, "Before  ");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_multiple() {
        let (result, changed, _) = on_text(
            remove_comments,
            "Before/* T*/ /* e */ /* s */ /* t */\r\nCase ",
        );
        assert_eq!(result, "Before   \r\nCase ");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_nested_markers() {
        let (result, changed, _) = on_text(remove_comments, "Before /* */ ops */ Test\nCase ");
        assert_eq!(result, "Before  ops */ Test\nCase ");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_comment_then_text() {
        let (result, changed, _) = on_text(remove_comments, "/*Test\r\nCase */After");
        assert_eq!(result, "After");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_empty_comment() {
        let (result, changed, _) = on_text(remove_comments, "Test\nCase /**/ After");
        assert_eq!(result, "Test\nCase  After");
        assert!(changed);
    }

    #[test]
    fn test_remove_comments_end_marker_without_start() {
        let (result, changed, _) = on_text(remove_comments, "Test\r\nCase */After");
        assert_eq!(result, "Test\r\nCase */After");
        assert!(!changed);
    }

    #[test]
    fn test_remove_comments_with_newline_after() {
        let (result, changed, _) = on_text(remove_comments, "Test/*\nCase */ After");
        assert_eq!(result, "Test After");
        assert!(changed);
    }

    // Test cases from replaceComments.json

    #[test]
    fn test_replace_comments_empty() {
        let (result, changed, _) = on_text(replace_comments, "");
        assert_eq!(result, "");
        assert!(!changed);
    }

    #[test]
    fn test_replace_comments_no_comments() {
        let (result, changed, _) = on_text(replace_comments, "TestCase");
        assert_eq!(result, "TestCase");
        assert!(!changed);
    }

    #[test]
    fn test_replace_comments_with_null() {
        let (result, changed, _) = on_text(replace_comments, "Test\u{0000}Case");
        assert_eq!(result, "Test\u{0000}Case");
        assert!(!changed);
    }

    #[test]
    fn test_replace_comments_full_comment() {
        let (result, changed, _) = on_text(replace_comments, "/* TestCase */");
        assert_eq!(result, " ");
        assert!(changed);
    }

    #[test]
    fn test_replace_comments_no_spaces() {
        let (result, changed, _) = on_text(replace_comments, "/*TestCase*/");
        assert_eq!(result, " ");
        assert!(changed);
    }

    #[test]
    fn test_replace_comments_space_before() {
        let (result, changed, _) = on_text(replace_comments, "/* TestCase*/");
        assert_eq!(result, " ");
        assert!(changed);
    }

    #[test]
    fn test_replace_comments_space_after() {
        let (result, changed, _) = on_text(replace_comments, "/*TestCase */");
        assert_eq!(result, " ");
        assert!(changed);
    }

    #[test]
    fn test_replace_comments_before_after() {
        let (result, changed, _) = on_text(replace_comments, "Before/* TestCase */After");
        assert_eq!(result, "Before After");
        assert!(changed);
    }

    #[test]
    fn test_replace_comments_with_spaces() {
        let (result, changed, _) = on_text(replace_comments, "Before /* TestCase */ After");
        assert_eq!(result, "Before   After");
        assert!(changed);
    }

    #[test]
    fn test_replace_comments_newline() {
        let (result, changed, _) = on_text(replace_comments, "/* Test\nCase */");
        assert_eq!(result, " ");
        assert!(changed);
    }

    #[test]
    fn test_replace_comments_crlf() {
        let (result, changed, _) = on_text(replace_comments, "/* Test\r\nCase */");
        assert_eq!(result, " ");
        assert!(changed);
    }

    #[test]
    fn test_replace_comments_unclosed_1() {
        let (result, changed, _) = on_text(replace_comments, "Before/* Test\r\nCase ");
        assert_eq!(result, "Before ");
        assert!(changed);
    }

    #[test]
    fn test_replace_comments_unclosed_2() {
        let (result, changed, _) = on_text(replace_comments, "Before /* Test\nCase ");
        assert_eq!(result, "Before  ");
        assert!(changed);
    }

    #[test]
    fn test_replace_comments_orphan_end() {
        let (result, changed, _) = on_text(replace_comments, "Test\r\nCase */After");
        assert_eq!(result, "Test\r\nCase */After");
        assert!(!changed);
    }

    #[test]
    fn test_replace_comments_orphan_end_2() {
        let (result, changed, _) = on_text(replace_comments, "Test\nCase */ After");
        assert_eq!(result, "Test\nCase */ After");
        assert!(!changed);
    }

    #[test]
    fn test_bytes_that_are_not_utf8() {
        assert_eq!(html_entity_decode(b"&lt;\xff&gt;").0, b"<\xff>");
        assert_eq!(normalise_path(b"/a/../\xff//b").0, b"/\xff/b");
        assert_eq!(normalise_path_win(b"\\a\\..\\\xff").0, b"/\xff");
        assert_eq!(cmd_line(b"A\xff^B").0, b"a\xffb");
        assert_eq!(remove_comments(b"\xff/* x */y").0, b"\xffy");
        assert_eq!(remove_comments_char(b"\xff/**/").0, b"\xff");
        assert_eq!(replace_comments(b"\xff/* x */").0, b"\xff ");
    }

    #[test]
    fn test_normalise_path_backslash_is_not_a_separator() {
        // As Go's path.Clean, whatever the platform
        assert_eq!(on_text(normalise_path, "a\\..\\b").0, "a\\..\\b");
        assert_eq!(on_text(normalise_path, "C:/x/../y").0, "C:/y");
    }

    // Go Coraza's TestNormalisePathWin
    #[test]
    fn test_normalise_path_win_as_windows_opens_files() {
        for (input, want) in [
            ("", ""),
            (
                r"C:\inetpub\wwwroot\index.html",
                "C:/inetpub/wwwroot/index.html",
            ),
            (r"..\..\etc\passwd", "../../etc/passwd"),
            (r"foo\..\bar", "bar"),
            (
                r"C:\inetpub\wwwroot\web.config.",
                "C:/inetpub/wwwroot/web.config",
            ),
            (
                r"C:\inetpub\wwwroot\web.config ",
                "C:/inetpub/wwwroot/web.config",
            ),
            (
                r"C:\inetpub\wwwroot\web.config::$DATA",
                "C:/inetpub/wwwroot/web.config",
            ),
            (
                r"C:\inetpub\wwwroot\web.config:hidden",
                "C:/inetpub/wwwroot/web.config",
            ),
            (r"..\..\web.config.", "../../web.config"),
            ("C:", "C:"),
            (r"C:\path\web.config:$DATA\", "C:/path/web.config/"),
            (r"C:\ \file.txt", "C:/file.txt"),
        ] {
            let (result, changed, _) = on_text(normalise_path_win, input);
            assert_eq!(result, want, "{input:?}");
            assert_eq!(changed, input != want, "{input:?}");
        }
    }

    #[test]
    fn test_cmd_line_changed_only_when_a_byte_changes() {
        // A space triggers the transformation but stays as it is
        let (result, changed, _) = on_text(cmd_line, "cmd arg");
        assert_eq!(result, "cmd arg");
        assert!(!changed);

        for input in ["cmd  arg", "cmd,arg", "cmd /c", "Cmd", "c^md"] {
            assert!(on_text(cmd_line, input).1, "{input:?}");
        }
    }

    /// The doc example of `transformations::complex::html_entity_decode`, before it became internal.
    #[test]
    fn doc_html_entity_decode() {
        use crate::transformations::complex::html_entity_decode;
        let (result, changed, _) = html_entity_decode(b"&lt;script&gt;");
        assert_eq!(result, b"<script>");
        assert!(changed);

        let (result, changed, _) = html_entity_decode(b"no entities here");
        assert_eq!(result, b"no entities here");
        assert!(!changed);

        let (result, changed, _) = html_entity_decode(b"&#60;&#x3E;");
        assert_eq!(result, b"<>");
        assert!(changed);

        let (result, changed, _) = html_entity_decode(b"&lcub;&gt");
        assert_eq!(result, b"{>");
        assert!(changed);
    }

    /// The doc example of `transformations::complex::normalise_path`, before it became internal.
    #[test]
    fn doc_normalise_path() {
        use crate::transformations::complex::normalise_path;
        let (result, changed, _) = normalise_path(b"/foo//bar");
        assert_eq!(result, b"/foo/bar");
        assert!(changed);

        let (result, changed, _) = normalise_path(b"dir/../foo");
        assert_eq!(result, b"foo");
        assert!(changed);

        let (result, changed, _) = normalise_path(b"/foo/bar/");
        assert_eq!(result, b"/foo/bar/");
        assert!(!changed);

        // Special case: "." becomes empty string
        let (result, changed, _) = normalise_path(b".");
        assert_eq!(result, b"");
        assert!(changed);
    }

    /// The doc example of `transformations::complex::normalise_path_win`, before it became internal.
    #[test]
    fn doc_normalise_path_win() {
        use crate::transformations::complex::normalise_path_win;
        let (result, changed, _) = normalise_path_win(b"\\foo\\bar\\baz");
        assert_eq!(result, b"/foo/bar/baz");
        assert!(changed);

        let (result, changed, _) = normalise_path_win(b"dir\\..\\foo");
        assert_eq!(result, b"foo");
        assert!(changed);

        let (result, changed, _) = normalise_path_win(b"dir\\\\foo\\\\bar");
        assert_eq!(result, b"dir/foo/bar");
        assert!(changed);

        let (result, changed, _) = normalise_path_win(b"C:\\inetpub\\web.config::$DATA");
        assert_eq!(result, b"C:/inetpub/web.config");
        assert!(changed);
    }

    /// The doc example of `transformations::complex::cmd_line`, before it became internal.
    #[test]
    fn doc_cmd_line() {
        use crate::transformations::complex::cmd_line;
        let (result, changed, _) = cmd_line(b"cmd.exe /c \"whoami\"");
        assert_eq!(result, b"cmd.exe/c whoami");
        assert!(changed);

        let (result, changed, _) = cmd_line(b"SELECT * FROM users WHERE id=1;");
        assert_eq!(result, b"select * from users where id=1 ");
        assert!(changed);
    }

    /// The doc example of `transformations::complex::remove_comments`, before it became internal.
    #[test]
    fn doc_remove_comments() {
        use crate::transformations::complex::remove_comments;
        let (result, changed, _) = remove_comments(b"SELECT * FROM users /* comment */ WHERE id=1");
        assert_eq!(result, b"SELECT * FROM users  WHERE id=1");
        assert!(changed);

        let (result, changed, _) = remove_comments(b"<!-- HTML comment --> <div>content</div>");
        assert_eq!(result, b" <div>content</div>");
        assert!(changed);
    }

    /// The doc example of `transformations::complex::remove_comments_char`, before it became internal.
    #[test]
    fn doc_remove_comments_char() {
        use crate::transformations::complex::remove_comments_char;
        let (result, changed, _) = remove_comments_char(b"Before/* TestCase */After");
        assert_eq!(result, b"Before TestCase After");
        assert!(changed);
    }

    /// The doc example of `transformations::complex::replace_comments`, before it became internal.
    #[test]
    fn doc_replace_comments() {
        use crate::transformations::complex::replace_comments;
        let (result, changed, _) =
            replace_comments(b"SELECT * FROM users /* comment */ WHERE id=1");
        assert_eq!(result, b"SELECT * FROM users   WHERE id=1");
        assert!(changed);

        let (result, changed, _) = replace_comments(b"no comments here");
        assert_eq!(result, b"no comments here");
        assert!(!changed);
    }
}
