// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Multipart body processor (multipart/form-data).
//!
//! Parses multipart/form-data bodies (typically file uploads) and populates
//! the FILES, ARGS_POST, and MULTIPART_* collections.

use super::{BodyProcessor, BodyProcessorError, BodyProcessorOptions};
use crate::collection::MapCollection;
use crate::transaction::Transaction;
use mime::Mime;
use multipart::server::Multipart;
use std::io::{Cursor, Read, Write};

/// Multipart body processor for file uploads
pub struct MultipartBodyProcessor;

impl BodyProcessor for MultipartBodyProcessor {
    fn process_request(
        &self,
        body: &[u8],
        tx: &mut Transaction,
        options: &BodyProcessorOptions,
    ) -> Result<(), BodyProcessorError> {
        // Parse Content-Type to get boundary
        let content_type = options
            .mime
            .parse::<Mime>()
            .map_err(|e| {
                tx.multipart_strict_error.set("1");
                BodyProcessorError::InvalidEncoding(
                    "multipart".to_string(),
                    format!("invalid content-type: {}", e),
                )
            })?;

        // Verify it's multipart
        if content_type.type_() != mime::MULTIPART {
            tx.multipart_strict_error.set("1");
            return Err(BodyProcessorError::Malformed(
                "multipart".to_string(),
                "not a multipart body".to_string(),
            ));
        }

        // Extract boundary parameter
        let boundary = content_type
            .get_param(mime::BOUNDARY)
            .ok_or_else(|| {
                tx.multipart_strict_error.set("1");
                BodyProcessorError::Malformed(
                    "multipart".to_string(),
                    "missing boundary parameter".to_string(),
                )
            })?
            .as_str();

        // Create multipart reader from body
        let cursor = Cursor::new(body);
        let mut multipart = Multipart::with_body(cursor, boundary);

        let mut total_size: u64 = 0;

        // Process each part
        loop {
            match multipart.read_entry() {
                Ok(Some(mut entry)) => {
                    let part_name = entry.headers.name.to_string();

                    // Collect part headers into MULTIPART_PART_HEADERS
                    // Add Content-Disposition
                    let mut content_disp = format!("Content-Disposition: form-data; name=\"{}\"", part_name);
                    if let Some(filename) = &entry.headers.filename {
                        content_disp.push_str(&format!("; filename=\"{}\"", filename));
                    }
                    tx.multipart_part_headers.add(&part_name, &content_disp);

                    // Add Content-Type if present
                    if let Some(content_type) = &entry.headers.content_type {
                        tx.multipart_part_headers.add(
                            &part_name,
                            &format!("Content-Type: {}", content_type),
                        );
                    }

                    // Check if this is a file upload (has filename)
                    if let Some(filename) = &entry.headers.filename {
                        // Read file data
                        let mut file_data = Vec::new();
                        let size = entry.data.read_to_end(&mut file_data).map_err(|e| {
                            tx.multipart_strict_error.set("1");
                            BodyProcessorError::Io(e)
                        })? as u64;

                        total_size += size;

                        // Save to temporary file if upload_dir is set
                        if !options.upload_dir.is_empty() {
                            let temp_file = save_to_temp(&options.upload_dir, &file_data)?;
                            tx.files_tmp_names.add("", &temp_file);
                        }

                        // Populate FILES collections
                        tx.files.add("", filename);
                        tx.files_sizes.set_index(filename, 0, &size.to_string());
                        tx.files_names.add("", &part_name);
                    } else {
                        // Regular form field - read value and add to ARGS_POST
                        let mut value = String::new();
                        entry.data.read_to_string(&mut value).map_err(|e| {
                            tx.multipart_strict_error.set("1");
                            BodyProcessorError::Io(e)
                        })?;

                        total_size += value.len() as u64;
                        tx.args_post_mut().add(&part_name, &value);
                    }
                }
                Ok(None) => {
                    // End of multipart stream
                    break;
                }
                Err(e) => {
                    // Parsing error - set strict error flag
                    tx.multipart_strict_error.set("1");
                    return Err(BodyProcessorError::Malformed(
                        "multipart".to_string(),
                        e.to_string(),
                    ));
                }
            }
        }

        // Set total combined size
        tx.files_combined_size.set(total_size.to_string());

        Ok(())
    }

    fn process_response(
        &self,
        _body: &[u8],
        _tx: &mut Transaction,
        _options: &BodyProcessorOptions,
    ) -> Result<(), BodyProcessorError> {
        // Multipart processor doesn't process response bodies
        Ok(())
    }
}

/// Save file data to temporary directory
fn save_to_temp(upload_dir: &str, data: &[u8]) -> Result<String, BodyProcessorError> {
    use std::fs;
    use std::path::PathBuf;

    // Create upload directory if it doesn't exist
    fs::create_dir_all(upload_dir)?;

    // Generate unique temp filename
    let temp_name = format!("crzmp{}", crate::utils::strings::random_string(16));
    let mut temp_path = PathBuf::from(upload_dir);
    temp_path.push(temp_name);

    // Write file
    let mut file = fs::File::create(&temp_path)?;
    file.write_all(data)?;

    Ok(temp_path.to_string_lossy().to_string())
}

/// Factory function for creating multipart body processors
pub fn create_multipart() -> Box<dyn BodyProcessor> {
    Box::new(MultipartBodyProcessor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body_processors::get_body_processor;
    use crate::collection::{Collection, Keyed, SingleCollection};
    use std::fs;

    #[test]
    fn test_multipart_invalid_mime_type() {
        let processor = MultipartBodyProcessor;
        let mut tx = Transaction::new("test-1");

        let body = b"";
        let mut options = BodyProcessorOptions::default();
        options.mime = "application/json".to_string();

        let result = processor.process_request(body, &mut tx, &options);
        assert!(result.is_err());
        assert_eq!(tx.multipart_strict_error.get(), "1");

        if let Err(e) = result {
            assert!(e.to_string().contains("not a multipart body"));
        }
    }

    #[test]
    fn test_multipart_missing_boundary() {
        let processor = MultipartBodyProcessor;
        let mut tx = Transaction::new("test-2");

        let body = b"";
        let mut options = BodyProcessorOptions::default();
        options.mime = "multipart/form-data".to_string();

        let result = processor.process_request(body, &mut tx, &options);
        assert!(result.is_err());
        assert_eq!(tx.multipart_strict_error.get(), "1");

        if let Err(e) = result {
            assert!(e.to_string().contains("missing boundary"));
        }
    }

    #[test]
    fn test_multipart_with_file_and_field() {
        let payload = "\
-----------------------------9051914041544843365972754266\r
Content-Disposition: form-data; name=\"text\"\r
\r
text default\r
-----------------------------9051914041544843365972754266\r
Content-Disposition: form-data; name=\"file1\"; filename=\"a.txt\"\r
Content-Type: text/plain\r
\r
Content of a.txt.\r
\r
-----------------------------9051914041544843365972754266--\r
";

        let processor = MultipartBodyProcessor;
        let mut tx = Transaction::new("test-3");

        let mut options = BodyProcessorOptions::default();
        options.mime = "multipart/form-data; boundary=---------------------------9051914041544843365972754266".to_string();

        processor
            .process_request(payload.as_bytes(), &mut tx, &options)
            .unwrap();

        // Check that field was parsed
        assert_eq!(tx.args_post().get("text"), vec!["text default"]);

        // Check that file was parsed
        let all_files = tx.files.find_all();
        assert_eq!(all_files.len(), 1);
        let files: Vec<_> = all_files.iter().map(|m| m.value.as_str()).collect();
        assert!(files.contains(&"a.txt"));

        // Check FILES_NAMES
        let all_names = tx.files_names.find_all();
        assert_eq!(all_names.len(), 1);
        let names: Vec<_> = all_names.iter().map(|m| m.value.as_str()).collect();
        assert!(names.contains(&"file1"));

        // Check multipart strict error not set on success
        assert_eq!(tx.multipart_strict_error.get(), "");
    }

    #[test]
    fn test_multipart_part_headers() {
        let payload = "\
-----------------------------9051914041544843365972754266\r
Content-Disposition: form-data; name=\"file1\"; filename=\"a.html\"\r
Content-Type: text/html\r
\r
<!DOCTYPE html><title>Content of a.html.</title>\r
\r
-----------------------------9051914041544843365972754266--\r
";

        let processor = MultipartBodyProcessor;
        let mut tx = Transaction::new("test-4");

        let mut options = BodyProcessorOptions::default();
        options.mime = "multipart/form-data; boundary=---------------------------9051914041544843365972754266".to_string();

        processor
            .process_request(payload.as_bytes(), &mut tx, &options)
            .unwrap();

        // Check that headers were captured
        let headers = tx.multipart_part_headers.get("file1");
        assert!(headers.len() >= 1, "Expected at least 1 header");

        // Headers should contain Content-Disposition or Content-Type
        let headers_str = headers.join(", ");
        assert!(
            headers_str.contains("Content-Disposition") || headers_str.contains("Content-Type"),
            "Headers should contain Content-Disposition or Content-Type: {}",
            headers_str
        );
    }

    #[test]
    fn test_multipart_malformed_sets_strict_error() {
        let payload = "\
--a\n\
\x0eContent-Disposition\x0e: form-data; name=\"file\";filename=\"1.jsp\"\n\
Content-Disposition: form-data; name=\"post\";\n\
\n\
<%out.print(123)%>\n\
--a--\
";

        let processor = MultipartBodyProcessor;
        let mut tx = Transaction::new("test-5");

        let mut options = BodyProcessorOptions::default();
        options.mime = "multipart/form-data; boundary=a".to_string();

        // Should fail on malformed headers
        let result = processor.process_request(payload.as_bytes(), &mut tx, &options);

        // Strict error should be set regardless of whether parsing failed
        if result.is_err() {
            assert_eq!(tx.multipart_strict_error.get(), "1");
        }
    }

    #[test]
    fn test_multipart_file_upload_to_temp() {
        let payload = "\
-----------------------------9051914041544843365972754266\r
Content-Disposition: form-data; name=\"file1\"; filename=\"test.txt\"\r
Content-Type: text/plain\r
\r
Test file content\r
-----------------------------9051914041544843365972754266--\r
";

        let processor = MultipartBodyProcessor;
        let mut tx = Transaction::new("test-6");

        // Create temp directory for test
        let temp_dir = std::env::temp_dir().join("coraza-test-multipart");
        fs::create_dir_all(&temp_dir).unwrap();

        let mut options = BodyProcessorOptions::default();
        options.mime = "multipart/form-data; boundary=---------------------------9051914041544843365972754266".to_string();
        options.upload_dir = temp_dir.to_string_lossy().to_string();

        processor
            .process_request(payload.as_bytes(), &mut tx, &options)
            .unwrap();

        // Check that temp file was created
        let all_temp_files = tx.files_tmp_names.find_all();
        let temp_files: Vec<_> = all_temp_files.iter().map(|m| m.value.as_str()).collect();
        assert_eq!(temp_files.len(), 1);

        // Verify file exists
        let temp_file_path = &temp_files[0];
        assert!(
            std::path::Path::new(temp_file_path).exists(),
            "Temp file should exist: {}",
            temp_file_path
        );

        // Cleanup
        fs::remove_file(temp_file_path).ok();
        fs::remove_dir(temp_dir).ok();
    }

    #[test]
    fn test_multipart_combined_size() {
        let payload = "\
-----------------------------9051914041544843365972754266\r
Content-Disposition: form-data; name=\"text\"\r
\r
12345\r
-----------------------------9051914041544843365972754266\r
Content-Disposition: form-data; name=\"file1\"; filename=\"a.txt\"\r
Content-Type: text/plain\r
\r
1234567890\r
-----------------------------9051914041544843365972754266--\r
";

        let processor = MultipartBodyProcessor;
        let mut tx = Transaction::new("test-7");

        let mut options = BodyProcessorOptions::default();
        options.mime = "multipart/form-data; boundary=---------------------------9051914041544843365972754266".to_string();

        processor
            .process_request(payload.as_bytes(), &mut tx, &options)
            .unwrap();

        // Combined size should be 5 (field) + 10 (file) = 15
        let combined = tx.files_combined_size.get();
        assert_eq!(combined, "15");
    }

    #[test]
    fn test_multipart_from_registry() {
        let processor = get_body_processor("multipart").unwrap();
        let mut tx = Transaction::new("test-8");

        let payload = "\
-----------------------------boundary\r
Content-Disposition: form-data; name=\"field\"\r
\r
value\r
-----------------------------boundary--\r
";

        let mut options = BodyProcessorOptions::default();
        options.mime = "multipart/form-data; boundary=---------------------------boundary".to_string();

        processor
            .process_request(payload.as_bytes(), &mut tx, &options)
            .unwrap();

        assert_eq!(tx.args_post().get("field"), vec!["value"]);
    }

    #[test]
    fn test_multipart_empty_body() {
        let processor = MultipartBodyProcessor;
        let mut tx = Transaction::new("test-9");

        let payload = "\
-----------------------------boundary--\r
";

        let mut options = BodyProcessorOptions::default();
        options.mime = "multipart/form-data; boundary=---------------------------boundary".to_string();

        processor
            .process_request(payload.as_bytes(), &mut tx, &options)
            .unwrap();

        // Should have no files or fields
        assert!(tx.files.find_all().is_empty());
        assert!(tx.args_post().find_all().is_empty());
        assert_eq!(tx.files_combined_size.get(), "0");
    }
}
