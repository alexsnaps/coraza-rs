// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! XML body processor (application/xml, text/xml).
//!
//! Parses XML bodies and extracts attribute values and text content.
//! This is a lenient parser that handles malformed/incomplete XML gracefully.

use super::{BodyProcessor, BodyProcessorError, BodyProcessorOptions};
use crate::collection::MapCollection;
use crate::transaction::Transaction;
use quick_xml::Reader;
use quick_xml::events::Event;

/// XML body processor
pub struct XmlBodyProcessor;

impl BodyProcessor for XmlBodyProcessor {
    fn process_request(
        &self,
        body: &[u8],
        tx: &mut Transaction,
        _options: &BodyProcessorOptions,
    ) -> Result<(), BodyProcessorError> {
        // Parse XML and extract attributes and content
        let (attrs, contents) = parse_xml(body);

        // Populate REQUEST_XML collection
        // //@* = all attribute values
        // /* = all text content
        let request_xml = &mut tx.request_xml;

        // Store all attribute values under //@* key
        for attr in attrs {
            request_xml.add("//@*", &attr);
        }

        // Store all content values under /* key
        for content in contents {
            request_xml.add("/*", &content);
        }

        Ok(())
    }

    fn process_response(
        &self,
        _body: &[u8],
        _tx: &mut Transaction,
        _options: &BodyProcessorOptions,
    ) -> Result<(), BodyProcessorError> {
        // XML processor doesn't process response bodies in this implementation
        Ok(())
    }
}

/// Parse XML and extract attribute values and text content
///
/// This is a lenient parser that:
/// - Extracts all attribute values from XML elements
/// - Extracts all text content (trimmed of whitespace)
/// - Handles malformed/incomplete XML gracefully (doesn't error on unexpected EOF)
///
/// # Arguments
///
/// * `xml_data` - The raw XML bytes
///
/// # Returns
///
/// A tuple of (attribute_values, text_contents)
fn parse_xml(xml_data: &[u8]) -> (Vec<String>, Vec<String>) {
    let mut attrs = Vec::new();
    let mut contents = Vec::new();

    let mut reader = Reader::from_reader(xml_data);
    reader.config_mut().check_end_names = false; // Lenient mode
    reader.config_mut().trim_text(true); // Trim whitespace

    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                // Extract attribute values
                for attr in e.attributes().flatten() {
                    if let Ok(value) = attr.decode_and_unescape_value(reader.decoder()) {
                        attrs.push(value.to_string());
                    }
                }
            }
            Ok(Event::Text(e)) => {
                // Extract text content (already trimmed by config)
                if let Ok(text) = e.unescape() {
                    let text_str = text.trim();
                    if !text_str.is_empty() {
                        contents.push(text_str.to_string());
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => {
                // Lenient mode - ignore errors (including unexpected EOF)
                // Just stop parsing when we hit an error
                break;
            }
            _ => {} // Ignore other events (comments, declarations, etc.)
        }
        buf.clear();
    }

    (attrs, contents)
}

/// Factory function for creating XML body processors
pub fn create_xml() -> Box<dyn BodyProcessor> {
    Box::new(XmlBodyProcessor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body_processors::get_body_processor;
    use crate::collection::Keyed;

    #[test]
    fn test_xml_attributes() {
        // Go test: TestXMLAttribures
        let xml_doc = br#"<?xml version="1.0" encoding="UTF-8"?>
<bookstore>
<book>
  <title lang="en">Harry <bold>Potter</bold> Biography</title>
  <price secret="value">29.99</price>
</book>

<book>
  <title lang="en">Learning XML</title>
  <price>39.95</price>
</book>

</bookstore>"#;

        let (attrs, contents) = parse_xml(xml_doc);

        // Should have 3 attributes: "en", "value", "en"
        assert_eq!(attrs.len(), 3, "Expected 3 attributes, got {}", attrs.len());

        // Should have 6 content items
        assert_eq!(
            contents.len(),
            6,
            "Expected 6 contents, got {}",
            contents.len()
        );

        // Check expected attributes
        let expected_attrs = vec!["en", "value"];
        for attr in &expected_attrs {
            assert!(
                attrs.contains(&attr.to_string()),
                "Expected attribute {} in {:?}",
                attr,
                attrs
            );
        }

        // Check expected contents
        let expected_contents = vec![
            "Harry",
            "Potter",
            "Biography",
            "29.99",
            "Learning XML",
            "39.95",
        ];
        for content in &expected_contents {
            assert!(
                contents.contains(&content.to_string()),
                "Expected content {} in {:?}",
                content,
                contents
            );
        }
    }

    #[test]
    fn test_xml_payload_flexibility() {
        // Go test: TestXMLPayloadFlexibility
        let xml_doc = br#"<note>
			<to>Tove</to>
			<from>Jani</from>
			<heading>Reminder</heading>
			<body>Don't forget me this weekend!
		</note>"#;

        let (_, contents) = parse_xml(xml_doc);

        assert_eq!(
            contents.len(),
            4,
            "Expected 4 contents, got {}",
            contents.len()
        );

        let expected_contents = vec!["Tove", "Jani", "Reminder", "Don't forget me this weekend!"];
        for content in &expected_contents {
            assert!(
                contents.contains(&content.to_string()),
                "Expected content {} in {:?}",
                content,
                contents
            );
        }
    }

    #[test]
    fn test_xml_unexpected_eof_in_middle_of_text() {
        // Go test: TestXMLUnexpectedEOF - inTheMiddleOfText
        let xml_doc = br#"<note>
			<to>Tove</to>
			<from>Jani</from>
			<heading>Reminder</heading>
			<body>Don't forget"#;

        let (_, contents) = parse_xml(xml_doc);

        let expected = ["Tove", "Jani", "Reminder", "Don't forget"];
        assert_eq!(
            contents.len(),
            expected.len(),
            "Expected {} contents, got {}",
            expected.len(),
            contents.len()
        );

        for (i, want) in expected.iter().enumerate() {
            assert_eq!(
                contents[i], *want,
                "Content mismatch at index {}: got {}, want {}",
                i, contents[i], want
            );
        }
    }

    #[test]
    fn test_xml_unexpected_eof_in_middle_of_start_element() {
        // Go test: TestXMLUnexpectedEOF - inTheMiddleOfStartElement
        let xml_doc = br#"<note>
			<to>Tove</to>
			<from>Jani</from>
			<heading>Reminder</heading>
			<bod"#;

        let (_, contents) = parse_xml(xml_doc);

        let expected = ["Tove", "Jani", "Reminder"];
        assert_eq!(
            contents.len(),
            expected.len(),
            "Expected {} contents, got {}",
            expected.len(),
            contents.len()
        );

        for (i, want) in expected.iter().enumerate() {
            assert_eq!(
                contents[i], *want,
                "Content mismatch at index {}: got {}, want {}",
                i, contents[i], want
            );
        }
    }

    #[test]
    fn test_xml_unexpected_eof_in_middle_of_end_element() {
        // Go test: TestXMLUnexpectedEOF - inTheMiddleOfEndElement
        let xml_doc = br#"<note>
			<to>Tove</to>
			<from>Jani</from>
			<heading>Reminder</heading"#;

        let (_, contents) = parse_xml(xml_doc);

        let expected = ["Tove", "Jani", "Reminder"];
        assert_eq!(
            contents.len(),
            expected.len(),
            "Expected {} contents, got {}",
            expected.len(),
            contents.len()
        );

        for (i, want) in expected.iter().enumerate() {
            assert_eq!(
                contents[i], *want,
                "Content mismatch at index {}: got {}, want {}",
                i, contents[i], want
            );
        }
    }

    #[test]
    fn test_xml_processor_basic() {
        let processor = XmlBodyProcessor;
        let mut tx = Transaction::new("test-1");

        let xml_doc = br#"<user><name>admin</name><role>superuser</role></user>"#;
        processor
            .process_request(xml_doc, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        // Check REQUEST_XML populated
        let xml_content = tx.request_xml.get("/*");
        assert!(xml_content.contains(&"admin".to_string()));
        assert!(xml_content.contains(&"superuser".to_string()));
    }

    #[test]
    fn test_xml_processor_with_attributes() {
        let processor = XmlBodyProcessor;
        let mut tx = Transaction::new("test-2");

        let xml_doc = br#"<config version="1.0"><setting key="debug">true</setting></config>"#;
        processor
            .process_request(xml_doc, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        // Check attributes
        let xml_attrs = tx.request_xml.get("//@*");
        assert!(xml_attrs.contains(&"1.0".to_string()));
        assert!(xml_attrs.contains(&"debug".to_string()));

        // Check content
        let xml_content = tx.request_xml.get("/*");
        assert!(xml_content.contains(&"true".to_string()));
    }

    #[test]
    fn test_xml_from_registry() {
        let processor = get_body_processor("xml").unwrap();
        let mut tx = Transaction::new("test-3");

        let xml_doc = br#"<test>value</test>"#;
        processor
            .process_request(xml_doc, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        let xml_content = tx.request_xml.get("/*");
        assert!(xml_content.contains(&"value".to_string()));
    }

    #[test]
    fn test_xml_empty() {
        let processor = XmlBodyProcessor;
        let mut tx = Transaction::new("test-4");

        let xml_doc = b"<root></root>";
        processor
            .process_request(xml_doc, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        // Empty XML should produce no content
        let xml_content = tx.request_xml.get("/*");
        assert!(xml_content.is_empty());

        let xml_attrs = tx.request_xml.get("//@*");
        assert!(xml_attrs.is_empty());
    }

    #[test]
    fn test_xml_malformed_lenient() {
        let processor = XmlBodyProcessor;
        let mut tx = Transaction::new("test-5");

        // Malformed XML - missing closing tags
        let xml_doc = b"<root><item>value1<item>value2";
        processor
            .process_request(xml_doc, &mut tx, &BodyProcessorOptions::default())
            .unwrap();

        // Should still extract what it can
        let xml_content = tx.request_xml.get("/*");
        assert!(!xml_content.is_empty());
    }
}
