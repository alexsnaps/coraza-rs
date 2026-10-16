// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! XML body processor (application/xml, text/xml), as Go Coraza's: its attribute values
//! and text, as Go's `encoding/xml` decoder reads them.

mod decoder;
mod tables;

use super::BodyProcessorError;
use crate::transaction::Transaction;
use decoder::{Decoder, Token};

/// Parses a request body's attribute values into REQUEST_XML `//@*`, and its text into
/// REQUEST_XML `/*`.
///
/// # Errors
///
/// If Go's decoder rejects the body, which leaves REQUEST_XML alone. A body cut short isn't
/// rejected, but read as far as it goes.
pub(super) fn process_request(body: &[u8], tx: &mut Transaction) -> Result<(), BodyProcessorError> {
    let document = Document::read(body)
        .map_err(|e| BodyProcessorError::Malformed("xml".to_string(), e.to_string()))?;
    for value in document.attribute_values {
        tx.request_xml.add("//@*", value);
    }
    for text in document.text {
        tx.request_xml.add("/*", text);
    }
    Ok(())
}

/// What the XML body processor reads of a document
#[derive(Debug, Default)]
struct Document {
    /// The values of the elements' attributes, in order
    attribute_values: Vec<String>,
    /// The text between tags, in order, each piece trimmed, and empty ones left out
    text: Vec<String>,
}

impl Document {
    /// Reads `xml` as Go Coraza's `readXML` does: a document cut short as far as it goes.
    fn read(xml: &[u8]) -> Result<Self, decoder::Error> {
        let mut decoder = Decoder::new(xml);
        let mut document = Self::default();
        loop {
            match decoder.token() {
                Ok(Some(Token::Start {
                    attribute_values, ..
                })) => document.attribute_values.extend(attribute_values),
                Ok(Some(Token::CharData(text))) => {
                    let text = text.trim();
                    if !text.is_empty() {
                        document.text.push(text.to_string());
                    }
                }
                Ok(Some(Token::End(_) | Token::Other)) => {}
                Ok(None) | Err(decoder::Error::UnexpectedEof { .. }) => return Ok(document),
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{BodyProcessorKind, inspect_request};
    use super::*;

    /// A transaction whose XML request body the XML processor inspected.
    fn inspect_xml(body: &[u8]) -> Transaction {
        inspect_request(BodyProcessorKind::Xml, "application/xml", body)
    }

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

        let Document {
            attribute_values: attrs,
            text: contents,
        } = Document::read(xml_doc).unwrap();

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

        let contents = Document::read(xml_doc).unwrap().text;

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

        let contents = Document::read(xml_doc).unwrap().text;

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

        let contents = Document::read(xml_doc).unwrap().text;

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

        let contents = Document::read(xml_doc).unwrap().text;

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
        let xml_doc = br#"<user><name>admin</name><role>superuser</role></user>"#;
        let tx = inspect_xml(xml_doc);

        // Check REQUEST_XML populated
        let xml_content = tx.request_xml.get("/*");
        assert!(xml_content.contains(&"admin".to_string()));
        assert!(xml_content.contains(&"superuser".to_string()));
    }

    #[test]
    fn test_xml_processor_with_attributes() {
        let xml_doc = br#"<config version="1.0"><setting key="debug">true</setting></config>"#;
        let tx = inspect_xml(xml_doc);

        // Check attributes
        let xml_attrs = tx.request_xml.get("//@*");
        assert!(xml_attrs.contains(&"1.0".to_string()));
        assert!(xml_attrs.contains(&"debug".to_string()));

        // Check content
        let xml_content = tx.request_xml.get("/*");
        assert!(xml_content.contains(&"true".to_string()));
    }

    #[test]
    fn test_xml_empty() {
        let xml_doc = b"<root></root>";
        let tx = inspect_xml(xml_doc);

        // Empty XML should produce no content
        let xml_content = tx.request_xml.get("/*");
        assert!(xml_content.is_empty());

        let xml_attrs = tx.request_xml.get("//@*");
        assert!(xml_attrs.is_empty());
    }

    #[test]
    fn test_xml_malformed_lenient() {
        // Malformed XML - missing closing tags
        let xml_doc = b"<root><item>value1<item>value2";
        let tx = inspect_xml(xml_doc);

        // Should still extract what it can
        let xml_content = tx.request_xml.get("/*");
        assert!(!xml_content.is_empty());
    }
}
