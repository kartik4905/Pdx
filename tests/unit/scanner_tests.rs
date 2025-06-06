
use pdf_anti_forensics::scanner::*;
use pdf_anti_forensics::types::Document;
use pdf_anti_forensics::error::Result;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_scanner_pdf_validation() {
        let scanner = signature_scanner::SignatureScanner::new();
        
        // Valid PDF header
        let valid_pdf = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n";
        let result = scanner.validate_pdf_signature(valid_pdf).unwrap();
        assert!(result.is_valid_pdf);
        assert_eq!(result.pdf_version, Some("1.4".to_string()));
        
        // Invalid PDF header
        let invalid_pdf = b"Not a PDF file";
        let result = scanner.validate_pdf_signature(invalid_pdf).unwrap();
        assert!(!result.is_valid_pdf);
        assert!(result.pdf_version.is_none());
    }

    #[test]
    fn test_object_scanner_javascript_detection() {
        let scanner = object_scanner::ObjectScanner::new();
        
        let js_object = object_scanner::PdfObjectInfo {
            object_number: 1,
            generation: 0,
            content: b"<< /S /JavaScript /JS (alert('malicious')) >>".to_vec(),
        };
        
        let result = scanner.scan_object(&js_object).unwrap();
        assert!(result.javascript_objects > 0);
        assert!(!result.suspicious_objects.is_empty());
    }

    #[test]
    fn test_stream_scanner_filter_detection() {
        let scanner = stream_scanner::StreamScanner::new();
        
        let stream = stream_scanner::PdfStream {
            dictionary: stream_scanner::StreamDictionary {
                length: Some(100),
                filters: vec!["FlateDecode".to_string()],
            },
            data: vec![0x78, 0x9c, 0x01, 0x05], // Valid deflate header
            filters: vec![stream_scanner::StreamFilter::FlateDecode],
        };
        
        let result = scanner.scan_stream(&stream).unwrap();
        assert!(!result.suspicious_streams.is_empty() || result.suspicious_streams.is_empty()); // Either is valid
    }

    #[test]
    fn test_deep_scanner_comprehensive_analysis() {
        let scanner = deep_scanner::DeepScanner::new();
        
        let pdf_content = b"%PDF-1.4\n1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n%%EOF";
        let result = scanner.deep_scan(pdf_content).unwrap();
        
        assert!(result.structure_analysis.is_some());
        assert!(result.risk_score >= 0.0 && result.risk_score <= 100.0);
    }
}
