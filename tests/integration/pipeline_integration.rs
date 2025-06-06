
use pdf_anti_forensics::pipeline::Pipeline;
use pdf_anti_forensics::config::Config;
use pdf_anti_forensics::types::Document;
use std::path::PathBuf;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_full_pipeline_execution() {
        let config = Config::default();
        let pipeline = Pipeline::new(config);
        
        // Create a simple test PDF
        let test_pdf = create_test_pdf();
        let document = Document::from_bytes(test_pdf).unwrap();
        
        let result = pipeline.process(document).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pipeline_stage_by_stage() {
        let config = Config::default();
        let pipeline = Pipeline::new(config);
        
        let test_pdf = create_test_pdf();
        let document = Document::from_bytes(test_pdf).unwrap();
        
        // Test Stage 0: Initial Load & Verification
        let stage0_result = pipeline.execute_stage_0(&document).await;
        assert!(stage0_result.is_ok());
        
        // Test Stage 1: Deep Structure Analysis
        let stage1_result = pipeline.execute_stage_1(&document).await;
        assert!(stage1_result.is_ok());
    }

    fn create_test_pdf() -> Vec<u8> {
        // Minimal valid PDF structure
        let pdf_content = b"%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj

xref
0 4
0000000000 65535 f 
0000000010 00000 n 
0000000053 00000 n 
0000000125 00000 n 
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
189
%%EOF";
        pdf_content.to_vec()
    }
}
