
use std::fs;
use std::path::PathBuf;

pub struct TestFixtures;

impl TestFixtures {
    pub fn get_minimal_pdf() -> Vec<u8> {
        b"%PDF-1.4
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
%%EOF".to_vec()
    }

    pub fn get_encrypted_pdf() -> Vec<u8> {
        // Minimal encrypted PDF for testing
        b"%PDF-1.4
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

4 0 obj
<<
/Filter /Standard
/V 1
/R 2
/O <01234567890123456789012345678901>
/U <01234567890123456789012345678901>
/P -44
>>
endobj

xref
0 5
0000000000 65535 f 
0000000010 00000 n 
0000000053 00000 n 
0000000125 00000 n 
0000000200 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
/Encrypt 4 0 R
>>
startxref
350
%%EOF".to_vec()
    }

    pub fn get_malformed_pdf() -> Vec<u8> {
        b"This is not a valid PDF file".to_vec()
    }

    pub fn get_javascript_pdf() -> Vec<u8> {
        b"%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction 4 0 R
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

4 0 obj
<<
/S /JavaScript
/JS (app.alert('Malicious JavaScript');)
>>
endobj

xref
0 5
0000000000 65535 f 
0000000010 00000 n 
0000000079 00000 n 
0000000151 00000 n 
0000000223 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
295
%%EOF".to_vec()
    }
}
