rule FileTypeDetection
{
    strings:
        $magic_bytes = { 4D 5A 90 00 03 00 00 00 }  // MZ header for PE files
        $magic_bytes2 = { 7F 45 4C 46 }           // ELF header
        $magic_bytes3 = { 50 4B 03 04 }           // ZIP file header
        $magic_bytes4 = { 25 50 44 46 }           // PDF header

    condition:
        // Check for PE files (Windows executables)
        $magic_bytes and filesize < 10MB
        
        // Check for ELF files (Linux executables)
        or $magic_bytes2 and filesize < 5MB
        
        // Check for ZIP files
        or $magic_bytes3 and filesize < 20MB
        
        // Check for PDF files
        or $magic_bytes4 and filesize < 15MB
}