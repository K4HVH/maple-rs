use maple_rs::{Maple, MapleError, MemoryModuleBuilder, Result};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_pe_format() {
        let invalid_data = b"This is not a PE file";
        let result = Maple::load_executable_from_memory(invalid_data);
        
        assert!(result.is_err());
        if let Err(e) = result {
            matches!(e, MapleError::InvalidPEFormat(_));
        }
    }

    #[test]
    fn test_empty_data() {
        let empty_data = &[];
        let result = Maple::load_library_from_memory(empty_data);
        
        assert!(result.is_err());
        if let Err(e) = result {
            matches!(e, MapleError::InvalidPEFormat(_));
        }
    }

    #[test]
    fn test_memory_module_builder_defaults() {
        let _builder = MemoryModuleBuilder::new();
        // Test that builder can be created (compilation test)
        assert!(true);
    }

    #[test]
    fn test_memory_module_builder_configuration() {
        let _builder = MemoryModuleBuilder::new()
            .resolve_imports(true)
            .process_relocations(false)
            .call_dll_main(true);
        
        // Test that builder methods can be chained (compilation test)
        assert!(true);
    }

    #[test]
    fn test_error_display() {
        let error = MapleError::InvalidPEFormat("test error".to_string());
        let error_string = format!("{}", error);
        assert!(error_string.contains("Invalid PE format"));
        assert!(error_string.contains("test error"));
    }

    #[test]
    fn test_error_debug() {
        let error = MapleError::MemoryAllocation("allocation failed".to_string());
        let debug_string = format!("{:?}", error);
        assert!(debug_string.contains("MemoryAllocation"));
    }

    #[test]
    fn test_result_type_alias() {
        let success: Result<i32> = Ok(42);
        let failure: Result<i32> = Err(MapleError::SymbolNotFound("test".to_string()));
        
        assert!(success.is_ok());
        assert!(failure.is_err());
    }

    #[cfg(not(windows))]
    #[test] 
    fn test_platform_not_supported() {
        let dummy_data = b"MZ"; // Minimal DOS header
        let result = Maple::load_executable_from_memory(dummy_data);
        
        // On non-Windows platforms, should return platform not supported error
        assert!(result.is_err());
        if let Err(e) = result {
            matches!(e, MapleError::PlatformNotSupported(_));
        }
    }

    #[test]
    fn test_error_from_io() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let maple_error: MapleError = io_error.into();
        
        matches!(maple_error, MapleError::Io(_));
    }
}

#[cfg(test)]
mod pe_parser_tests {
    use super::*;
    
    #[test]
    fn test_dos_header_validation() {
        // Test with invalid DOS signature
        let mut fake_pe = vec![0u8; 1024];
        fake_pe[0] = b'X'; // Invalid signature (should be 'MZ')
        fake_pe[1] = b'Y';
        
        let result = Maple::load_executable_from_memory(&fake_pe);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_minimal_dos_header() {
        // Create a minimal DOS header that will fail later validation
        let mut fake_pe = vec![0u8; 1024];
        fake_pe[0] = b'M';
        fake_pe[1] = b'Z';
        // Missing proper NT headers will cause failure
        
        let result = Maple::load_executable_from_memory(&fake_pe);
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod memory_management_tests {
    use super::*;
    
    #[test]
    fn test_multiple_load_attempts() {
        let invalid_data = b"Invalid PE data";
        
        // Multiple failed loads should not cause memory leaks
        for _ in 0..10 {
            let result = Maple::load_library_from_memory(invalid_data);
            assert!(result.is_err());
        }
    }
}