//! # maple-rs
//!
//! A Rust library for loading Windows PE executables and DLLs directly from memory,
//! without needing to write them to disk first. This is a modern, safe Rust replacement
//! for the C memorymodule library.
//!
//! ## ⚠️ Security Notice
//!
//! This library enables loading and executing code from memory buffers, which can be used
//! for legitimate purposes such as:
//! - Dynamic code loading in game engines
//! - Plugin systems
//! - Testing and debugging tools
//! - Memory-efficient application packaging
//!
//! However, it could also be misused for malicious purposes. Users are responsible for
//! ensuring they only load trusted code and comply with all applicable laws and
//! security policies.
//!
//! ## Features
//!
//! - **In-Memory Loading**: Load PE executables (.exe) and libraries (.dll) from memory
//! - **Full PE Support**: Complete PE parsing, import resolution, and relocation processing
//! - **Native Execution**: Code runs exactly as if loaded from disk
//! - **Memory Safety**: Proper memory management with automatic cleanup
//! - **Cross-Platform Ready**: Windows implementation complete, Linux planned
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use maple_rs::{Maple, Result};
//! use std::fs;
//!
//! fn main() -> Result<()> {
//!     // Load an executable from memory
//!     let data = fs::read("program.exe")?;
//!     let module = Maple::load_executable_from_memory(&data)?;
//!     
//!     // Execute the program's entry point
//!     module.execute_entry_point()?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Advanced Usage
//!
//! ```rust,no_run
//! use maple_rs::{MemoryModuleBuilder, Result};
//! use std::fs;
//!
//! fn main() -> Result<()> {
//!     let data = fs::read("library.dll")?;
//!     
//!     let module = MemoryModuleBuilder::new()
//!         .resolve_imports(true)
//!         .process_relocations(true)
//!         .call_dll_main(true)
//!         .load_from_memory(&data)?;
//!     
//!     // Get a function from the loaded library
//!     let function = module.get_proc_address("MyFunction")?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Platform Support
//!
//! - **Windows**: Full support for PE executables and DLLs
//! - **Linux**: Placeholder implementation (planned for future release)
//!
//! ## Error Handling
//!
//! All operations return a `Result<T, MapleError>` with comprehensive error information:
//!
//! ```rust,no_run
//! use maple_rs::{Maple, MapleError};
//! # let data = b"dummy data";
//!
//! match Maple::load_executable_from_memory(data) {
//!     Ok(module) => {
//!         // Successfully loaded
//!     },
//!     Err(MapleError::InvalidPEFormat(msg)) => {
//!         eprintln!("Invalid PE file: {}", msg);
//!     },
//!     Err(MapleError::MemoryAllocation(msg)) => {
//!         eprintln!("Memory allocation failed: {}", msg);
//!     },
//!     Err(e) => {
//!         eprintln!("Other error: {}", e);
//!     }
//! }
//! ```

pub mod error;
pub mod memory_module;
pub mod pe;
pub mod windows;

#[cfg(unix)]
pub mod linux;

pub use error::MapleError;
pub use memory_module::{MemoryModule, MemoryModuleBuilder};

/// Result type alias for all maple-rs operations.
pub type Result<T> = std::result::Result<T, MapleError>;

/// Main entry point for the maple-rs library.
///
/// Provides convenient static methods for loading executables and libraries
/// from memory buffers.
pub struct Maple;

impl Maple {
    /// Loads a DLL/library from a memory buffer.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw bytes of the PE file to load
    ///
    /// # Returns
    ///
    /// Returns a `MemoryModule` trait object that can be used to interact with
    /// the loaded library, including getting function addresses.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use maple_rs::Maple;
    /// use std::fs;
    ///
    /// let dll_data = fs::read("library.dll").unwrap();
    /// let module = Maple::load_library_from_memory(&dll_data).unwrap();
    /// let func = module.get_proc_address("MyFunction").unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `MapleError` if:
    /// - The PE format is invalid
    /// - Memory allocation fails
    /// - Import resolution fails
    /// - Platform is not supported
    pub fn load_library_from_memory(data: &[u8]) -> Result<Box<dyn MemoryModule>> {
        #[cfg(windows)]
        {
            windows::WindowsMemoryModule::from_memory(data)
                .map(|m| Box::new(m) as Box<dyn MemoryModule>)
        }

        #[cfg(unix)]
        {
            linux::LinuxMemoryModule::from_memory(data)
                .map(|m| Box::new(m) as Box<dyn MemoryModule>)
        }
    }

    /// Loads an executable from a memory buffer.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw bytes of the PE executable to load
    ///
    /// # Returns
    ///
    /// Returns a `MemoryModule` trait object that can be used to execute
    /// the program's entry point.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use maple_rs::Maple;
    /// use std::fs;
    ///
    /// let exe_data = fs::read("program.exe").unwrap();
    /// let module = Maple::load_executable_from_memory(&exe_data).unwrap();
    /// module.execute_entry_point().unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `MapleError` if:
    /// - The PE format is invalid
    /// - Memory allocation fails
    /// - Import resolution fails
    /// - Platform is not supported
    pub fn load_executable_from_memory(data: &[u8]) -> Result<Box<dyn MemoryModule>> {
        Self::load_library_from_memory(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_maple_creation() {
        // Basic compilation test
        let _maple = Maple;
    }

    #[test]
    fn test_result_type() {
        let success: Result<i32> = Ok(42);
        let failure: Result<i32> = Err(MapleError::InvalidPEFormat("test".to_string()));

        assert_eq!(success, Ok(42));
        assert!(failure.is_err());
    }
}
