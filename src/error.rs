use thiserror::Error;

#[derive(Error, Debug)]
pub enum MapleError {
    #[error("Invalid PE format: {0}")]
    InvalidPEFormat(String),
    
    #[error("Memory allocation failed: {0}")]
    MemoryAllocation(String),
    
    #[error("Import resolution failed: {0}")]
    ImportResolution(String),
    
    #[error("Relocation processing failed: {0}")]
    RelocationFailed(String),
    
    #[error("Symbol not found: {0}")]
    SymbolNotFound(String),
    
    #[error("Execution failed: {0}")]
    ExecutionFailed(String),
    
    #[error("Platform not supported: {0}")]
    PlatformNotSupported(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[cfg(windows)]
    #[error("Windows API error: {0}")]
    WindowsApi(u32),
}