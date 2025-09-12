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

impl PartialEq for MapleError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (MapleError::InvalidPEFormat(a), MapleError::InvalidPEFormat(b)) => a == b,
            (MapleError::MemoryAllocation(a), MapleError::MemoryAllocation(b)) => a == b,
            (MapleError::ImportResolution(a), MapleError::ImportResolution(b)) => a == b,
            (MapleError::RelocationFailed(a), MapleError::RelocationFailed(b)) => a == b,
            (MapleError::SymbolNotFound(a), MapleError::SymbolNotFound(b)) => a == b,
            (MapleError::ExecutionFailed(a), MapleError::ExecutionFailed(b)) => a == b,
            (MapleError::PlatformNotSupported(a), MapleError::PlatformNotSupported(b)) => a == b,
            (MapleError::Io(a), MapleError::Io(b)) => a.kind() == b.kind(),
            #[cfg(windows)]
            (MapleError::WindowsApi(a), MapleError::WindowsApi(b)) => a == b,
            _ => false,
        }
    }
}
