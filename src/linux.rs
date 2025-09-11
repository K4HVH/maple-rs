use crate::{
    error::MapleError,
    memory_module::{MemoryModule, MemoryModuleBuilder},
    Result,
};

pub struct LinuxMemoryModule {
    _placeholder: (),
}

impl LinuxMemoryModule {
    pub fn from_memory(_data: &[u8]) -> Result<Self> {
        Err(MapleError::PlatformNotSupported(
            "Linux implementation not yet available".to_string(),
        ))
    }

    pub fn from_memory_with_options(
        _data: &[u8],
        _options: &MemoryModuleBuilder,
    ) -> Result<Self> {
        Err(MapleError::PlatformNotSupported(
            "Linux implementation not yet available".to_string(),
        ))
    }
}

impl MemoryModule for LinuxMemoryModule {
    fn get_proc_address(&self, _name: &str) -> Result<*const u8> {
        Err(MapleError::PlatformNotSupported(
            "Linux implementation not yet available".to_string(),
        ))
    }

    fn get_proc_address_ordinal(&self, _ordinal: u16) -> Result<*const u8> {
        Err(MapleError::PlatformNotSupported(
            "Linux implementation not yet available".to_string(),
        ))
    }

    fn execute_entry_point(&self) -> Result<()> {
        Err(MapleError::PlatformNotSupported(
            "Linux implementation not yet available".to_string(),
        ))
    }

    fn call_dll_entry_point(&self, _reason: u32) -> Result<bool> {
        Err(MapleError::PlatformNotSupported(
            "Linux implementation not yet available".to_string(),
        ))
    }

    fn free(&mut self) -> Result<()> {
        Err(MapleError::PlatformNotSupported(
            "Linux implementation not yet available".to_string(),
        ))
    }

    fn is_loaded(&self) -> bool {
        false
    }

    fn base_address(&self) -> *const u8 {
        std::ptr::null()
    }

    fn size(&self) -> usize {
        0
    }
}