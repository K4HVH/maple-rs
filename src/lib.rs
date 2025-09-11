pub mod error;
pub mod memory_module;
pub mod pe;
pub mod windows;

#[cfg(unix)]
pub mod linux;

pub use error::MapleError;
pub use memory_module::{MemoryModule, MemoryModuleBuilder};

pub type Result<T> = std::result::Result<T, MapleError>;

pub struct Maple;

impl Maple {
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

    pub fn load_executable_from_memory(data: &[u8]) -> Result<Box<dyn MemoryModule>> {
        Self::load_library_from_memory(data)
    }
}