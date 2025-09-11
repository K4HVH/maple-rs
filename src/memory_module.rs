use crate::Result;

pub trait MemoryModule {
    fn get_proc_address(&self, name: &str) -> Result<*const u8>;
    fn get_proc_address_ordinal(&self, ordinal: u16) -> Result<*const u8>;
    fn execute_entry_point(&self) -> Result<()>;
    fn call_dll_entry_point(&self, reason: u32) -> Result<bool>;
    fn free(&mut self) -> Result<()>;
    fn is_loaded(&self) -> bool;
    fn base_address(&self) -> *const u8;
    fn size(&self) -> usize;
}

pub struct MemoryModuleBuilder {
    pub resolve_imports: bool,
    pub process_relocations: bool,
    pub call_dll_main: bool,
}

impl Default for MemoryModuleBuilder {
    fn default() -> Self {
        Self {
            resolve_imports: true,
            process_relocations: true,
            call_dll_main: true,
        }
    }
}

impl MemoryModuleBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn resolve_imports(mut self, resolve: bool) -> Self {
        self.resolve_imports = resolve;
        self
    }

    pub fn process_relocations(mut self, process: bool) -> Self {
        self.process_relocations = process;
        self
    }

    pub fn call_dll_main(mut self, call: bool) -> Self {
        self.call_dll_main = call;
        self
    }

    pub fn load_from_memory(self, data: &[u8]) -> Result<Box<dyn MemoryModule>> {
        #[cfg(windows)]
        {
            use crate::windows::WindowsMemoryModule;
            WindowsMemoryModule::from_memory_with_options(data, &self)
                .map(|m| Box::new(m) as Box<dyn MemoryModule>)
        }

        #[cfg(unix)]
        {
            use crate::linux::LinuxMemoryModule;
            LinuxMemoryModule::from_memory_with_options(data, &self)
                .map(|m| Box::new(m) as Box<dyn MemoryModule>)
        }
    }
}

pub const DLL_PROCESS_ATTACH: u32 = 1;
pub const DLL_THREAD_ATTACH: u32 = 2;
pub const DLL_THREAD_DETACH: u32 = 3;
pub const DLL_PROCESS_DETACH: u32 = 0;