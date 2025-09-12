use crate::Result;
use std::ffi::OsStr;

pub trait MemoryModule {
    fn get_proc_address(&self, name: &str) -> Result<*const u8>;
    fn get_proc_address_ordinal(&self, ordinal: u16) -> Result<*const u8>;
    fn execute_entry_point(&self) -> Result<()>;
    fn call_dll_entry_point(&self, reason: u32) -> Result<bool>;
    fn execute_dll_application(&self) -> Result<()>;
    fn free(&mut self) -> Result<()>;
    fn is_loaded(&self) -> bool;
    fn base_address(&self) -> *const u8;
    fn size(&self) -> usize;

    // Resource management
    fn find_resource(&self, name: Option<&str>, resource_type: Option<&str>) -> Result<*const u8>;
    fn find_resource_ex(
        &self,
        name: Option<&str>,
        resource_type: Option<&str>,
        language: u16,
    ) -> Result<*const u8>;
    fn sizeof_resource(&self, resource: *const u8) -> Result<usize>;
    fn load_resource(&self, resource: *const u8) -> Result<*const u8>;
    fn load_string(&self, id: u32, buffer: &mut [u16]) -> Result<usize>;
    fn load_string_ex(&self, id: u32, buffer: &mut [u16], language: u16) -> Result<usize>;
}

// Function type definitions for custom callbacks
pub type CustomAllocFunction = fn(
    size: usize,
    allocation_type: u32,
    protect: u32,
    user_data: *mut std::ffi::c_void,
) -> *mut u8;
pub type CustomFreeFunction =
    fn(ptr: *mut u8, size: usize, free_type: u32, user_data: *mut std::ffi::c_void) -> bool;
pub type CustomLoadLibraryFunction =
    fn(filename: &OsStr, user_data: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
pub type CustomGetProcAddressFunction =
    fn(module: *mut std::ffi::c_void, name: &str, user_data: *mut std::ffi::c_void) -> *const u8;
pub type CustomFreeLibraryFunction =
    fn(module: *mut std::ffi::c_void, user_data: *mut std::ffi::c_void) -> bool;

pub struct MemoryModuleBuilder {
    pub resolve_imports: bool,
    pub process_relocations: bool,
    pub call_dll_main: bool,
    pub ignore_missing_imports: bool,
    pub is_application_dll: bool,
    pub alloc_function: Option<CustomAllocFunction>,
    pub free_function: Option<CustomFreeFunction>,
    pub load_library_function: Option<CustomLoadLibraryFunction>,
    pub get_proc_address_function: Option<CustomGetProcAddressFunction>,
    pub free_library_function: Option<CustomFreeLibraryFunction>,
    pub user_data: *mut std::ffi::c_void,
}

impl Default for MemoryModuleBuilder {
    fn default() -> Self {
        Self {
            resolve_imports: true,
            process_relocations: true,
            call_dll_main: true,
            ignore_missing_imports: false,
            is_application_dll: false,
            alloc_function: None,
            free_function: None,
            load_library_function: None,
            get_proc_address_function: None,
            free_library_function: None,
            user_data: std::ptr::null_mut(),
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

    pub fn ignore_missing_imports(mut self, ignore: bool) -> Self {
        self.ignore_missing_imports = ignore;
        self
    }

    pub fn is_application_dll(mut self, is_app_dll: bool) -> Self {
        self.is_application_dll = is_app_dll;
        self
    }

    pub fn alloc_function(mut self, func: CustomAllocFunction) -> Self {
        self.alloc_function = Some(func);
        self
    }

    pub fn free_function(mut self, func: CustomFreeFunction) -> Self {
        self.free_function = Some(func);
        self
    }

    pub fn load_library_function(mut self, func: CustomLoadLibraryFunction) -> Self {
        self.load_library_function = Some(func);
        self
    }

    pub fn get_proc_address_function(mut self, func: CustomGetProcAddressFunction) -> Self {
        self.get_proc_address_function = Some(func);
        self
    }

    pub fn free_library_function(mut self, func: CustomFreeLibraryFunction) -> Self {
        self.free_library_function = Some(func);
        self
    }

    pub fn user_data(mut self, data: *mut std::ffi::c_void) -> Self {
        self.user_data = data;
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
