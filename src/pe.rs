use crate::{MapleError, Result};
use std::mem;

#[repr(C)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: u32,
}

#[repr(C)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
pub struct ImageOptionalHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

#[repr(C)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[repr(C)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_line_numbers: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub characteristics: u32,
}

#[repr(C)]
pub struct ImageImportDescriptor {
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub first_thunk: u32,
}

#[repr(C)]
pub struct ImageImportByName {
    pub hint: u16,
    pub name: [u8; 1],
}

#[repr(C)]
pub struct ImageBaseRelocation {
    pub virtual_address: u32,
    pub size_of_block: u32,
}

#[repr(C)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

#[repr(C)]
pub struct ImageTlsDirectory32 {
    pub start_address_of_raw_data: u32,
    pub end_address_of_raw_data: u32,
    pub address_of_index: u32,
    pub address_of_callbacks: u32,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}

#[repr(C)]
pub struct ImageTlsDirectory64 {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}

#[repr(C)]
pub struct ImageResourceDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub number_of_name_entries: u16,
    pub number_of_id_entries: u16,
}

#[repr(C)]
pub struct ImageResourceDirectoryEntry {
    pub name_or_id: u32,
    pub offset_to_data_or_directory: u32,
}

#[repr(C)]
pub struct ImageResourceDataEntry {
    pub offset_to_data: u32,
    pub size: u32,
    pub code_page: u32,
    pub reserved: u32,
}

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550;
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x010b;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020b;

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;

pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
pub const IMAGE_REL_BASED_HIGH: u16 = 1;
pub const IMAGE_REL_BASED_LOW: u16 = 2;
pub const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
pub const IMAGE_REL_BASED_HIGHADJ: u16 = 4;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;

pub const IMAGE_ORDINAL_FLAG32: u32 = 0x80000000;
pub const IMAGE_ORDINAL_FLAG64: u64 = 0x8000000000000000;

#[derive(Clone, Copy, Debug)]
pub enum PEArchitecture {
    PE32,
    PE32Plus,
}

pub enum OptionalHeader<'a> {
    PE32(&'a ImageOptionalHeader32),
    PE32Plus(&'a ImageOptionalHeader64),
}

pub struct PEParser<'a> {
    data: &'a [u8],
    _dos_header: &'a ImageDosHeader,
    _nt_headers_offset: usize,
    file_header: &'a ImageFileHeader,
    pub optional_header: &'a ImageOptionalHeader64,
    data_directories: &'a [ImageDataDirectory],
    sections: Vec<&'a ImageSectionHeader>,
}

impl<'a> PEParser<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self> {
        if data.len() < mem::size_of::<ImageDosHeader>() {
            return Err(MapleError::InvalidPEFormat("File too small for DOS header".to_string()));
        }

        let dos_header = unsafe { &*(data.as_ptr() as *const ImageDosHeader) };

        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(MapleError::InvalidPEFormat("Invalid DOS signature".to_string()));
        }

        let nt_headers_offset = dos_header.e_lfanew as usize;
        if nt_headers_offset + 4 > data.len() {
            return Err(MapleError::InvalidPEFormat("Invalid NT headers offset".to_string()));
        }

        let nt_signature = u32::from_le_bytes([
            data[nt_headers_offset],
            data[nt_headers_offset + 1],
            data[nt_headers_offset + 2],
            data[nt_headers_offset + 3],
        ]);

        if nt_signature != IMAGE_NT_SIGNATURE {
            return Err(MapleError::InvalidPEFormat("Invalid NT signature".to_string()));
        }

        let file_header_offset = nt_headers_offset + 4;
        if file_header_offset + mem::size_of::<ImageFileHeader>() > data.len() {
            return Err(MapleError::InvalidPEFormat("Invalid file header".to_string()));
        }

        let file_header = unsafe { &*(data[file_header_offset..].as_ptr() as *const ImageFileHeader) };

        let optional_header_offset = file_header_offset + mem::size_of::<ImageFileHeader>();
        if optional_header_offset + mem::size_of::<ImageOptionalHeader64>() > data.len() {
            return Err(MapleError::InvalidPEFormat("Invalid optional header".to_string()));
        }

        let optional_header = unsafe { &*(data[optional_header_offset..].as_ptr() as *const ImageOptionalHeader64) };

        if optional_header.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            return Err(MapleError::InvalidPEFormat("Not a 64-bit executable".to_string()));
        }

        let data_directories_offset = optional_header_offset + mem::size_of::<ImageOptionalHeader64>();
        let data_directories = unsafe {
            std::slice::from_raw_parts(
                data[data_directories_offset..].as_ptr() as *const ImageDataDirectory,
                optional_header.number_of_rva_and_sizes as usize,
            )
        };

        let sections_offset = optional_header_offset + file_header.size_of_optional_header as usize;
        let mut sections = Vec::new();

        for i in 0..file_header.number_of_sections {
            let section_offset = sections_offset + i as usize * mem::size_of::<ImageSectionHeader>();
            if section_offset + mem::size_of::<ImageSectionHeader>() > data.len() {
                return Err(MapleError::InvalidPEFormat("Invalid section header".to_string()));
            }

            let section = unsafe { &*(data[section_offset..].as_ptr() as *const ImageSectionHeader) };
            sections.push(section);
        }

        Ok(PEParser {
            data,
            _dos_header: dos_header,
            _nt_headers_offset: nt_headers_offset,
            file_header,
            optional_header,
            data_directories,
            sections,
        })
    }

    pub fn image_base(&self) -> u64 {
        self.optional_header.image_base
    }

    pub fn size_of_image(&self) -> u32 {
        self.optional_header.size_of_image
    }

    pub fn entry_point(&self) -> u32 {
        self.optional_header.address_of_entry_point
    }

    pub fn sections(&self) -> &[&ImageSectionHeader] {
        &self.sections
    }

    pub fn data_directory(&self, index: usize) -> Option<&ImageDataDirectory> {
        self.data_directories.get(index)
    }

    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for section in &self.sections {
            if rva >= section.virtual_address && rva < section.virtual_address + section.virtual_size {
                let offset = rva - section.virtual_address;
                return Some(section.pointer_to_raw_data as usize + offset as usize);
            }
        }
        None
    }

    pub fn get_data_at_rva(&self, rva: u32, size: usize) -> Option<&[u8]> {
        let offset = self.rva_to_offset(rva)?;
        if offset + size <= self.data.len() {
            Some(&self.data[offset..offset + size])
        } else {
            None
        }
    }

    pub fn get_import_directory(&self) -> Option<&ImageDataDirectory> {
        self.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT)
    }

    pub fn get_export_directory(&self) -> Option<&ImageDataDirectory> {
        self.data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT)
    }

    pub fn get_base_relocation_directory(&self) -> Option<&ImageDataDirectory> {
        self.data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC)
    }

    pub fn get_tls_directory(&self) -> Option<&ImageDataDirectory> {
        self.data_directory(IMAGE_DIRECTORY_ENTRY_TLS)
    }

    pub fn get_resource_directory(&self) -> Option<&ImageDataDirectory> {
        self.data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE)
    }

    pub fn is_dll(&self) -> bool {
        const IMAGE_FILE_DLL: u16 = 0x2000;
        (self.file_header.characteristics & IMAGE_FILE_DLL) != 0
    }
}