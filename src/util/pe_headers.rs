use std::os::raw::c_void;

use windows::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
use windows::core::PCSTR;
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::Win32::Foundation::{HANDLE, HMODULE};
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER64, IMAGE_DATA_DIRECTORY};

// This is the dos image header magic number.
const DOS_HEADER_MAGIC_NUMBER:u32 = 0x4D5A;
// The NT image header magic number, but since it is a dword it is padded by two null bytes.
const NT_HEADER_MAGIC_NUMBER:u32 = 0x50450000;

//Data directory array constants
const EXPORT:usize         = 0;  
const IMPORT:usize         = 1; 
const RESOURCE:usize       = 2; 
const EXCEPTION:usize      = 3;
const SECURITY:usize       = 4;
const BASERELOC:usize      = 5;
const DEBUG:usize          = 6;
const ARCHITECTURE:usize   = 7;
const GLOBALPTR:usize      = 8;
const TLS:usize            = 9;
const LOAD_CONFIG:usize    = 10;
const BOUND_IMPORT:usize   = 11;
const IAT:usize            = 12;
const DELAY_IMPORT:usize   = 13;
const COM_DESCRIPTOR:usize = 14;


pub struct PeHeader {
    pub base_address: *const c_void,
    pub entry_point: *const c_void,
    pub sections: u16,
    pub symbols:u32,
    pub symbol_table: *const c_void,
    pub text_size: u32,
    pub text_address: *const c_void,
    pub export_table_address: *const c_void,
}

impl PeHeader {
    pub unsafe fn parse() -> PeHeader {
        // Because this should always return -1, we may wish to consider hardcoding this to avoid
        // unnecessary imports.
        let process_handle:HANDLE = GetCurrentProcess();

        // Passing this a null pointer should return the handle to our current module (represented
        // by -1).
        let module_handle:HMODULE = GetModuleHandleA(PCSTR::null()).expect("Failed to get handle on own module.");
        
        let mut module_info:MODULEINFO = Default::default();

        // Too lazy to count struct size so this should work 
        let cb:u32 = 0xFFFFFFFF;
        let _ = GetModuleInformation(process_handle, module_handle, &mut module_info, cb);
        
        let base_address:*const c_void = module_info.lpBaseOfDll as *const c_void;
        let entry_point:*const c_void = module_info.EntryPoint as *const c_void;

        let pimage_dos_header: *const IMAGE_DOS_HEADER = base_address as *const IMAGE_DOS_HEADER;
        let image_dos_header:IMAGE_DOS_HEADER = *pimage_dos_header;
       
        // Verifies that we have the correct magic number. If this fails, I would put money on 
        // endian-ness issues.
        assert!(u32::from(image_dos_header.e_magic.to_be()) == DOS_HEADER_MAGIC_NUMBER);        
        
        let nt_header_offset:isize = image_dos_header.e_lfanew as isize;
        let nt_header_address:*const c_void = base_address.offset(nt_header_offset);
        
        let pnt_header: *const IMAGE_NT_HEADERS64 = nt_header_address as *const IMAGE_NT_HEADERS64;
        let nt_header:IMAGE_NT_HEADERS64 = *pnt_header;
        
        assert!(nt_header.Signature.to_be() == NT_HEADER_MAGIC_NUMBER);
        
        let image_file_header:IMAGE_FILE_HEADER = nt_header.FileHeader;
        let optional_header:IMAGE_OPTIONAL_HEADER64 = nt_header.OptionalHeader;
        
        let sections:u16 = image_file_header.NumberOfSections;

        let symbols:u32 = image_file_header.NumberOfSymbols;
        let symbol_table:*const c_void = image_file_header.PointerToSymbolTable as *const c_void;
        
        let text_size:u32 = optional_header.SizeOfCode;
        let text_address:*const c_void = base_address.offset(optional_header.BaseOfCode as isize);

        let data_directory:[IMAGE_DATA_DIRECTORY; 16] = optional_header.DataDirectory;

        let export_table_address = data_directory[EXPORT].VirtualAddress as *const c_void;


        PeHeader{
            base_address,
            entry_point,
            sections,
            symbols,
            symbol_table,
            text_size,
            text_address,
            export_table_address,
        }
    }
}

