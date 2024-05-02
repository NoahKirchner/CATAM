use crate::util::pe_headers::parse_headers;
use core::ffi::c_void;
use std::slice;
use std::collections::HashMap;
use windows::Win32::System::{
    Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_DATA_DIRECTORY}, SystemServices::IMAGE_DOS_HEADER,
};
use windows::Win32::System::SystemServices::IMAGE_EXPORT_DIRECTORY;



// Data directory array constant
const EXPORT: usize = 0;
pub unsafe fn export_dll(dll_base_address: *mut c_void) -> HashMap<String, *mut c_void> {
    let function_table: HashMap<String, *mut c_void> = HashMap::new();
    let (dos_header, nt_header) = parse_headers(dll_base_address as *const c_void);
    // This is severely autistic, basically grabs a pointer to the export image directory from a
    // few nested structs and then dereferences it    
    // header structs
    dbg!(nt_header.OptionalHeader.DataDirectory[EXPORT].VirtualAddress);
    let export_directory:IMAGE_EXPORT_DIRECTORY = *(dll_base_address.offset(nt_header.OptionalHeader.DataDirectory[EXPORT].VirtualAddress as isize) as *const IMAGE_EXPORT_DIRECTORY);
   
    dbg!(export_directory);

    let name_count = export_directory.NumberOfNames;

    // Notes for tomorrow, this creates an array slice at runtime of [u32; name_count] where each
    // u32 is an offset from dll_base_address to a symbol name. 
    let name_array = slice::from_raw_parts(dll_base_address.offset(export_directory.AddressOfNames as u32 as isize) as *const u32, name_count as usize); 
    dbg!(name_array);

    // This is not giving any memory access issues and it is pointing to the correct place, just
    // have to properly cast these to ascii and we will be able to get a list of names.
    for name in 0..name_count {
        let offset = &name_array[name as usize];
        dbg!(*(dll_base_address.offset(*offset as isize) as *const u32));
    }

   return function_table;
}
