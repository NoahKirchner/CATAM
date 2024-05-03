use crate::util::pe_headers::parse_headers;
use core::ffi::{c_void, c_char};
use std::ffi::{CStr, CString};
use std::slice;
use std::collections::HashMap;
use windows::Win32::System::{
    Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_DATA_DIRECTORY}, SystemServices::IMAGE_DOS_HEADER,
};
use windows::Win32::System::SystemServices::IMAGE_EXPORT_DIRECTORY;

#[derive(Debug)]
pub struct FunctionEntry {
    pub address:*mut c_void,
    pub ordinal:u16,
}

// Data directory array constant
const EXPORT: usize = 0;
pub unsafe fn export_dll(dll_base_address: *mut c_void) -> HashMap<String, FunctionEntry> {
    let mut function_table: HashMap<String, FunctionEntry> = HashMap::new();
    // We don't need the dos header so pce out thug
    let (_, nt_header) = parse_headers(dll_base_address as *const c_void);
    // This is severely autistic, basically grabs a pointer to the export image directory from a
    // few nested structs and then dereferences it    
    // header structs
    let export_directory:IMAGE_EXPORT_DIRECTORY = *(dll_base_address.offset(nt_header.OptionalHeader.DataDirectory[EXPORT].VirtualAddress as isize) as *const IMAGE_EXPORT_DIRECTORY);
   

    let function_count = export_directory.NumberOfFunctions;

    // This creates an array slice at runtime of [u32; function_count] where each
    // u32 is an offset from dll_base_address to a symbol name. 
    let name_array = slice::from_raw_parts(dll_base_address.offset(export_directory.AddressOfNames as u32 as isize) as *const u32, function_count as usize); 
    
    let address_array = slice::from_raw_parts(dll_base_address.offset(export_directory.AddressOfFunctions as u32 as isize) as *const u32, function_count as usize);

    // This is u16 because it's a WORD not a DWORD.
    let ordinal_array = slice::from_raw_parts(dll_base_address.offset(export_directory.AddressOfNameOrdinals as u32 as isize) as *const u16, function_count as usize);

    // This is the base value for ordinals, basically add this onto the value you pull out of 
    // the ordinal array. It is a u32 by default but because rust is retarded you cannot add a u32
    // to a u16, so we are just going to cast to a u16 and pray for the best.
    let ordinal_base = export_directory.Base as u16;

    for function in 0..function_count {
        
        // Iterates through the name array, calculates the RVA (offset from base) and casts from
        // the native char* to a rust String.
        let name_offset = &name_array[function as usize];
        let pfunction_name:*const c_char = dll_base_address.offset(*name_offset as isize) as *const c_char;  
        let function_name:String = CStr::from_ptr(pfunction_name).to_string_lossy().into_owned();
    
        // Iterates through the ordinal array and adds on the ordinal base so we get the correct
        // number.
        let function_ordinal = *&ordinal_array[function as usize] + ordinal_base;
        
        // Iterates through the address array and grabs a pointer to the entry point of each
        // function.
        let address_offset = &address_array[function as usize];
        let function_address:*mut c_void = dll_base_address.offset(*address_offset as isize) as *mut c_void;
        
        function_table.insert(function_name, FunctionEntry {address:function_address, ordinal:function_ordinal});
    }

   return function_table;
}
