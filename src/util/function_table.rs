use crate::util::pe_headers::{DOS_HEADER_MAGIC_NUMBER, NT_HEADER_MAGIC_NUMBER};
use core::ffi::c_void;
use std::collections::HashMap;
use windows::Win32::System::{
    Diagnostics::Debug::IMAGE_NT_HEADERS64, SystemServices::IMAGE_DOS_HEADER,
};

pub unsafe fn export_dll(dll_base_address: *mut c_void) -> HashMap<String, *mut c_void> {
    let function_table: HashMap<String, *mut c_void> = HashMap::new();
    let image_dos_header: IMAGE_DOS_HEADER = *(dll_base_address as *const IMAGE_DOS_HEADER);

    assert!(u32::from(image_dos_header.e_magic.to_be()) == DOS_HEADER_MAGIC_NUMBER);

    let image_nt_header: IMAGE_NT_HEADERS64;

    return function_table;
}
