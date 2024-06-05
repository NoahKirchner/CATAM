#![allow(nonstandard_style)]
use crate::util::function_table::{export_dll, get_function_pointer};
use crate::util::pe_headers::PeHeader;
use core::ffi::c_void;
use std::ffi::CString;
use std::mem::transmute;
use std::ptr::{null, null_mut};
pub struct Ntdll {}

impl Ntdll {
    pub unsafe fn parse(process_header: PeHeader) -> Ntdll {
        let dll = process_header
            .dll_map
            .get("ntdll.dll")
            .expect("No ntdll imported in header.");
        let function_table = export_dll(*dll);

        // NtQueryInformationProcess
        let loadlibrarya = transmute(get_function_pointer(&function_table, "NtCreateUserProcess"));

        Kernel32 {}
    }
}
