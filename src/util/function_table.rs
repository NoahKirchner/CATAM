use crate::util::pe_headers::PeHeader;
use windows::Win32::System::Kernel::LIST_ENTRY;
use windows::Win32::System::WindowsProgramming::LDR_DATA_TABLE_ENTRY;
use core::ffi::c_void;

pub struct FunctionTable {

}

impl FunctionTable {
    pub unsafe fn new(pe_header:PeHeader) {
/*
        let module_list = pe_header.module_list;
        let start_address = module_list.Flink as *const c_void;
        let ptest: *const LDR_DATA_TABLE_ENTRY = start_address as *const LDR_DATA_TABLE_ENTRY;
        let test:LDR_DATA_TABLE_ENTRY = *ptest;
        dbg!(test.FullDllName);
*/

    }
} 
