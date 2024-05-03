use crate::util::pe_headers::PeHeader;
use crate::util::function_table::{export_dll, FunctionEntry};
use core::ffi::{c_void};
use std::mem::transmute;
use std::ptr::{null, null_mut};
pub struct Kernel32 {
    virtualalloc:unsafe extern "C" fn(*mut c_void, usize, u32, u32)->*mut c_void,
    //VirtualProtect:u32,
    //CreateThread:u32,
    //WaitForSingleObject:u32,
}

impl Kernel32 {
    pub unsafe fn parse(process_header:PeHeader)->Kernel32{
        let dll = process_header.dll_map.get("kernel32.dll").expect("No kernel32 imported in header.");
        let function_table = export_dll(*dll);
    
        let pvirtualalloc:*mut c_void = function_table.get("VirtualAlloc").expect("Failed to get function").address;
        let virtualalloc:unsafe extern "C" fn(*mut c_void, usize, u32, u32)->*mut c_void = transmute(pvirtualalloc);
        Kernel32{
            virtualalloc
        }    
    }

    pub unsafe fn VirtualAlloc(self, lpAddress:Option<*mut c_void>, dwSize:usize, flAllocationType:u32, flProtect:u32)->*mut c_void {
        let lp_address = match lpAddress {
            None => null_mut() as *mut c_void,
            Some(x) => x,
        };
        (self.virtualalloc)(lp_address, dwSize, flAllocationType, flProtect)
    }

}


