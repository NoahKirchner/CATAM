use crate::util::function_table::{export_dll, FunctionEntry};
use crate::util::pe_headers::PeHeader;
use core::ffi::c_void;
use std::mem::transmute;
use std::ptr::{null, null_mut};
pub struct Kernel32 {
    virtualalloc: unsafe extern "C" fn(*mut c_void, usize, u32, u32) -> *mut c_void,
    virtualprotect: unsafe extern "C" fn(*const c_void, usize, u32, *mut u32) -> (),
    // Thread attributes (None for our purposes), stack size, pointer to buffer, pointer to
    // variable to be passed to the thread, creation flags, thread id (None for our purposes)
    createthread: unsafe extern "C" fn(
        *const c_void,
        u32,
        *mut c_void,
        *const c_void,
        u32,
        *const u32,
    ) -> isize,
    // isize is a HANDLE, u32 is time (use the INFINITE constant)
    waitforsingleobject: unsafe extern "C" fn(isize, u32) -> (),
}

impl Kernel32 {
    pub unsafe fn parse(process_header: PeHeader) -> Kernel32 {
        let dll = process_header
            .dll_map
            .get("kernel32.dll")
            .expect("No kernel32 imported in header.");
        let function_table = export_dll(*dll);

        //TODO turn this awful retarded shit into a macro bro please
        let pvirtualalloc: *mut c_void = function_table
            .get("VirtualAlloc")
            .expect("Failed to get function")
            .address;

        let virtualalloc: unsafe extern "C" fn(*mut c_void, usize, u32, u32) -> *mut c_void =
            transmute(pvirtualalloc);

        let pvirtualprotect: *mut c_void = function_table
            .get("VirtualProtect")
            .expect("Failed to get function")
            .address;

        let virtualprotect: unsafe extern "C" fn(
            lpaddress: *const c_void,
            dwsize: usize,
            flnewprotect: u32,
            lpfloldprotect: *mut u32,
        ) -> () = transmute(pvirtualprotect);

        let pcreatethread: *mut c_void = function_table
            .get("CreateThread")
            .expect("Failed to get function")
            .address;
        
        // TODO error handling for thread return (if you really care about that lol)
        let createthread: unsafe extern "C" fn(
            lpthreadattributes: *const c_void,
            dwstacksize: u32,
            lpstartaddress: *mut c_void,
            lpparameter: *const c_void,
            dwcreationflags: u32,
            lpthreadid: *const u32,
        ) -> isize = transmute(pcreatethread);

        let pwaitforsingleobject: *mut c_void = function_table
            .get("WaitForSingleObject")
            .expect("Failed to get function")
            .address;
        
        let waitforsingleobject: unsafe extern "C" fn(hhandle: isize, dwmilliseconds: u32) -> () =
            transmute(pwaitforsingleobject);

        Kernel32 {
            virtualalloc,
            virtualprotect,
            createthread,
            waitforsingleobject,
        }
    }

    pub unsafe fn VirtualAlloc(
        &self,
        lpAddress: Option<*mut c_void>,
        dwSize: usize,
        flAllocationType: u32,
        flProtect: u32,
    ) -> *mut c_void {
        let lp_address = match lpAddress {
            None => null_mut() as *mut c_void,
            Some(x) => x,
        };
        (self.virtualalloc)(lp_address, dwSize, flAllocationType, flProtect)
    }
    // TODO implement error handling by checking the result of lpfloldprotect
    pub unsafe fn VirtualProtect(
        &self,
        lpaddress: *const c_void,
        dwsize: usize,
        flnewprotect: u32,
        lpfloldprotect: *mut u32,
    ) -> () {
        (self.virtualprotect)(lpaddress, dwsize, flnewprotect, lpfloldprotect)
    }

    pub unsafe fn CreateThread(
        &self,
        lpthreadattributes: Option<*const c_void>,
        dwstacksize: u32,
        lpstartaddress: *mut c_void,
        lpparameter: Option<*const c_void>,
        dwcreationflags: u32,
        lpthreadid: Option<*const u32>,
    ) -> isize {
        let lp_thread_attributes = match lpthreadattributes {
            None => null() as *const c_void,
            Some(x) => x,
        };
        let lp_parameter = match lpparameter {
            None => null() as *const c_void,
            Some(x) => x,
        };
        let lp_thread_id = match lpthreadid {
            None => null() as *const u32,
            Some(x) => x,
        };
        (self.createthread)(
            lp_thread_attributes,
            dwstacksize,
            lpstartaddress,
            lp_parameter,
            dwcreationflags,
            lp_thread_id,
        )
    }

    pub unsafe fn WaitForSingleObject(&self, hhandle: isize, dwmilliseconds: u32) -> () {
        (self.waitforsingleobject)(hhandle, dwmilliseconds)
    }
}
