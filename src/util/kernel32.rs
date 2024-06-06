#![allow(nonstandard_style)]
// Rust imports
use crate::util::function_table::{export_dll, get_function_pointer};
use crate::util::pe_headers::PeHeader;
use core::ffi::c_void;
use std::ffi::CString;
use std::mem::transmute;
use std::ptr::{null, null_mut};

// Windows struct imports
use windows::Win32::Security::{SECURITY_ATTRIBUTES};
use windows::Win32::System::Threading::{STARTUPINFOA, PROCESS_INFORMATION};

// @TODO, use the windows crate's repr c structs as arguments where they are needed. Use the 
// implementation of CreateProcess below as a template

pub struct Kernel32 {
    virtualalloc: unsafe extern "C" fn(*mut c_void, usize, u32, u32) -> *mut c_void,
    virtualprotect: unsafe extern "C" fn(*const c_void, usize, u32, *mut u32) -> (),
    // @TODO implement windows structs for these random fuckoff fields, like SECURITY_ATTRIBUTES
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


    createprocess: unsafe extern "C" fn(
        *const c_void, // LPCSTR lpApplicationName
        *mut c_void, // LPSTR lpCommandLine [in, out]
        *const SECURITY_ATTRIBUTES, // LPSECURITY_ATTRIBUTES lpProcessAttributes
        *const SECURITY_ATTRIBUTES, // LPSECURITY_ATTRIBUTES lpThreadAttributes
        bool, // bool bInheritHandles (just google it dude), prolly set true
        u32, // DWORD dwCreationflags
        *const c_void, // LPVOID lpEnvironment
        *const c_void, //LPCSTR lpCurrentDirectory
        *const STARTUPINFOA, //LPSTARTUPINFOA lpStartupInfo
        *mut PROCESS_INFORMATION, // LPROCESS_INFORMATION lpProcessInformation [out]

    ) -> (),

    // isize is a HANDLE, u32 is time (use the INFINITE constant)
    waitforsingleobject: unsafe extern "C" fn(isize, u32) -> (),

    // There's probably a better way to do this but this needs to
    // be a pointer to a null terminated C String and this is what the
    // legitimate windows crate does.
    loadlibrarya: unsafe extern "C" fn(*const c_void) -> isize,
    // GetModuleHandle
    // GetProcAddress
    // ReadProcessMemory
    // WriteProcessMemory
}

impl Kernel32 {
    pub unsafe fn parse(process_header: PeHeader) -> Kernel32 {
        let dll = process_header
            .dll_map
            .get("kernel32.dll")
            .expect("No kernel32 imported in header.");
        let function_table = export_dll(*dll);

        let virtualalloc = transmute(get_function_pointer(&function_table, "VirtualAlloc"));

        let virtualprotect = transmute(get_function_pointer(&function_table, "VirtualProtect"));

        let createthread = transmute(get_function_pointer(&function_table, "CreateThread"));

        let createprocess = todo!();

        let waitforsingleobject =
            transmute(get_function_pointer(&function_table, "WaitForSingleObject"));

        let loadlibrarya = transmute(get_function_pointer(&function_table, "LoadLibraryA"));


        Kernel32 {
            virtualalloc,
            virtualprotect,
            createthread,
            createprocess,
            waitforsingleobject,
            loadlibrarya,
        }
    }

    pub unsafe fn VirtualAlloc(
        &self,
        lpaddress: Option<*mut c_void>,
        dwsize: usize,
        flallocationtype: u32,
        flprotect: u32,
    ) -> *mut c_void {
        let lp_address = match lpaddress {
            None => null_mut() as *mut c_void,
            Some(x) => x,
        };
        (self.virtualalloc)(lp_address, dwsize, flallocationtype, flprotect)
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

    pub unsafe fn LoadLibraryA(&self, library: &str) -> isize {
        // TODO remove this unwrap, retard, but also
        // this creates a null terminated string from the library string
        // turns it into bytes and returns a *const u8 (pointer) to the byte
        // array. It is retarded, but I think it will work.
        dbg!(CString::new(library)).unwrap();
        let dll =
            CString::new(library).unwrap().to_bytes_with_nul() as *const [u8] as *const c_void;
        dbg!(dll);
        (self.loadlibrarya)(dll)
    }
}
