#![allow(nonstandard_style)]
// Rust imports
use crate::util::function_table::{export_dll, get_function_pointer};
use crate::util::helpers::*;
use crate::util::pe_headers::PeHeader;
use core::ffi::c_void;
use std::ffi::{CStr, CString};
use std::mem::transmute;
use std::ptr::{null, null_mut};

// Windows struct imports
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Kernel::CSTRING;
use windows::Win32::System::Threading::{
    LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, STARTUPINFOEXA,
};
// Defines for process creation flags, probably move these to a
// more abstracted file in ../execution/ or something
// @TODO, use the windows crate's repr c structs as arguments where they are needed. Use the
// implementation of CreateProcess below as a template

pub struct Ntdll {
    rtlallocateheap: unsafe extern "C" fn(
        *const c_void, // PVOID HeapHandle
        u32,           // DWORD dwFlags
        u32,           // SIZE_T dwBytes (just a dword cuh)
    ) -> *const c_void,
    rtlcreateheap: unsafe extern "C" fn(
        u32,           // ULONG flags
        *const c_void, // PVOID heapbase [Optional]
        u32,           // SIZE_T ReserveSize [Optional]
        u32,           // SIZE_T CommitSize [Optional]
        *const c_void, // PVOID Lock [Optional]
        *const c_void, // PRTL_HEAP_PARAMETERS Parameters [Optional]
    ) -> *const c_void, //HANDLE,
}

impl Ntdll {
    pub unsafe fn parse(process_header: &PeHeader) -> Ntdll {
        let dll = process_header
            .dll_map
            .get("ntdll.dll")
            .expect("No ntdll imported in header.");
        let function_table = export_dll(*dll);

        let rtlallocateheap = transmute(get_function_pointer(&function_table, "RtlAllocateHeap"));
        let rtlcreateheap = transmute(get_function_pointer(&function_table, "RtlCreateHeap"));
        Ntdll {
            rtlallocateheap,
            rtlcreateheap,
        }
    }

    // idk if this works TODO fix
    pub unsafe fn RtlAllocateHeap(
        &self,
        heaphandle: *const c_void,
        heapflags: u32,
        size: u32,
    ) -> *const c_void {
        let hHeap = heaphandle;
        dbg!(hHeap);
        let dwFlags = heapflags;
        dbg!(dwFlags);
        let dwBytes = size;
        dbg!(dwBytes);
        (self.rtlallocateheap)(hHeap, dwFlags, dwBytes)
    }
    // idk if this works TODO fix
    pub unsafe fn RtlCreateHeap(
        &self,
        flags: u32,
        basepointer: Option<*const c_void>,
        reservesize: Option<u32>,
        commitsize: Option<u32>,
        lock: Option<*const c_void>,
        parameters: Option<*const c_void>,
    ) -> *const c_void {
        let Flags = flags;
        let HeapBase = match basepointer {
            None => null() as *const c_void,
            Some(x) => x,
        };
        let ReserveSize = match reservesize {
            None => 0,
            Some(x) => x,
        };
        let CommitSize = match commitsize {
            None => 0,
            Some(x) => x,
        };
        let Lock = match lock {
            None => null() as *const c_void,
            Some(x) => x,
        };
        let Parameters = match parameters {
            None => null() as *const c_void,
            Some(x) => x,
        };
        dbg!(Flags, HeapBase, ReserveSize, CommitSize, Lock, Parameters);
        (self.rtlcreateheap)(Flags, HeapBase, ReserveSize, CommitSize, Lock, Parameters)
    }
}
