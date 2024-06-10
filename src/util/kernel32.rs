#![allow(nonstandard_style)]
// Rust imports
use crate::util::function_table::{export_dll, get_function_pointer};
use crate::util::pe_headers::PeHeader;
use crate::util::helpers::*;
use core::ffi::c_void;
use std::ffi::{CStr, CString};
use std::mem::transmute;
use std::ptr::{null, null_mut};


// Windows struct imports
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Kernel::CSTRING;
use windows::Win32::System::Threading::{PROCESS_INFORMATION, STARTUPINFOEXA, LPPROC_THREAD_ATTRIBUTE_LIST};
use windows::Win32::Foundation::GetLastError;
// Defines for process creation flags, probably move these to a
// more abstracted file in ../execution/ or something
pub const CREATE_NO_WINDOW: u32 = 0x08000000;
pub const CREATE_SUSPENDED: u32 = 0x00000004;
pub const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x00080000;

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
        *const c_void,   // LPSTR lpCommandLine [in, out]
        *const c_void, // LPSECURITY_ATTRIBUTES lpProcessAttributes
        *const c_void, // LPSECURITY_ATTRIBUTES lpThreadAttributes
        bool,          // bool bInheritHandles (just google it dude), prolly set true
        u32,           // DWORD dwCreationflags
        *const c_void, // LPVOID lpEnvironment
        *const c_void, //LPCSTR lpCurrentDirectory
        *const c_void, //LPSTARTUPINFOA lpStartupInfo
        *mut c_void,   // LPROCESS_INFORMATION lpProcessInformation [out]
    ) -> (),

    initializeprocthreadattributelist: unsafe extern "C" fn(
        *mut c_void,
        u32,
        u32, //This must be 0
        *mut usize,
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

        let createprocess = transmute(get_function_pointer(&function_table, "CreateProcessA"));

        let initializeprocthreadattributelist = transmute(get_function_pointer(&function_table, "InitializeProcThreadAttributeList"));
        dbg!(initializeprocthreadattributelist);

        let waitforsingleobject =
            transmute(get_function_pointer(&function_table, "WaitForSingleObject"));

        let loadlibrarya = transmute(get_function_pointer(&function_table, "LoadLibraryA"));

        Kernel32 {
            virtualalloc,
            virtualprotect,
            createthread,
            createprocess,
            initializeprocthreadattributelist,
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

    //@TODO needs the process creation flags implemented somewhere (probably at the top of this
    //file)
    pub unsafe fn CreateProcess(
        &self,
        exepath: &str,
        commandline: &str,
        procattributes: Option<SECURITY_ATTRIBUTES>,
        threadattributes: Option<SECURITY_ATTRIBUTES>,
        inherithandles: bool,
        creationflags: u32,
        environment: Option<*const c_void>,
        directory: Option<&str>,
        startupinfo: STARTUPINFOEXA,
    ) -> PROCESS_INFORMATION {
        let mut processinfo = PROCESS_INFORMATION::default();
       
        // I know that these are terrible implementations that should be handled 
        // with a match statement or something because they are technically optional, 
        // but I swear to God using ANY kind of error checking here passes an invalid string 
        // somehow @TODO figure out what the fuck happenin. I think it's a Windows API issue.
        let cstringpath = convert_to_cstring(exepath);
        let path = convert_to_cstr(&cstringpath);
        let lpApplicationName = path.as_ptr() as *const c_void;

        let cstrcmd = convert_to_cstring(commandline);
        let cmd = convert_to_cstr(&cstrcmd);
        let lpCommandLine = cmd.as_ptr() as *const c_void;

        // I do not understand the *const _ syntax but it works
        let lpProcessAttributes = match procattributes {
            None => null() as *const c_void,
            Some(x) => &x as *const _ as *const c_void,
        };
        let lpThreadAttributes = match threadattributes {
            None => null() as *const c_void,
            Some(x) => &x as *const _ as *const c_void,
        };

        let bInheritHandles = inherithandles;
        let dwCreationFlags = creationflags;
        let lpEnvironment = match environment {
            None => null() as *const c_void,
            Some(x) => x,
        };
        let lpCurrentDirectory = match directory {
            None => null() as *const c_void,
            Some(x) => CString::new(x).unwrap().to_bytes_with_nul() as *const [u8] as *const c_void,
        };
        let lpStartupInfo = &startupinfo as *const _ as *const c_void;
        let lpProcessInformation = &mut processinfo as *mut _ as *mut c_void;
        dbg!(
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation
        );
        (self.createprocess)(
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation,
        );
        processinfo
    }

    pub unsafe fn InitializeProcThreadAttributeList(&self, 
        attributecount:u32,
        )->LPPROC_THREAD_ATTRIBUTE_LIST {
        let mut size: usize = 0;
        dbg!(size);
        let mut lpsize = &mut size as *mut usize;
        dbg!(lpsize);
        dbg!((self.initializeprocthreadattributelist)(core::ptr::null_mut(), attributecount.clone(), 0, lpsize));
        dbg!(GetLastError());
        dbg!(size);
        let mut lpattributelist = LPPROC_THREAD_ATTRIBUTE_LIST::default();
        dbg!(lpattributelist);
        (self.initializeprocthreadattributelist)(lpattributelist.0, attributecount, 0, lpsize);
        dbg!(lpattributelist);
        lpattributelist
    }

    pub unsafe fn WaitForSingleObject(&self, hhandle: isize, dwmilliseconds: u32) -> () {
        (self.waitforsingleobject)(hhandle, dwmilliseconds)
    }

    pub unsafe fn LoadLibraryA(&self, library: &str) -> isize {
        // TODO remove this unwrap, retard, but also
        // this creates a null terminated string from the library string
        // turns it into bytes and returns a *const u8 (pointer) to the byte
        // array and then casts it as a const c_void because slices are not valid in
        // ffi
        dbg!(CString::new(library)).unwrap();
        let dll =
            CString::new(library).unwrap().to_bytes_with_nul() as *const [u8] as *const c_void;
        dbg!(dll);
        (self.loadlibrarya)(dll)
    }
}
