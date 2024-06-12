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
        *const c_void, // LPSTR lpCommandLine [in, out]
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

    createfile: unsafe extern "C" fn(
        *const c_void, // LPCSTR lpFileName
        u32,           // DWORD dwDesiredAccess
        u32,           // DWORD dwShareMode
        *const c_void, // LPSECURITYATTRIBUTES lpSecurityAttributes [Optional]
        u32,           // DWORD dwCreationDisposition
        u32,           // DWORD dwFlagsAndAttributes
        isize,         // HANDLE hTemplateFile [Optional] (Pass zero for null)
    ) -> isize, // HANDLE

    getfilesize: unsafe extern "C" fn(
        isize, // HANDLE hfile (Handle to file to read returned by CreateFile)
        *const c_void, // LPDWORD lpFileSizeHigh [Out, Optional] a pointer to a return variable for
               // a high order dword, not necessary
    ) -> u32,

    readfile: unsafe extern "C" fn(
        isize,       // HANDLE hFile
        *mut c_void, // LPVOID lpBuffer [out]
        u32,         // DWORD nNumberOfBytesToRead
        *mut c_void, // LPDWORD lpNumberOfBytesRead [out, optional], how fucking retarded is this
        *mut c_void, //LPOVERLAPPED lpOverLapped [in, out, optional]
    ),

    getprocessheap: unsafe extern "C" fn() -> isize, // handle

    heapcreate: unsafe extern "C" fn(
        u32, // DWORD flOptions
        u32, // SIZE_T dwInitialSize
        u32, // SIZE_T dwMaximumSize (set to 0 for infinite size)
    ) -> isize, //handle

    // doesnt work TODO fix or dont idc
    heapalloc: *const unsafe extern "C" fn(
        isize, // HANDLE hHeap
        u32,   // DWORD dwFlags
        u32,   // SIZE_T dwBytes (just a dword cuh)
    ) -> *const c_void,

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
    pub unsafe fn parse(process_header: &PeHeader) -> Kernel32 {
        let dll = process_header
            .dll_map
            .get("kernel32.dll")
            .expect("No kernel32 imported in header.");
        let function_table = export_dll(*dll);

        let virtualalloc = transmute(get_function_pointer(&function_table, "VirtualAlloc"));

        let virtualprotect = transmute(get_function_pointer(&function_table, "VirtualProtect"));

        let createthread = transmute(get_function_pointer(&function_table, "CreateThread"));

        let createprocess = transmute(get_function_pointer(&function_table, "CreateProcessA"));

        //TODO this doesnt work idiot
        let initializeprocthreadattributelist = transmute(get_function_pointer(
            &function_table,
            "InitializeProcThreadAttributeList",
        ));
        dbg!(initializeprocthreadattributelist);

        let createfile = transmute(get_function_pointer(&function_table, "CreateFileA"));

        let getfilesize = transmute(get_function_pointer(&function_table, "GetFileSize"));

        let readfile = transmute(get_function_pointer(&function_table, "ReadFile"));

        let getprocessheap = transmute(get_function_pointer(&function_table, "GetProcessHeap"));

        let heapcreate = transmute(get_function_pointer(&function_table, "HeapCreate"));

        let heapalloc = transmute(get_function_pointer(&function_table, "HeapAlloc"));
        dbg!(heapalloc);

        let waitforsingleobject =
            transmute(get_function_pointer(&function_table, "WaitForSingleObject"));

        let loadlibrarya = transmute(get_function_pointer(&function_table, "LoadLibraryA"));

        Kernel32 {
            virtualalloc,
            virtualprotect,
            createthread,
            createprocess,
            initializeprocthreadattributelist,
            createfile,
            getfilesize,
            readfile,
            getprocessheap,
            heapcreate,
            heapalloc,
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
    //@TODO this doesn't work sorry
    pub unsafe fn InitializeProcThreadAttributeList(
        &self,
        attributecount: u32,
    ) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        let mut size: usize = 0;
        dbg!(size);
        let mut lpsize = &mut size as *mut usize;
        dbg!(lpsize);
        dbg!((self.initializeprocthreadattributelist)(
            core::ptr::null_mut(),
            attributecount.clone(),
            0,
            lpsize
        ));
        dbg!(GetLastError());
        dbg!(size);
        let mut lpattributelist = LPPROC_THREAD_ATTRIBUTE_LIST::default();
        dbg!(lpattributelist);
        (self.initializeprocthreadattributelist)(lpattributelist.0, attributecount, 0, lpsize);
        dbg!(lpattributelist);
        lpattributelist
    }

    pub unsafe fn CreateFile(
        &self,
        filename: &str,
        access: u32,
        sharemode: u32,
        securityattributes: Option<SECURITY_ATTRIBUTES>,
        creationdisposition: u32,
        flags: u32,
        templatefile: Option<isize>,
    ) -> isize {
        let cstringfilename = convert_to_cstring(filename);
        let filename = convert_to_cstr(&cstringfilename);
        let lpFileName = filename.as_ptr() as *const c_void;
        let dwDesiredAccess = access;
        let dwShareMode = sharemode;

        let lpSecurityAttributes = match securityattributes {
            None => null() as *const c_void,
            Some(x) => &x as *const _ as *const c_void,
        };

        let dwCreationDisposition = creationdisposition;
        let dwFlagsAndAttributes = flags;

        let hTemplateFile = match templatefile {
            None => 0 as isize,
            Some(x) => x,
        };

        (self.createfile)(
            lpFileName,
            dwDesiredAccess,
            dwShareMode,
            lpSecurityAttributes,
            dwCreationDisposition,
            dwFlagsAndAttributes,
            hTemplateFile,
        )
    }

    pub unsafe fn GetFileSize(
        &self,
        filehandle: isize,
        filesizehigh: Option<*const c_void>,
    ) -> u32 {
        let hFile = filehandle;
        let lpFileSizeHigh = match filesizehigh {
            None => null() as *const c_void,
            Some(x) => x,
        };
        (self.getfilesize)(hFile, lpFileSizeHigh)
    }

    pub unsafe fn ReadFile(
        &self,
        hFile: isize,
        lpBuffer: *mut c_void,
        nNumberOfBytesToRead: u32,
        bytesread: Option<*mut c_void>,
        overlapped: Option<*mut c_void>,
    ) {
        let lpNumberOfBytesRead = match bytesread {
            None => null_mut() as *mut c_void,
            Some(x) => x,
        };
        let lpOverlapped = match overlapped {
            None => null_mut() as *mut c_void,
            Some(x) => x,
        };
        (self.readfile)(
            hFile,
            lpBuffer,
            nNumberOfBytesToRead,
            lpNumberOfBytesRead,
            lpOverlapped,
        )
    }

    pub unsafe fn GetProcessHeap(&self) -> isize {
        (self.getprocessheap)()
    }

    pub unsafe fn HeapCreate(&self, flags: u32, startsize: u32, maxsize: u32) -> isize {
        let flOptions = flags;
        let dwInitialSize = startsize;
        let dwMaximumSize = maxsize;
        (self.heapcreate)(flOptions, dwInitialSize, dwMaximumSize)
    }

    pub unsafe fn HeapAlloc(&self, heaphandle: isize, heapflags: u32, size: u32) -> *const c_void {
        let hHeap = heaphandle;
        let dwFlags = heapflags;
        let dwBytes = size;
        (*self.heapalloc)(hHeap, dwFlags, dwBytes)
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
