use windows::core::PSTR;
use windows::Win32::System::Memory::{
    VirtualAlloc, PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE,
};
use windows::Win32::System::WindowsProgramming::GetUserNameA;
unsafe fn get_username() -> String {
    let mut size: u32 = 128;
    let psize: *mut u32 = &mut size;
    let mut user = Vec::with_capacity(size as usize);
    let lpbuffer = PSTR(user.as_mut_ptr());
    GetUserNameA(lpbuffer, psize).unwrap();
    user.set_len(size as usize);

    String::from_utf8(user).unwrap()
}

unsafe fn run_shellcode(shellcode: Vec<u8>) -> () {
    let dwsize = shellcode.len();
    let fiAllocationType = VIRTUAL_ALLOCATION_TYPE(0x3000);
    let fiProtect = PAGE_PROTECTION_FLAGS(0x40);
    let pmem = VirtualAlloc(None, dwsize, fiAllocationType, fiProtect);
}

fn main() {
    let testme: String;
    unsafe {
        testme = get_username();
    }
    println!("{}", testme);
}
