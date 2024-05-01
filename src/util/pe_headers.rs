use std::os::raw::c_void;
use core::arch::asm;
use windows::Win32::System::WindowsProgramming::LDR_DATA_TABLE_ENTRY;
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER64, IMAGE_DATA_DIRECTORY};
use windows::Win32::System::Threading::{TEB, PEB, PEB_LDR_DATA};
use windows::Win32::System::Kernel::LIST_ENTRY;


// This is the dos image header magic number.
const DOS_HEADER_MAGIC_NUMBER:u32 = 0x4D5A;
// The NT image header magic number, but since it is a dword it is padded by two null bytes.
const NT_HEADER_MAGIC_NUMBER:u32 = 0x50450000;

//Data directory array constants
const EXPORT:usize         = 0;  
const IMPORT:usize         = 1; 
const RESOURCE:usize       = 2; 
const EXCEPTION:usize      = 3;
const SECURITY:usize       = 4;
const BASERELOC:usize      = 5;
const DEBUG:usize          = 6;
const ARCHITECTURE:usize   = 7;
const GLOBALPTR:usize      = 8;
const TLS:usize            = 9;
const LOAD_CONFIG:usize    = 10;
const BOUND_IMPORT:usize   = 11;
const IAT:usize            = 12;
const DELAY_IMPORT:usize   = 13;
const COM_DESCRIPTOR:usize = 14;


pub struct PeHeader {
    pub base_address: *const c_void,
    pub sections: u16,
    pub symbols:u32,
    pub symbol_table: *const c_void,
    pub text_size: u32,
    pub text_address: *const c_void,
}

impl PeHeader {

    //@TODO Hey retard, you should probably split this into multiple private functions because this
    //is getting a little crazy. But hey, I'm not your dad, dude. It's your life. You're still
    //retarded though.
    pub unsafe fn parse() -> PeHeader {
      
       
        // We now begin pebbing and tebbing all over the place. 

        // Yeah I know I just invalidated the teb step below but I really don't want to do retarded
        // ass .offset shit if I can just cast directly into a struct tee bee haych. Anyway this
        // grabs an undocumented field which points us at the base address for the image.
        let peb_address:*const c_void;
        asm!("mov {}, gs:0x60", out(reg) peb_address);
        let ppbase_address = peb_address.offset(0x10);
        let pbase_address = ppbase_address as *const u64;
        let base_address = *pbase_address as *const c_void;
        
        dbg!(base_address);

        // Fills the relevant header structs with data now that we have the base address
        let pimage_dos_header: *const IMAGE_DOS_HEADER = base_address as *const IMAGE_DOS_HEADER;
        let image_dos_header:IMAGE_DOS_HEADER = *pimage_dos_header;
       
        // Verifies that we have the correct magic number. If this fails, I would put money on 
        // endian-ness issues.
        assert!(u32::from(image_dos_header.e_magic.to_be()) == DOS_HEADER_MAGIC_NUMBER);        
        
        // Bunch of casts, grabbing offsets from fields in these structs and then casting to more
        // structs.
        let nt_header_offset:isize = image_dos_header.e_lfanew as isize;
        let nt_header_address:*const c_void = base_address.offset(nt_header_offset);
        
        let pnt_header: *const IMAGE_NT_HEADERS64 = nt_header_address as *const IMAGE_NT_HEADERS64;
        let nt_header:IMAGE_NT_HEADERS64 = *pnt_header;
        
        assert!(nt_header.Signature.to_be() == NT_HEADER_MAGIC_NUMBER);
        
        let image_file_header:IMAGE_FILE_HEADER = nt_header.FileHeader;
        let optional_header:IMAGE_OPTIONAL_HEADER64 = nt_header.OptionalHeader;
        
        let sections:u16 = image_file_header.NumberOfSections;

        let symbols:u32 = image_file_header.NumberOfSymbols;
        let symbol_table:*const c_void = image_file_header.PointerToSymbolTable as *const c_void;
        
        let text_size:u32 = optional_header.SizeOfCode;
        let text_address:*const c_void = base_address.offset(optional_header.BaseOfCode as isize);

        // Now we move onto finding our own import table.

        // Moves the value @ gs:0x30 into teb_address. That value points to the teb.
        let teb_address:*const c_void;
        asm!("mov {}, gs:0x30", out(reg) teb_address);

        let pteb:*const TEB = teb_address as *const TEB;
        let teb:TEB = *pteb;
        let peb:PEB = *teb.ProcessEnvironmentBlock;
        let loader_data:PEB_LDR_DATA = *peb.Ldr;
        let module_list:LIST_ENTRY = loader_data.InMemoryOrderModuleList;

        // I know that this is super confusing looking, so I am going to explain it line by line.
        // The struct LDR_DATA_TABLE_ENTRY contains within it a struct called LIST_ENTRY, that 
        // contains two *mut LIST_ENTRY inside of it. We are looping through this doubly linked
        // list to extract information about imported dlls.
        // 
        // ----
        // Sets a mutable variable to use to loop through that is set to a dereferenced pointer to
        // the first link in the list, stored inside of OUR module (module_list).
        let mut plink = *module_list.Flink;
        // We are setting a guard for the while loop by duplicating our first variable.
        let guard = plink;
        
        // While the current link we are observing's FORWARD list item is not equal to our first
        // link's REAR item.
        while *plink.Flink != *guard.Blink {
            // Save a copy of our current LIST_ENTRY.
            let link = plink;
            // Dereference our current LIST_ENTRY's next item and cast it to the struct we want,
            // LDR_DATA_TABLE_ENTRY.
            let pentry = plink.Flink as *const LDR_DATA_TABLE_ENTRY;
            let entry = *pentry;
            dbg!(entry.FullDllName.Buffer.to_string().unwrap());
            dbg!(entry.DllBase);
            // Set our next item to iterate through to the pointer containing struct of the object
            // we just observed.
            plink = *link.Flink;
        }
        // I cannot find a better way to explain this, even to myself. Sorry!

        PeHeader{
            base_address,
            sections,
            symbols,
            symbol_table,
            text_size,
            text_address,
        }
    }

}

