use windows::Win32::System::Threading::GetCurrentProcess;

pub struct DOSHeader {}

pub struct NTHeader {}

pub struct ProcessHeaders {
    dos_header: DOSHeader,
    nt_header: NTHeader,
}
