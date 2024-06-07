use std::ffi::{CStr, CString};

// Simple helper functions for annoying string conversions. These are separate like this 
// to avoid lifetime issues.
pub fn convert_to_cstring(path:&str)->CString{
    CString::new(path).unwrap() 
}

pub fn convert_to_cstr(path:&CString)->&CStr{
    CStr::from_bytes_with_nul(path.to_bytes_with_nul()).unwrap()
}

