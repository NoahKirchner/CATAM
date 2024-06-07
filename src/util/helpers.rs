use std::ffi::{CStr, CString};

#[macro_export]
macro_rules! pcstr {
    ($path:expr) => {
        let rawpath = CString::new($path).unwrap();
        let pathcstr = CStr::from_bytes_with_nul(rawpath.to_bytes_with_nul()).unwrap();
        pathcstr.as_ptr()
    };
}
