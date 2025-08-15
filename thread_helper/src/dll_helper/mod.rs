#![allow(dead_code)]

mod dll;
mod peb_lookup;
pub mod windef;

pub use dll::*;

use std::ffi::{c_char, OsStr};
use std::os::windows::ffi::OsStrExt;





fn c_to_rust_string(c_str: *const c_char) -> String{
    unsafe {
        std::ffi::CStr::from_ptr(c_str).to_string_lossy().into_owned()
    }
}
pub fn c_to_rust_string_form_bytes(c_bytes: &[i8]) -> CommonResult<String> {
    let valid_bytes: Vec<u8> = c_bytes.iter().map(|&x| x as u8).collect();
    Ok(std::ffi::CStr::from_bytes_until_nul(&valid_bytes)?.to_string_lossy().into_owned())
}


pub fn get_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}
