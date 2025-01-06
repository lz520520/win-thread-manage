#![allow(dead_code)]

mod dll;
mod peb_lookup;
pub mod windef;

pub use dll::*;

use std::ffi::{ OsStr};
use std::os::windows::ffi::OsStrExt;








pub fn get_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}
