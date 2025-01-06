#![allow(non_camel_case_types)]


use std::ffi::{c_char, c_float, c_int, c_long, c_uchar, c_uint, c_ulong, c_ushort, c_void};

pub type ULONG = c_ulong;
pub type PULONG = *mut ULONG;
pub type USHORT = c_ushort;
pub type PUSHORT = *mut USHORT;
pub type UCHAR = c_uchar;
pub type PUCHAR = *mut UCHAR;
pub type PSZ = *mut c_char;
pub const MAX_PATH: usize = 260;
pub const FALSE: BOOL = 0;
pub const TRUE: BOOL = 1;
pub type DWORD = c_ulong;
pub type BOOL = c_int;
pub type BYTE = c_uchar;
pub type WORD = c_ushort;
pub type FLOAT = c_float;
pub type PFLOAT = *mut FLOAT;
pub type PBOOL = *mut BOOL;
pub type LPBOOL = *mut BOOL;
pub type PBYTE = *mut BYTE;
pub type LPBYTE = *mut BYTE;
pub type PINT = *mut c_int;
pub type LPINT = *mut c_int;
pub type PWORD = *mut WORD;
pub type LPWORD = *mut WORD;
pub type LPLONG = *mut c_long;
pub type PDWORD = *mut DWORD;
pub type LPDWORD = *mut DWORD;
pub type LPVOID = *mut c_void;
pub type PVOID = *mut c_void;

pub type LPCVOID = *const c_void;
pub type INT = c_int;
pub type UINT = c_uint;
pub type PUINT = *mut c_uint;
pub type LONG = c_long;
pub type SIZE_T = ULONG_PTR;


pub type INT_PTR = isize;
pub type PINT_PTR = *mut isize;
pub type UINT_PTR = usize;
pub type PUINT_PTR = *mut usize;
pub type LONG_PTR = isize;
pub type PLONG_PTR = *mut isize;
pub type ULONG_PTR = usize;
pub type PULONG_PTR = *mut usize;
pub type SHANDLE_PTR = isize;
pub type HANDLE_PTR = usize;