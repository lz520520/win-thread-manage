#![allow(non_snake_case)]

use std::arch::asm;
use std::ffi::{c_char, c_short, c_ulong, c_void,  CString};
use std::ptr::null_mut;
use std::{mem, slice};
use lazy_static::lazy_static;
use winapi::shared::minwindef::{FARPROC, HMODULE};
use windows::core::PCSTR;
use windows::Win32::Foundation::{BOOL,  UNICODE_STRING};
use windows::Win32::System::Diagnostics::Debug::{IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_HEADERS64};
use windows::Win32::System::Kernel::LIST_ENTRY;
use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY};
const CRC_KERNEL32: u32 =  0x6AE69F02;
const CRC_GetProcAddress: u32 = 0xC97C1FFF;
const CRC_LoadLibraryA: u32 = 0x3FC1BD8D;
const CRC_FreeLibrary: u32 =  0xDA68238F;
#[allow(non_snake_case)]
#[derive(Default)]
pub struct  MiniIAT {
    pub MyLoadLibraryA: Option<unsafe extern "system" fn(lpFileName: PCSTR) -> HMODULE>,
    pub MyGetProcAddress: Option<unsafe extern "system" fn (hmodule : HMODULE, lpprocname : PCSTR) -> FARPROC>,
    pub MyFreeLibrary: Option<unsafe extern "system" fn (hmodule : HMODULE) -> BOOL>,

}

lazy_static! {
    pub static ref GLOBAL_IAT: MiniIAT = {
        unsafe {
            let base = get_module_by_checksum(CRC_KERNEL32).unwrap();
            let mut iat = MiniIAT::default();
            iat.MyLoadLibraryA = std::mem::transmute(get_func_by_checksum( base, CRC_LoadLibraryA));
            iat.MyGetProcAddress = std::mem::transmute(get_func_by_checksum(base, CRC_GetProcAddress));
            iat.MyFreeLibrary = std::mem::transmute(get_func_by_checksum(base, CRC_FreeLibrary));
            iat
        }


    };
}


pub fn calc_checksum<T>(curr_name: *const T, case_sensitive: bool) -> u32
where
    T: Into<u32> + Copy,
{
    let mut crc: u32 = 0xFFFFFFFF;

    unsafe {
        let mut curr_ptr = curr_name;
        while !curr_ptr.is_null() && (*curr_ptr).into() != 0 {
            let mut  ch = (*curr_ptr).into() as u8;

            ch = if !case_sensitive {
                if ch <= b'Z' && ch >= b'A' {
                    ch - b'A' + b'a'
                } else {
                    ch
                }
            } else {
                ch
            };

            for _ in 0..8 {
                let b = (ch as u32 ^ crc) & 1;
                crc >>= 1;
                if b != 0 {
                    crc ^= 0xEDB88320;
                }
                ch >>= 1;
            }

            curr_ptr = curr_ptr.add(1); // 移动到下一个字符
        }
    }

    !crc
}


fn c_to_rust_string(c_str: *const c_char) -> String{
    unsafe {
        std::ffi::CStr::from_ptr(c_str).to_string_lossy().into_owned()
    }
}
fn memory_copy(destination_ptr: *mut u8, source_ptr: *const u8, number_of_bytes: usize) {
    unsafe {
        for index in 0..number_of_bytes {
            *destination_ptr.add(index) = *source_ptr.add(index);
        }
    }
}

#[repr(C)]
#[allow(non_snake_case,non_camel_case_types)]
pub union LDR_DATA_TABLE_ENTRY_u1 {
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub InProgressLinks: LIST_ENTRY,
}
#[repr(C)]
#[allow(non_snake_case,non_camel_case_types)]
pub struct LDR_DATA_TABLE_ENTRY1 {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub u1: LDR_DATA_TABLE_ENTRY_u1,
    pub DllBase: *mut c_void,
    pub EntryPoint: *mut c_void,
    pub SizeOfImage: c_ulong,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    pub Flags: c_ulong,
    pub LoadCount: c_short,
    pub TlsIndex: c_short,
    pub SectionHandle: c_ulong,
    pub CheckSum: c_ulong,
    pub TimeDateStamp: c_ulong,
}

pub struct ModuleHandle {
    pub handle: HMODULE,
    pub use_load: bool,
}
#[cfg(target_arch = "x86_64")]
unsafe fn get_peb() -> *mut windows::Win32::System::Threading::PEB {
    let mut peb: *mut windows::Win32::System::Threading::PEB = std::ptr::null_mut();
    asm!("mov {}, gs:[0x60]", out(reg) peb);
    peb
}

#[cfg(target_arch = "x86")]
unsafe fn get_peb() -> *mut windows::Win32::System::Threading::PEB {
    let mut peb: *mut windows::Win32::System::Threading::PEB = std::ptr::null_mut();
    asm!("mov {}, fs:[0x30]", out(reg) peb);
    peb
}

pub fn unicode_string_to_rust_string(unicode_string: &UNICODE_STRING) -> String {
    let transate  = unsafe {slice::from_raw_parts(unicode_string.Buffer.as_ptr(), unicode_string.Length as usize)};
    array_to_string_utf16( transate)
}
pub fn array_to_string_utf16(buffer: &[u16]) -> String {
    let mut string: Vec<u16> = Vec::new();
    for char in buffer.to_vec() {
        if char == 0 {
            break;
        }
        string.push(char);
    }
    String::from_utf16_lossy(&string)
}
fn get_module_by_checksum(checksum: u32) -> Option<HMODULE> {
    // Retrieve the PEB
    unsafe {
        let peb = get_peb();

        if peb.is_null() {
            return None;
        }

        let ldr = (*peb).Ldr;
        if ldr.is_null() {
            return None;
        }
        let mut current = (*ldr).InMemoryOrderModuleList.Flink;
        let head = &(*ldr).InMemoryOrderModuleList as *const _ as *mut _;
        while head != current {
            // 这里由于InMemoryOrderLinks在LDR_DATA_TABLE_ENTRY1第二项，偏移需要往前移才能对齐
            let entry = (current as usize -  mem::size_of::<LIST_ENTRY>()) as *mut LDR_DATA_TABLE_ENTRY1;
            if entry.is_null()  || (*entry).DllBase.is_null() {
                break;
            }
            let curr_name = (*entry).BaseDllName;

            let curr_crc = calc_checksum(curr_name.Buffer.as_ptr(), false);
            if curr_crc == checksum {
                return Some((*entry).DllBase as HMODULE);
            }
            current = (*current).Flink;

        }
    }

    None
}

pub fn my_load_library(library_name: *const u8) -> Option<ModuleHandle> {
    if let Some(handle) = get_module_by_checksum(calc_checksum(library_name, false)) {
        Some(ModuleHandle{
            handle,
            use_load: false,
        })
    } else {
        unsafe {
            if let Some(func) = GLOBAL_IAT.MyLoadLibraryA {
                let handle = func(PCSTR::from_raw(library_name));
                if handle.is_null() {
                     None
                } else {
                    Some(ModuleHandle{
                        handle,
                        use_load: true,
                    })
                }
            } else {
                None
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub type IMAGE_NT_HEADER = IMAGE_NT_HEADERS64;
#[cfg(target_arch = "x86")]
pub type IMAGE_NT_HEADER = IMAGE_NT_HEADERS32;


pub  fn get_func_by_checksum(
    module: HMODULE,
    checksum: u32,
) -> FARPROC {
    unsafe {
        let module_base = module as usize;
        let dos_header = module_base as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            return null_mut();
        }
        let nt_headers = (module_base + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADER;
        let exports_dir = &(*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize];

        if exports_dir.VirtualAddress == 0 {
            return null_mut();
        }

        let export_base = module_base + exports_dir.VirtualAddress as usize;
        let export_directory = export_base as *const IMAGE_EXPORT_DIRECTORY;
        let names_count = (*export_directory).NumberOfNames as usize;

        let funcs_list_rva = (module_base + (*export_directory).AddressOfFunctions as usize) as *const u32;
        let func_names_list_rva = (module_base + (*export_directory).AddressOfNames as usize) as *const u32;
        let names_ords_list_rva = (module_base + (*export_directory).AddressOfNameOrdinals as usize) as *const u16;

        let mut proc: *mut c_void = null_mut();
        let mut proc_name: *const u8 = null_mut();

        for i in 0..names_count {
            let name_rva = *func_names_list_rva.add(i);
            let name_index = *names_ords_list_rva.add(i);
            let func_rva = *funcs_list_rva.add(name_index as usize);

            proc_name = (module_base + name_rva as usize) as *const u8;

            if (proc_name as u32 & 0xFFFF_0000) != 0 {
                let curr_crc = calc_checksum(proc_name, true);
                if curr_crc == checksum {
                    proc = (module_base + func_rva as usize) as *mut c_void;
                    break;
                }
            }
        }

        let exp_end = export_base + (*exports_dir).Size as usize;
        if (proc as usize) < export_base || (proc as usize) > exp_end {
            return std::mem::transmute(proc);
        }
        if let Some(func) = GLOBAL_IAT.MyGetProcAddress {
            func(module as _, PCSTR::from_raw(proc_name))
        } else {
            null_mut()
        }
    }
}


pub  fn my_get_proc_address(
    module: HMODULE,
    proc_name: *const u8,
) -> FARPROC {

    unsafe {
        let module_base = module as usize;
        let dos_header = module_base as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            return null_mut();
        }
        let nt_headers = (module_base + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADER;
        let exports_dir = &(*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize];

        if exports_dir.VirtualAddress == 0 {
            return null_mut();
        }

        let export_base = module_base + exports_dir.VirtualAddress as usize;
        let export_directory = export_base as *const IMAGE_EXPORT_DIRECTORY;
        let names_count = (*export_directory).NumberOfNames as usize;

        let funcs_list_rva = (module_base + (*export_directory).AddressOfFunctions as usize) as *const u32;
        let func_names_list_rva = (module_base + (*export_directory).AddressOfNames as usize) as *const u32;
        let names_ords_list_rva = (module_base + (*export_directory).AddressOfNameOrdinals as usize) as *const u16;

        let mut proc: *mut c_void = null_mut();
        let dw_name = proc_name as u32;

        if (dw_name & 0xFFFF_0000) != 0 {
            let checksum = calc_checksum(proc_name, true);
            // println!("111: {}",r_name );
            for i in 0..names_count {
                let name_rva = *func_names_list_rva.add(i);
                let name_index = *names_ords_list_rva.add(i);
                let func_rva = *funcs_list_rva.add(name_index as usize);

                let curr_name = (module_base + name_rva as usize) as *const u8;

                if (curr_name as u32 & 0xFFFF_0000) != 0 {
                    let curr_crc = calc_checksum(curr_name, true);
                    if curr_crc == checksum {
                        proc = (module_base + func_rva as usize) as *mut c_void;
                        break;
                    }
                }
            }

        } else {
            let dw_base = (*export_directory).Base;
            if dw_name >= dw_base && dw_name <= dw_base + (*export_directory).NumberOfFunctions - 1{
                let func_rva = *funcs_list_rva.add((dw_name - dw_base) as usize);
                proc = (module_base + func_rva as usize) as *mut c_void;

            }
        }

        let export_end = export_base + (*exports_dir).Size as usize;
        if (proc as usize) < export_base || (proc as usize) > export_end {
            return std::mem::transmute(proc);
        }
        if let Some(func) = GLOBAL_IAT.MyGetProcAddress {
            func(module as _, PCSTR::from_raw(proc_name))
        } else {
            null_mut()
        }
    }
}
#[test]
fn get_module_by_checksum_test() {
    let c =CString::new("ntdll.dll").unwrap();
    unsafe {
        (GLOBAL_IAT.MyLoadLibraryA.unwrap())(PCSTR::from_raw(c.as_ptr() as *const _));
    }
}

#[test]
fn test_checksum() {
    // let sum = calc_checksum("GetProcAddress\0".as_ptr() ,true);
    // assert_eq!(sum, 0xC97C1FFF);

    let sum1 = calc_checksum("GetProcAddress\0".as_ptr() ,false);
    let sum2 = calc_checksum("GETProCAddress\0".as_ptr() ,false);
    assert_eq!(sum1, sum2);


    let sum = calc_checksum("LoadLibraryA\0".as_ptr() ,true);
    assert_eq!(sum, 0x3FC1BD8D);

    let sum = calc_checksum("FreeLibrary\0".as_ptr() ,true);
    assert_eq!(sum, 0xDA68238F);

    let sum = calc_checksum("VirtualProtect\0".as_ptr() ,true);
    assert_eq!(sum, 0x10066F2F);

    let sum = calc_checksum(b"CreateFileW\0".as_ptr() ,true);
    assert_eq!(sum, 0xA1EFE929);
    let sum = calc_checksum(b"GetFileSize\0".as_ptr() ,true);
    assert_eq!(sum, 0xA7FB4165);

    let sum = calc_checksum(b"VirtualAlloc\0".as_ptr() ,true);
    assert_eq!(sum, 0x9CE0D4A);

    let sum = calc_checksum(b"VirtualFree\0".as_ptr() ,true);
    assert_eq!(sum, 0xCD53F5DD);

    let sum = calc_checksum(b"ReadFile\0".as_ptr() ,true);
    assert_eq!(sum, 0x95C03D0);
}