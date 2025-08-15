use windows::core::BOOL;
use windows::Win32::Foundation::{HANDLE};
use windows::Win32::System::Diagnostics::Debug::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SECTION_HEADER};
use windows::Win32::System::Diagnostics::ToolHelp::{CREATE_TOOLHELP_SNAPSHOT_FLAGS, MODULEENTRY32, TH32CS_SNAPMODULE};
use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE};
use crate::dll_helper::{c_to_rust_string_form_bytes, CommonResult};
use crate::{get_dll_fn, new_dll};

pub struct ModuleInfo {
    pub name: String,
    pub path: String,
    pub module_base: usize,
    pub code_base: usize,
    pub code_size: usize,
}

#[cfg(target_arch = "x86_64")]
#[allow(non_camel_case_types)]
pub type IMAGE_NT_HEADER = windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
#[cfg(target_arch = "x86")]
#[allow(non_camel_case_types)]
pub type IMAGE_NT_HEADER = windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;

#[allow(non_snake_case)]
pub fn get_all_module_info() -> CommonResult<Vec<ModuleInfo>> {
    let kernel32= new_dll!("kernel32.dll")?;
    let fnCreateToolhelp32Snapshot = get_dll_fn!(
            kernel32,
           "CreateToolhelp32Snapshot",
            fn(CREATE_TOOLHELP_SNAPSHOT_FLAGS,u32) -> HANDLE
        )?;
    let fnModule32First = get_dll_fn!(
            kernel32,
           "Module32First",
            fn(HANDLE, *mut MODULEENTRY32) ->BOOL
        )?;
    let fnModule32Next = get_dll_fn!(
            kernel32,
           "Module32Next",
            fn(HANDLE, *mut MODULEENTRY32) ->BOOL
        )?;
    let fnCloseHandle = get_dll_fn!(
            kernel32,
           "CloseHandle",
            fn(HANDLE) -> BOOL
        )?;

    unsafe {
        let mut infos =  vec![];
        let snapshot = fnCreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
        if snapshot.is_invalid() {
            return Err(windows::core::Error::from_win32().into())
        }
        let mut module_entry: MODULEENTRY32 = MODULEENTRY32::default();
        module_entry.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;
        fnModule32First(snapshot, &mut module_entry).ok()?;
        loop {
            // 输出模块的信息
            let module =  c_to_rust_string_form_bytes(&module_entry.szModule).unwrap_or_default();
            let exe_path =  c_to_rust_string_form_bytes(&module_entry.szExePath).unwrap_or_default();
            let module_base = module_entry.modBaseAddr as usize;
            let dos_header = module_base as *const IMAGE_DOS_HEADER;
            if (*dos_header).e_magic == IMAGE_DOS_SIGNATURE {

                let nt_headers = (module_base + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADER;
                let section_headers = (module_base + (*dos_header).e_lfanew as usize + std::mem::size_of::<IMAGE_NT_HEADER>()) as *const IMAGE_SECTION_HEADER;
                for i in 0..(*nt_headers).FileHeader.NumberOfSections {
                    let section_header  = section_headers.add(i as usize);
                    if (*section_header).VirtualAddress > 0 {
                        if (*section_header).Characteristics.0 & IMAGE_SCN_MEM_EXECUTE.0 > 0 {
                            let start = module_base + (*section_header).VirtualAddress as usize;
                            let length =(*section_header).Misc.VirtualSize as usize;
                            let info = ModuleInfo{
                                name: module.clone(),
                                path: exe_path.clone(),
                                module_base,
                                code_base: start,
                                code_size: length,
                            };
                            infos.push(info);
                            // break;
                        }
                    }
                }
            }

            // 获取下一个模块
            if !fnModule32Next(snapshot, &mut module_entry).as_bool() {
                break
            }
        }
        let _ = fnCloseHandle(snapshot);
        Ok(infos)
    }
}