use std::ptr::null_mut;
use minhook::{MinHook, MH_STATUS};
use windows::Win32::System::Memory::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VIRTUAL_ALLOCATION_TYPE};
use thread_helper::alloc::initialize_hooks;
use thread_helper::dll_helper::CommonResult;
use thread_helper::{get_dll_fn, new_dll_test};

fn main() -> CommonResult<()> {
    initialize_hooks();
    let kernel32 = new_dll_test!("kernel32.dll")?;
    let fnVirtualAlloc = get_dll_fn!(
            kernel32,
           "VirtualAlloc",
            fn(lpaddress : *const core::ffi::c_void, dwsize : usize, flallocationtype : VIRTUAL_ALLOCATION_TYPE, flprotect : PAGE_PROTECTION_FLAGS) -> *mut core::ffi::c_void
        )?;
    unsafe {
        fnVirtualAlloc(null_mut(), 266, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    std::thread::sleep(std::time::Duration::from_secs(100));

    Ok(())
}
