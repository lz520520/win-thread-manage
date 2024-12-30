use std::ptr;
use std::ptr::null_mut;
use minhook::{MinHook, MH_STATUS};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{GetProcessHeap, VirtualAlloc, VirtualFree, VirtualQuery, HEAP_ZERO_MEMORY, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_FREE, MEM_RELEASE, MEM_RESERVE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VIRTUAL_ALLOCATION_TYPE};
use thread_helper::dll_helper::CommonResult;
use thread_helper::{get_dll_fn, new_dll_test};
use thread_helper::dll_helper::DllHelper;
fn main() -> CommonResult<()> {
    win_thread_manage::initialize_hooks();
    let kernel32 = new_dll_test!("kernel32.dll")?;
    let fnVirtualAlloc = get_dll_fn!(
            kernel32,
           "VirtualAlloc",
            fn(lpaddress : *const core::ffi::c_void, dwsize : usize, flallocationtype : VIRTUAL_ALLOCATION_TYPE, flprotect : PAGE_PROTECTION_FLAGS) -> *mut core::ffi::c_void
        )?;
    unsafe {
        let handle = fnVirtualAlloc(null_mut(), 266, MEM_COMMIT | MEM_RESERVE, PAGE_PROTECTION_FLAGS(0x445));
        VirtualFree(handle, 0, MEM_RELEASE)?;
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let result = VirtualQuery(Some(handle), &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>());
        if result == 0 {
            println!("VirtualQuery failed");
        } else {
            println!("VirtualQuery OK, {:?}",mbi.State);
        }

    }
    let bb = Vec::<u8>::with_capacity(10240);
    bb.to_ascii_lowercase();
    // println!("a: {:?}", bb);
    // println!("b: {:?}", bb);

    std::thread::sleep(std::time::Duration::from_secs(100));

    Ok(())
}
