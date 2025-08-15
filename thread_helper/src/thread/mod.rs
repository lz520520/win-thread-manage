pub mod stack;
pub mod module;

use std::collections::HashSet;
use windows::core::BOOL;
use windows::Win32::Foundation::{FALSE, HANDLE};
use windows::Win32::System::Memory::{ MEMORY_BASIC_INFORMATION, MEM_COMMIT,  MEM_RELEASE, MEM_RESERVE, VIRTUAL_FREE_TYPE};
use windows::Win32::System::Threading::{ THREAD_ACCESS_RIGHTS, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME, THREAD_TERMINATE};
use crate::{get_dll_fn, new_dll};
use crate::alloc;
use crate::dll_helper::CommonResult;

fn is_valid_address(address: *const std::ffi::c_void,
                    fn_virtual_query: unsafe extern "system" fn(lpaddress : *const core::ffi::c_void, lpbuffer : *mut MEMORY_BASIC_INFORMATION, dwlength : usize) -> usize) -> bool{
    let mut mbi = MEMORY_BASIC_INFORMATION::default();
    unsafe {
        let result = fn_virtual_query(address, &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>());
        if result == 0 {
            return false;
        }
        let result = mbi.State == MEM_COMMIT || mbi.State == MEM_RESERVE;
        if !result {
            // println!("state: {:?}", mbi.State);
        }
        result
    }
}

#[allow(non_snake_case)]
pub fn thread_clean(mem_base: usize, _mem_size: usize) -> CommonResult<()> {
    let kernel32 = new_dll!("kernel32.dll")?;
    let fnVirtualQuery = get_dll_fn!(
            kernel32,
           "VirtualQuery",
            fn(lpaddress : *const core::ffi::c_void, lpbuffer : *mut MEMORY_BASIC_INFORMATION, dwlength : usize) -> usize
        )?;

    let fnVirtualFree = get_dll_fn!(
            kernel32,
           "VirtualFree",
            fn(lpaddress : *mut core::ffi::c_void, dwsize : usize, dwfreetype : VIRTUAL_FREE_TYPE) -> BOOL
        )?;

    let fnOpenThread = get_dll_fn!(
            kernel32,
           "OpenThread",
            fn(THREAD_ACCESS_RIGHTS,BOOL,u32) -> HANDLE
        )?;
    let fnSuspendThread = get_dll_fn!(
            kernel32,
           "SuspendThread",
            fn(hthread : HANDLE) -> u32
        )?;
    let fnTerminateThread = get_dll_fn!(
            kernel32,
           "TerminateThread",
            fn(HANDLE, u32) -> BOOL
        )?;
    let fnCloseHandle = get_dll_fn!(
            kernel32,
           "CloseHandle",
            fn(HANDLE) -> BOOL
        )?;

    // println!("mem_base: {:X}, mem_size: {}", mem_base, mem_size);
    let mut all_threads = HashSet::new();


    // let infos =  get_threads_of_process(mem_base, mem_size)?;

    if let Some (threads) = alloc::MEM_ALLOC_CACHE.get_thread(mem_base) {
        threads.iter().for_each(|thread| {
            if *thread > 0 {
                all_threads.insert(*thread);
            }
        });

        for tid in threads.clone() {
            if tid > 0 {
                unsafe {
                    let result__ = fnOpenThread(THREAD_SUSPEND_RESUME | THREAD_TERMINATE | THREAD_QUERY_INFORMATION, FALSE, tid as u32);
                    if let Ok(handle) = (!result__.is_invalid()).then(|| result__).ok_or_else(windows_result::Error::from_win32) {
                        let _ = fnSuspendThread(handle);
                        let _ = fnTerminateThread(handle, 0).ok()?;
                        let _ = fnCloseHandle(handle).ok()?;
                    }
                }
            }
        }
        alloc::MEM_ALLOC_CACHE.del_thread(mem_base);

    }

    println!("kill thread over");

    if let Some(alloc_infos) = alloc::MEM_ALLOC_CACHE.get_alloc(mem_base) {
        println!("alloc_infos: {}", alloc_infos.len());
        let mut count = 0;
        if !all_threads.is_empty() {
            for info in alloc_infos {
                // println!("Alloc thread: {}", info.tid);
                if info.tid == 0 {
                    continue;
                }
                if is_valid_address(info.alloc_base as *const _, fnVirtualQuery) {
                    unsafe {
                        let _ = fnVirtualFree(info.alloc_base as *mut _, 0, MEM_RELEASE);
                    }
                    count += 1;
                }

            }
            println!("free count: {}", count);

        }

        alloc::MEM_ALLOC_CACHE.del_alloc(mem_base);
        alloc::MEM_ALLOC_CACHE.del_mem(mem_base);
        println!("free memory over");
    }
    Ok(())

}
