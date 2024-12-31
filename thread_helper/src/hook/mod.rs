
use std::cell::{Cell};
use std::sync::{Once};
use std::{ptr};
use minhook::MinHook;
use windows::Win32::Foundation::{BOOL, FALSE, HANDLE};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Memory::{PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VIRTUAL_ALLOCATION_TYPE, VIRTUAL_FREE_TYPE};
use windows::Win32::System::Threading::{GetCurrentThreadId, GetThreadId, LPTHREAD_START_ROUTINE, THREAD_CREATION_FLAGS};
use crate::alloc;
use crate::alloc::{AllocInfo, MemInfo};
use crate::thread::stack::get_current_thread_frames;

static mut ORIGINAL_VIRTUAL_ALLOC: Option<unsafe extern "system" fn(
    lpaddress: *const core::ffi::c_void,
    dwsize: usize,
    flallocationtype: VIRTUAL_ALLOCATION_TYPE,
    flprotect: PAGE_PROTECTION_FLAGS,
) -> *mut core::ffi::c_void> = None;

static mut ORIGINAL_CREATE_THREAD: Option<unsafe extern "system" fn(
    lpthreadattributes : *const SECURITY_ATTRIBUTES,
    dwstacksize : usize,
    lpstartaddress : LPTHREAD_START_ROUTINE,
    lpparameter : *const core::ffi::c_void,
    dwcreationflags : THREAD_CREATION_FLAGS,
    lpthreadid : *mut u32,
) -> HANDLE> = None;

static mut ORIGINAL_VIRTUAL_FREE: Option<unsafe extern "system" fn(
    lpaddress : *mut core::ffi::c_void,
    dwsize : usize,
    dwfreetype : VIRTUAL_FREE_TYPE
) -> BOOL> = None;


static INIT: Once = Once::new();

thread_local! {
    static IN_MY_VIRTUAL_ALLOC: Cell<bool> = Cell::new(false);
}

#[allow(non_snake_case, unused_variables)]
unsafe extern "system" fn MyVirtualAlloc(
    lpaddress : *const core::ffi::c_void,
    dwsize : usize, flallocationtype : VIRTUAL_ALLOCATION_TYPE,
    flprotect : PAGE_PROTECTION_FLAGS) -> *mut core::ffi::c_void {
    let already_in_hook = IN_MY_VIRTUAL_ALLOC.with(|flag| {

        if flag.get() {
            true
        } else {
            flag.set(true);
            false
        }
    });
    let  protect: PAGE_PROTECTION_FLAGS;
    let tid = GetCurrentThreadId();
    // if !already_in_hook {
    //     if flprotect.0 == 0x445 {
    //         println!("gc plugin");
    //     }
    //     // println!("tid: {tid} lpaddress: {lpaddress:?} dwsize: {dwsize}, flallocationtype: {flallocationtype:?}, flprotect: {flprotect:?}");
    // }
    // println!("virtual");




    let protect = if flprotect.0 == 0x445 {
        PAGE_READWRITE
    } else {
        flprotect
    };

    let memory =  if let Some(original) = ORIGINAL_VIRTUAL_ALLOC {
        // std::thread::sleep(std::time::Duration::from_secs(100));
        original(lpaddress, dwsize, flallocationtype, protect)
    } else {
        ptr::null_mut()
    };
    if !memory.is_null()  {
        let alloc_address = memory as usize;
        if flprotect.0 == 0x445{
            alloc::MEM_ALLOC_CACHE.add_mem(alloc_address, &MemInfo{
                mem_base: alloc_address,
                mem_size: dwsize,
            });
            alloc::MEM_ALLOC_CACHE.add_thread(alloc_address, 0);
        } else {
            let mems:  Vec<MemInfo> = alloc::MEM_ALLOC_CACHE.all_mem_values();
            if !mems.is_empty() {
                if let Ok(thread_frames)  = get_current_thread_frames() {
                    for mem in mems {
                        if thread_frames.stack_frames.iter().any(|frame| {
                            if *frame >= mem.mem_base && *frame < mem.mem_base + mem.mem_size {
                                alloc::MEM_ALLOC_CACHE.add_alloc(mem.mem_base, &AllocInfo{
                                    tid: tid as usize,
                                    alloc_base: alloc_address,
                                    alloc_size: dwsize,
                                    flallocationtype,
                                    flprotect,
                                });
                                true
                            } else {
                                false
                            }
                        }) {
                            break
                        }
                    }
                } else {
                    println!("virtual alloc thread no memory");
                }
            }
        }
    }
    IN_MY_VIRTUAL_ALLOC.with(|flag| flag.set(false));
    memory
}

#[allow(non_snake_case, unused_variables)]
unsafe extern "system" fn MyCreateThread(lpthreadattributes : *const SECURITY_ATTRIBUTES,
                                         dwstacksize : usize,
                                         lpstartaddress : LPTHREAD_START_ROUTINE,
                                         lpparameter : *const core::ffi::c_void,
                                         dwcreationflags : THREAD_CREATION_FLAGS, lpthreadid : *mut u32) -> HANDLE {
    let handle =  if let Some(original) = ORIGINAL_CREATE_THREAD {
        original(lpthreadattributes, dwstacksize, lpstartaddress, lpparameter, dwcreationflags, lpthreadid)
    } else {
        HANDLE::default()
    };

    if !handle.is_invalid() {
        let mems:  Vec<MemInfo> = alloc::MEM_ALLOC_CACHE.all_mem_values();
        if !mems.is_empty() {
            match get_current_thread_frames() {
                Ok(thread_frames) => {

                    for mem in mems {
                        if thread_frames.stack_frames.iter().any(|frame| {
                            if *frame >= mem.mem_base && *frame < mem.mem_base + mem.mem_size {
                                let tid = GetThreadId(handle);
                                // println!("create thread: {}", tid);

                                if tid > 0 {
                                    alloc::MEM_ALLOC_CACHE.add_thread(mem.mem_base, tid as usize);
                                }
                                true
                            } else {
                                false
                            }
                        }) {
                            break
                        }
                    }
                }
                Err(_err) => {
                    // println!("Error getting current thread frames ({:?})", err);
                }
            }

        }
    }
    handle
}



#[allow(non_snake_case, unused_variables)]
unsafe extern "system" fn MyVirtualFree(
    lpaddress : *mut core::ffi::c_void,
    dwsize : usize,
    dwfreetype : VIRTUAL_FREE_TYPE
) -> BOOL {
    let status =  if let Some(original) = ORIGINAL_VIRTUAL_FREE {
        original(lpaddress, dwsize, dwfreetype)
    } else {
        FALSE
    };

    let mems:  Vec<MemInfo> = alloc::MEM_ALLOC_CACHE.all_mem_values();
    if !mems.is_empty() {
        match get_current_thread_frames() {
            Ok(thread_frames) => {
                for mem in mems {
                    if thread_frames.stack_frames.iter().any(|frame| {
                        if *frame >= mem.mem_base && *frame < mem.mem_base + mem.mem_size {
                            alloc::MEM_ALLOC_CACHE.del_alloc_value(lpaddress as usize);
                            true
                        } else {
                            false
                        }
                    }) {
                        break
                    }
                }
            }
            Err(_err) => {
                // println!("Error getting current thread frames ({:?})", err);
            }
        }

    }
    status
}


pub fn hooks(){
    unsafe {
        // std::thread::sleep(std::time::Duration::from_secs(20));
        // println!("Initializing...");
        INIT.call_once(|| {
            let origin = MinHook::create_hook_api(
                obfstr::obfstr!("Kernel32.dll"),
                obfstr::obfstr!("VirtualAlloc"),
                MyVirtualAlloc as _,
            )
                .unwrap();

            ORIGINAL_VIRTUAL_ALLOC = Some(std::mem::transmute(origin));

            let origin = MinHook::create_hook_api(
                obfstr::obfstr!("Kernel32.dll"),
                obfstr::obfstr!("CreateThread"),
                MyCreateThread as _,
            )
                .unwrap();
            ORIGINAL_CREATE_THREAD = Some(std::mem::transmute(origin));

            let origin = MinHook::create_hook_api(
                obfstr::obfstr!("Kernel32.dll"),
                obfstr::obfstr!("VirtualFree"),
                MyVirtualFree as _,
            )
                .unwrap();
            ORIGINAL_VIRTUAL_FREE = Some(std::mem::transmute(origin));

            let _ = MinHook::enable_all_hooks();
        });

    }
}
