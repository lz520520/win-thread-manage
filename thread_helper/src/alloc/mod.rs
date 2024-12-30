pub mod cache;

use std::cell::{Cell};
use std::sync::{Once};
use std::{ptr};
use minhook::MinHook;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Memory::{ MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VIRTUAL_ALLOCATION_TYPE};
use windows::Win32::System::Threading::{GetCurrentThreadId, GetThreadId, LPTHREAD_START_ROUTINE, THREAD_CREATION_FLAGS};
use crate::alloc::cache::{AllocInfo, MemInfo};
use crate::dll_helper::CommonResult;
use crate::thread::get_current_thread_frames;

static mut ORIGINAL_VIRTUAL_ALLOC: Option<unsafe extern "system" fn(
    lpaddress: *const core::ffi::c_void,
    dwsize: usize,
    flallocationtype: VIRTUAL_ALLOCATION_TYPE,
    flprotect: PAGE_PROTECTION_FLAGS,
) -> *mut core::ffi::c_void> = None;

static mut ORIGINAL_CREATE_THREAD: Option<unsafe extern "system" fn(lpthreadattributes : *const SECURITY_ATTRIBUTES,
    dwstacksize : usize,
    lpstartaddress : LPTHREAD_START_ROUTINE,
    lpparameter : *const core::ffi::c_void,
    dwcreationflags : THREAD_CREATION_FLAGS, lpthreadid : *mut u32) -> HANDLE> = None;

static INIT: Once = Once::new();

thread_local! {
    static IN_MY_VIRTUAL_ALLOC: Cell<bool> = Cell::new(false);
}

#[no_mangle]
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
    //     println!("tid: {tid} lpaddress: {lpaddress:?} dwsize: {dwsize}, flallocationtype: {flallocationtype:?}, flprotect: {flprotect:?}");
    // }



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
            cache::MEM_ALLOC_CACHE.add_mem(alloc_address, &MemInfo{
                mem_base: alloc_address,
                mem_size: dwsize,
            });
            cache::MEM_ALLOC_CACHE.add_thread(alloc_address, 0);
            // cache::MEM_ALLOC_CACHE.add_alloc(alloc_address, &AllocInfo{
            //     alloc_base: alloc_address,
            //     alloc_size: dwsize,
            //     flallocationtype,
            //     flprotect,
            // });
        } else {
            let mems:  Vec<MemInfo> = cache::MEM_ALLOC_CACHE.all_mem_values();
            if !mems.is_empty() {
                if let Ok(thread_frames)  = get_current_thread_frames() {
                    // println!("thread frames: {}", thread_frames.stack_frames.len());

                    for mem in mems {
                        if thread_frames.stack_frames.iter().any(|frame| {
                            if *frame >= mem.mem_base && *frame < mem.mem_base + mem.mem_size {
                                if !already_in_hook {
                                    // println!("virtual alloc thread: {}", tid);
                                    // println!("plugin alloc mem: {:X}, mem_size: {}", alloc_address, dwsize);
                                }
                                cache::MEM_ALLOC_CACHE.add_alloc(mem.mem_base, &AllocInfo{
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

#[no_mangle]
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
        let mems:  Vec<MemInfo> = cache::MEM_ALLOC_CACHE.all_mem_values();
        if !mems.is_empty() {
            match get_current_thread_frames() {
                Ok(thread_frames) => {

                    for mem in mems {
                        if thread_frames.stack_frames.iter().any(|frame| {
                            if *frame >= mem.mem_base && *frame < mem.mem_base + mem.mem_size {
                                let tid = GetThreadId(handle);
                                // println!("create thread: {}", tid);

                                if tid > 0 {
                                    cache::MEM_ALLOC_CACHE.add_thread(mem.mem_base, tid as usize);
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
                Err(err) => {
                    println!("Error getting current thread frames ({:?})", err);
                }
            }

            }
    }
    handle
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
            let _ = MinHook::enable_all_hooks();
        });

    }
}
