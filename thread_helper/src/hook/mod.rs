
use std::cell::{Cell};
use std::sync::{Mutex, Once};
use std::{mem, ptr};
use minhook::MinHook;
use once_cell::sync::Lazy;
use winapi::shared::minwindef::UINT;
use windows::core::BOOL;
use windows::Win32::Foundation::{FALSE, HANDLE};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Memory::{PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VIRTUAL_ALLOCATION_TYPE, VIRTUAL_FREE_TYPE};
use windows::Win32::System::Threading::{GetCurrentThreadId, GetThreadId, LPTHREAD_START_ROUTINE, THREAD_CREATION_FLAGS};
use crate::alloc;
use crate::alloc::{AllocInfo, MemInfo};
use crate::thread::module::get_memory;
use crate::thread::stack::{stackback};


static  ORIGINAL_VIRTUAL_ALLOC: Lazy<Mutex<Option<unsafe extern "system" fn(
    lpaddress: *const core::ffi::c_void,
    dwsize: usize,
    flallocationtype: VIRTUAL_ALLOCATION_TYPE,
    flprotect: PAGE_PROTECTION_FLAGS,
) -> *mut core::ffi::c_void>>> = Lazy::new(|| Mutex::new(None));


static  ORIGINAL_FREE_CONSOLE: Lazy<Mutex<Option<unsafe extern "system" fn() -> BOOL>>> = Lazy::new(|| Mutex::new(None));

static  ORIGINAL_CREATE_THREAD: Lazy<Mutex<Option<unsafe extern "system" fn(
    lpthreadattributes : *const SECURITY_ATTRIBUTES,
    dwstacksize : usize,
    lpstartaddress : LPTHREAD_START_ROUTINE,
    lpparameter : *const core::ffi::c_void,
    dwcreationflags : THREAD_CREATION_FLAGS,
    lpthreadid : *mut u32,
) -> HANDLE>>> = Lazy::new(|| Mutex::new(None));

static  ORIGINAL_VIRTUAL_FREE: Lazy<Mutex<Option<unsafe extern "system" fn(
    lpaddress : *mut core::ffi::c_void,
    dwsize : usize,
    dwfreetype : VIRTUAL_FREE_TYPE
) -> BOOL>>> = Lazy::new(|| Mutex::new(None));


static  ORIGINAL_VIRTUAL_PROTECT: Lazy<Mutex<Option<unsafe extern "system" fn(
    lpaddress : *mut core::ffi::c_void,
    dwsize : usize,
    flnewprotect : PAGE_PROTECTION_FLAGS,
    lpfloldprotect : *mut PAGE_PROTECTION_FLAGS
) -> BOOL>>> = Lazy::new(|| Mutex::new(None));


static MODULE_BLACKLIST: Lazy<Mutex<Vec<String>>> = Lazy::new(|| {Mutex::new(Vec::new())});

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
    let origin = ORIGINAL_VIRTUAL_ALLOC.lock().unwrap().clone();
    let memory =  if let Some(original) = origin {
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
                if let Ok(frames) = stackback(64) {
                    for mem in mems {

                        if frames.iter().any(|frame| {
                            if frame.addr >= mem.mem_base && frame.addr < mem.mem_base + mem.mem_size {
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
                }
            }
        }
    }
    IN_MY_VIRTUAL_ALLOC.with(|flag| flag.set(false));
    memory
}

#[allow(non_snake_case, unused_variables)]
unsafe extern "system" fn MyVirtualProtect(
    lpaddress : *mut core::ffi::c_void,
    dwsize : usize,
    flnewprotect : PAGE_PROTECTION_FLAGS,
    lpfloldprotect : *mut PAGE_PROTECTION_FLAGS
) -> BOOL {
    let protect = if flnewprotect.0 == 0x445 {
        PAGE_READWRITE
    } else {
        flnewprotect
    };
    let origin = ORIGINAL_VIRTUAL_PROTECT.lock().unwrap().clone();
    let status =  if let Some(original) = origin {
        // std::thread::sleep(std::time::Duration::from_secs(100));
        original(lpaddress, dwsize, protect, lpfloldprotect)
    } else {
        FALSE
    };
    if status.as_bool()  && flnewprotect.0 == 0x445 {
        let alloc_address = lpaddress as usize;
        alloc::MEM_ALLOC_CACHE.add_mem(alloc_address, &MemInfo{
            mem_base: alloc_address,
            mem_size: dwsize,
        });
        alloc::MEM_ALLOC_CACHE.add_thread(alloc_address, 0);
    }
    status
}

#[allow(non_snake_case, unused_variables)]
unsafe extern "system" fn MyFreeConsole() -> BOOL {
    let origin = ORIGINAL_FREE_CONSOLE.lock().unwrap().clone();
    let status =  if let Some(original) = origin {
        // std::thread::sleep(std::time::Duration::from_secs(100));
        original()
    } else {
        FALSE
    };
    status
}

#[allow(non_snake_case, unused_variables)]
unsafe extern "system" fn MyCreateThread(lpthreadattributes : *const SECURITY_ATTRIBUTES,
                                         dwstacksize : usize,
                                         lpstartaddress : LPTHREAD_START_ROUTINE,
                                         lpparameter : *const core::ffi::c_void,
                                         dwcreationflags : THREAD_CREATION_FLAGS, lpthreadid : *mut u32) -> HANDLE {
    let module_blacklist = {MODULE_BLACKLIST.lock().unwrap().clone()};
    for module in module_blacklist.iter() {
        if let Ok(mem) = get_memory(&module) {
            let addr: usize =  std::mem::transmute(lpstartaddress);
            if addr >= mem.mem_base && addr <= mem.mem_base + mem.mem_size {
                return HANDLE::default()
            }
        }
    }
    let origin = ORIGINAL_CREATE_THREAD.lock().unwrap().clone();
    let handle =  if let Some(original) = origin {
        original(lpthreadattributes, dwstacksize, lpstartaddress, lpparameter, dwcreationflags, lpthreadid)
    } else {
        HANDLE::default()
    };

    if !handle.is_invalid() {
        let mems:  Vec<MemInfo> = alloc::MEM_ALLOC_CACHE.all_mem_values();
        if !mems.is_empty() {
            match stackback(64) {
                Ok(thread_frames) => {

                    for mem in mems {
                        if thread_frames.iter().any(|frame| {
                            if frame.addr >= mem.mem_base && frame.addr < mem.mem_base + mem.mem_size {
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
    let origin = ORIGINAL_VIRTUAL_FREE.lock().unwrap().clone();
    let status =  if let Some(original) = origin {
        original(lpaddress, dwsize, dwfreetype)
    } else {
        FALSE
    };

    let mems:  Vec<MemInfo> = alloc::MEM_ALLOC_CACHE.all_mem_values();
    if !mems.is_empty() {
        match stackback(64) {
            Ok(thread_frames) => {
                for mem in mems {
                    if thread_frames.iter().any(|frame| {
                        if frame.addr >= mem.mem_base && frame.addr < mem.mem_base + mem.mem_size {
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
#[allow(non_snake_case, unused_variables)]
extern "stdcall" fn MyExitProcess(uExitCode: UINT) {
    // println!("hook exit");
    std::thread::sleep(std::time::Duration::from_secs(60 * 60 * 24 * 365  ));

}


pub fn set_module_blacklist(list: Vec<String>) {
    *MODULE_BLACKLIST.lock().unwrap() = list;

}

fn is_hook(code: &[u8]) -> bool {
    code.starts_with(&[0xE8]) ||
        code.starts_with(&[0xE9]) ||
        (code[0] == 0x0F && (code[1] & 0xF0) == 0x80) ||
        code.starts_with(&[0xFF,0x15,0x00,0x00,0x00,0x02]) ||
        code.starts_with(&[0xFF,0x25,0x00,0x00,0x00,0x00])||
        (code[0] & 0xF0 == 0x70 && code[1..].starts_with(&[0x0E,0xFF,0x25]))
}

pub fn hooks(){
    unsafe {
        let dll = crate::dll_helper::DllHelper::new_module(obfstr::obfstr!("kernel32.dll")).unwrap();

        let proc = dll.get_fn(obfstr::obfstr!("FreeConsole")).unwrap();
        let mem_start: [u8; 6] = std::ptr::read(proc as *const [u8; 6]);
        if is_hook(&mem_start) {
            return;
        }
        let _ = MinHook::remove_hook(mem::transmute(proc));
        let origin = MinHook::create_hook_api(
            obfstr::obfstr!("Kernel32.dll"),
            obfstr::obfstr!("FreeConsole"),
            MyFreeConsole as _,
        )
            .unwrap();
        *ORIGINAL_FREE_CONSOLE.lock().unwrap() = Some(std::mem::transmute(origin));


        let proc = dll.get_fn(obfstr::obfstr!("VirtualAlloc")).unwrap();
        let _ = MinHook::remove_hook(mem::transmute(proc));
        let origin = MinHook::create_hook_api(
            obfstr::obfstr!("Kernel32.dll"),
            obfstr::obfstr!("VirtualAlloc"),
            MyVirtualAlloc as _,
        )
            .unwrap();
        *ORIGINAL_VIRTUAL_ALLOC.lock().unwrap() = Some(std::mem::transmute(origin));

        let proc = dll.get_fn(obfstr::obfstr!("VirtualProtect")).unwrap();
        let _ = MinHook::remove_hook(mem::transmute(proc));
        let origin = MinHook::create_hook_api(
            obfstr::obfstr!("Kernel32.dll"),
            obfstr::obfstr!("VirtualProtect"),
            MyVirtualProtect as _,
        )
            .unwrap();
        *ORIGINAL_VIRTUAL_PROTECT.lock().unwrap() = Some(std::mem::transmute(origin));

        let proc = dll.get_fn(obfstr::obfstr!("CreateThread")).unwrap();
        let _ = MinHook::remove_hook(mem::transmute(proc));
        let origin = MinHook::create_hook_api(
            obfstr::obfstr!("Kernel32.dll"),
            obfstr::obfstr!("CreateThread"),
            MyCreateThread as _,
        )
            .unwrap();
        *ORIGINAL_CREATE_THREAD.lock().unwrap() = Some(std::mem::transmute(origin));

        let proc = dll.get_fn(obfstr::obfstr!("VirtualFree")).unwrap();
        let _ = MinHook::remove_hook(mem::transmute(proc));
        let origin = MinHook::create_hook_api(
            obfstr::obfstr!("Kernel32.dll"),
            obfstr::obfstr!("VirtualFree"),
            MyVirtualFree as _,
        )
            .unwrap();
        *ORIGINAL_VIRTUAL_FREE.lock().unwrap() = Some(std::mem::transmute(origin));

        let proc = dll.get_fn(obfstr::obfstr!("ExitProcess")).unwrap();
        let _ = MinHook::remove_hook(mem::transmute(proc));
        let _origin = MinHook::create_hook_api(
            obfstr::obfstr!("Kernel32.dll"),
            obfstr::obfstr!("ExitProcess"),
            MyExitProcess as _).unwrap();

        let _ = MinHook::enable_all_hooks();
    }
}
