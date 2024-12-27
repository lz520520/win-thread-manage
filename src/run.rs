use ntapi::ntpsapi::THREAD_BASIC_INFORMATION;
use windows::Wdk::System::Threading::{THREADINFOCLASS};
use windows::Win32::Foundation::{BOOL, FALSE, HANDLE, NTSTATUS};
use windows::Win32::System::Diagnostics::Debug::{CONTEXT, CONTEXT_CONTROL_AMD64};
use windows::Win32::System::Diagnostics::ToolHelp::{CREATE_TOOLHELP_SNAPSHOT_FLAGS, TH32CS_SNAPTHREAD, THREADENTRY32};
use windows::Win32::System::Memory::{ MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE};
use windows::Win32::System::Threading::{ PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, THREAD_ACCESS_RIGHTS, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME, THREAD_TERMINATE};
use crate::{get_dll_fn, new_dll};
use crate::dll_helper::CommonResult;

fn is_address_executable(address: usize,
                         fn_virtual_query: unsafe extern "system" fn(lpaddress : *const core::ffi::c_void, lpbuffer : *mut MEMORY_BASIC_INFORMATION, dwlength : usize) -> usize) -> bool {
    unsafe {
        // 初始化 MEMORY_BASIC_INFORMATION
        let mut mbi = MEMORY_BASIC_INFORMATION::default();

        // 调用 VirtualQueryEx 获取内存信息
        if fn_virtual_query(
            address as *const _,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) == 0
        {
            return false;
        }

        // 检查 Protect 属性
        mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE

    }
}
#[derive(Clone)]
struct ThreadInfo {
    pub tid: u32,
    pub stack_frames: Vec<usize>,
}
#[allow(non_snake_case)]
fn get_threads_of_process(mem_base: usize, mem_size: usize) -> CommonResult<Vec<ThreadInfo>> {
    let ntdll = new_dll!("ntdll.dll")?;
    let kernel32 = new_dll!("kernel32.dll")?;

    let fnGetCurrentProcessId = get_dll_fn!(
            kernel32,
           "GetCurrentProcessId",
            fn() -> u32
        )?;
    let fnCreateToolhelp32Snapshot = get_dll_fn!(
            kernel32,
           "CreateToolhelp32Snapshot",
            fn(CREATE_TOOLHELP_SNAPSHOT_FLAGS,u32) -> HANDLE
        )?;
    let fnOpenProcess = get_dll_fn!(
            kernel32,
           "OpenProcess",
            fn(PROCESS_ACCESS_RIGHTS, BOOL,u32) -> HANDLE
        )?;
    let fnGetCurrentThreadId = get_dll_fn!(
            kernel32,
           "GetCurrentThreadId",
            fn() -> u32
        )?;
    let fnThread32First = get_dll_fn!(
            kernel32,
           "Thread32First",
            fn(HANDLE, *mut THREADENTRY32) ->BOOL
        )?;
    let fnThread32Next = get_dll_fn!(
            kernel32,
           "Thread32Next",
            fn(HANDLE, *mut THREADENTRY32) ->BOOL
        )?;
    let fnOpenThread = get_dll_fn!(
            kernel32,
           "OpenThread",
            fn(dwdesiredaccess : THREAD_ACCESS_RIGHTS, binherithandle : BOOL, dwthreadid : u32) -> HANDLE
        )?;
    let fnNtQueryInformationThread = get_dll_fn!(
            ntdll,
           "NtQueryInformationThread",
            fn(threadhandle : HANDLE, threadinformationclass : THREADINFOCLASS, threadinformation : *mut core::ffi::c_void, threadinformationlength : u32, returnlength : *mut u32) -> NTSTATUS
        )?;

    let fnSuspendThread = get_dll_fn!(
            kernel32,
           "SuspendThread",
            fn(hthread : HANDLE) -> u32
        )?;
    let fnGetThreadContext = get_dll_fn!(
            kernel32,
           "GetThreadContext",
            fn(hthread : HANDLE, lpcontext : *mut CONTEXT) ->  BOOL
        )?;
    let fnResumeThread = get_dll_fn!(
            kernel32,
           "ResumeThread",
            fn(hthread : HANDLE) -> u32
        )?;
    let fnCloseHandle = get_dll_fn!(
            kernel32,
           "CloseHandle",
            fn(HANDLE) -> BOOL
        )?;

    let fnVirtualQuery = get_dll_fn!(
            kernel32,
           "VirtualQuery",
            fn(lpaddress : *const core::ffi::c_void, lpbuffer : *mut MEMORY_BASIC_INFORMATION, dwlength : usize) -> usize
        )?;

    let mut infos = Vec::new();
    unsafe {
        let process_id = fnGetCurrentProcessId();

        let snapshot =  fnCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        let snapshot = (!snapshot.is_invalid()).then(|| snapshot).ok_or_else(windows_result::Error::from_win32)?;

        let mut thread_entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        let process_handle = fnOpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, process_id);
        let process_handle = (!process_handle.is_invalid()).then(|| process_handle).ok_or_else(windows_result::Error::from_win32)?;

        let tid =  fnGetCurrentThreadId();
        if fnThread32First(snapshot, &mut thread_entry).ok().is_ok() {
            loop{
                if thread_entry.th32OwnerProcessID == process_id  && thread_entry.th32ThreadID != tid {
                    let thread_handle = fnOpenThread(THREAD_GET_CONTEXT |
                                     THREAD_SUSPEND_RESUME |
                                     THREAD_QUERY_INFORMATION, FALSE, thread_entry.th32ThreadID);
                    if !thread_handle.is_invalid() {
                        let mut thread_info = THREAD_BASIC_INFORMATION::default();
                        let mut return_length = 0;

                        let result = fnNtQueryInformationThread(
                            thread_handle,
                            THREADINFOCLASS(0), // ThreadBasicInformation
                            &mut thread_info as *mut _ as *mut _,
                            std::mem::size_of::<THREAD_BASIC_INFORMATION>() as u32,
                            &mut return_length,
                        );
                        if result.is_ok() {
                            let stack_base = (*thread_info.TebBaseAddress).NtTib.StackBase as usize;
                            let stack_limit = (*thread_info.TebBaseAddress).NtTib.StackLimit as usize;

                            let mut ctx = CONTEXT::default();

                            #[cfg(any(target_arch = "x86_64"))]
                            {
                                ctx.ContextFlags = CONTEXT_CONTROL_AMD64;
                            }

                            #[cfg(target_arch = "x86")]
                            {
                                ctx.ContextFlags = CONTEXT_CONTROL_X86;
                            }

                            fnSuspendThread(thread_handle);
                            let result = fnGetThreadContext(thread_handle, &mut ctx);
                            fnResumeThread(thread_handle);
                            result.ok()?;
                            #[cfg(target_arch = "x86_64")]
                            let mut current_rsp = ctx.Rsp as usize; // Or Esp for x86
                            #[cfg(target_arch = "x86")]
                            let mut current_rsp = ctx.Esp as usize; // Or Esp for x86


                            let mut stack_frames = Vec::new();
                            while  current_rsp < stack_base && current_rsp >= stack_limit {
                                let stack_value_ptr = current_rsp as *const usize;
                                if !stack_value_ptr.is_null() && is_address_executable(*stack_value_ptr, fnVirtualQuery) {
                                    stack_frames.push(*stack_value_ptr);
                                }
                                current_rsp += std::mem::size_of::<usize>();
                            }
                            if mem_base > 0 {
                                for frame in stack_frames.clone() {
                                    if frame >= mem_base && frame < mem_base + mem_size {
                                        let info = ThreadInfo{
                                            tid: thread_entry.th32ThreadID,
                                            stack_frames: stack_frames,
                                        };
                                        infos.push(info);
                                        break
                                    }
                                }
                            } else {
                                let info = ThreadInfo{
                                    tid: thread_entry.th32ThreadID,
                                    stack_frames: stack_frames,
                                };
                                infos.push(info);
                            }
                            let _ = fnCloseHandle(thread_handle);
                        }




                    }
                }
                if fnThread32Next(snapshot, &mut thread_entry).ok().is_err() {
                    break;
                }
            }

        }
        let _ = fnCloseHandle(snapshot);
        let _ = fnCloseHandle(process_handle);
    }
    Ok(infos)
}

#[allow(non_snake_case)]
pub fn start(mem_base: usize, mem_size: usize) -> CommonResult<()> {
    let kernel32 = new_dll!("kernel32.dll")?;
    let fnOpenThread = get_dll_fn!(
            kernel32,
           "OpenThread",
            fn(THREAD_ACCESS_RIGHTS,BOOL,u32) -> HANDLE
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


    println!("mem_base: {}, mem_size: {}", mem_base, mem_size);
    let infos =  get_threads_of_process(mem_base, mem_size)?;



    for info in infos {
        unsafe {
            let result__ = fnOpenThread(THREAD_TERMINATE | THREAD_QUERY_INFORMATION, FALSE, info.tid);
            if let Ok(handle) = (!result__.is_invalid()).then(|| result__).ok_or_else(windows_result::Error::from_win32) {
                let _ = fnTerminateThread(handle, 0).ok()?;
                println!("kill thread: {}", info.tid);
                let _ = fnCloseHandle(handle).ok()?;
            }

        }
    }
    println!("kill thread over");

    // unsafe {
    //     VirtualFree(mem_base as *mut _, 0, MEM_RELEASE)?;
    // }
    Ok(())

}
