use windows::core::BOOL;
use windows::Win32::Foundation::{CloseHandle, FALSE, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{CREATE_TOOLHELP_SNAPSHOT_FLAGS, TH32CS_SNAPTHREAD, THREADENTRY32};
use windows::Win32::System::Threading::{GetCurrentThreadId, OpenThread, TerminateThread, THREAD_ACCESS_RIGHTS, THREAD_ALL_ACCESS, THREAD_SUSPEND_RESUME};
use crate::{get_dll_fn, new_dll};
use crate::dll_helper::CommonResult;

pub fn get_current_thread_id() -> u32 {
    unsafe {
        GetCurrentThreadId()
    }
}

pub fn close_thread(tid: u32, code: u32) -> CommonResult<()> {
    unsafe {
        let handle = OpenThread(THREAD_ALL_ACCESS, false, tid)?;
        TerminateThread(handle, code)?;
        CloseHandle(handle)?;
    }
    Ok(())
}

pub struct ThreadManager {
    thread_handles: Vec<HANDLE>
}
#[allow(non_snake_case)]
impl ThreadManager {
    pub fn new() -> Self {
        ThreadManager{ thread_handles: vec![] }
    }
    pub fn suspend_all_threads(&mut self) -> CommonResult<()> {
        let kernel32= new_dll!("kernel32.dll")?;
        let fnCreateToolhelp32Snapshot = get_dll_fn!(
                kernel32,
               "CreateToolhelp32Snapshot",
                fn(CREATE_TOOLHELP_SNAPSHOT_FLAGS,u32) -> HANDLE
            )?;
        let fnGetCurrentProcessId = get_dll_fn!(
                kernel32,
               "GetCurrentProcessId",
                fn() -> u32
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
        let fnSuspendThread = get_dll_fn!(
                kernel32,
               "SuspendThread",
                fn(hthread : HANDLE) -> u32
            )?;

        let fnCloseHandle = get_dll_fn!(
                kernel32,
               "CloseHandle",
                fn(HANDLE) -> BOOL
            )?;
        
        unsafe {
            // 1. 抑制线程
            let snapshot =  fnCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot.is_invalid() {
                return Err(obfstr::obfstr!("invalid snapshot").into());
            }
            let process_id = fnGetCurrentProcessId();
            let mut thread_entry = THREADENTRY32::default();
            let tid =  fnGetCurrentThreadId();

            if fnThread32First(snapshot, &mut thread_entry).ok().is_ok() {
                loop{
                    if thread_entry.th32OwnerProcessID == process_id  && thread_entry.th32ThreadID != tid {
                        let thread_handle = fnOpenThread(THREAD_SUSPEND_RESUME
                                                         , FALSE, thread_entry.th32ThreadID);
                        if !thread_handle.is_invalid() {
                            let _ = fnSuspendThread(thread_handle);
                            self.thread_handles.push(thread_handle);
                        }
                    }
                    if fnThread32Next(snapshot, &mut thread_entry).ok().is_err() {
                        break;
                    }
                }
            }
            let _ = fnCloseHandle(snapshot);
        }
        Ok(())

    }
}
#[allow(non_snake_case)]
impl Drop for ThreadManager {
    fn drop(&mut self) {
        let kernel32= new_dll!("kernel32.dll").unwrap();
        let fnResumeThread = get_dll_fn!(
                kernel32,
               "ResumeThread",
                fn(hthread : HANDLE) -> u32
            ).unwrap();
        let fnCloseHandle = get_dll_fn!(
                kernel32,
               "CloseHandle",
                fn(HANDLE) -> BOOL
            ).unwrap();
       unsafe {
           for handle in self.thread_handles.clone() {
               let _ = fnResumeThread(handle);
               let _ = fnCloseHandle(handle);
           }
       }
    }
}