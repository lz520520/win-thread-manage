use std::error::Error;
use ntapi::ntpsapi::THREAD_BASIC_INFORMATION;
use windows::Wdk::System::Threading::{NtQueryInformationThread, THREADINFOCLASS};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::{GetThreadContext, CONTEXT, CONTEXT_CONTROL_AMD64};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32};
use windows::Win32::System::Memory::{VirtualFree, VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_RELEASE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE};
use windows::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId, OpenProcess, OpenThread, ResumeThread, SuspendThread, TerminateThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME, THREAD_TERMINATE};

fn is_address_executable(address: usize) -> bool {
    unsafe {
        // 初始化 MEMORY_BASIC_INFORMATION
        let mut mbi = MEMORY_BASIC_INFORMATION::default();

        // 调用 VirtualQueryEx 获取内存信息
        if VirtualQuery(
            Some(address as *const _),
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
fn get_threads_of_process(mem_base: usize, mem_size: usize) -> windows::core::Result<Vec<ThreadInfo>> {
    let mut infos = Vec::new();
    unsafe {
        let process_id = GetCurrentProcessId();

        let snapshot =  CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)?;
        let mut thread_entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        let process_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, process_id)?;
        let tid =  GetCurrentThreadId();
        if Thread32First(snapshot, &mut thread_entry).is_ok() {
            loop{
                if thread_entry.th32OwnerProcessID == process_id  && thread_entry.th32ThreadID != tid {
                    if let Ok(thread_handle) = OpenThread(THREAD_GET_CONTEXT |
                                                              THREAD_SUSPEND_RESUME |
                                                              THREAD_QUERY_INFORMATION, false, thread_entry.th32ThreadID) {
                        let mut thread_info = THREAD_BASIC_INFORMATION::default();
                        let mut return_length = 0;

                        let result = NtQueryInformationThread(
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

                            SuspendThread(thread_handle);
                            GetThreadContext(thread_handle, &mut ctx)?;
                            ResumeThread(thread_handle);
                            #[cfg(target_arch = "x86_64")]
                            let mut current_rsp = ctx.Rsp as usize; // Or Esp for x86
                            #[cfg(target_arch = "x86")]
                            let mut current_rsp = ctx.Esp as usize; // Or Esp for x86


                            let mut stack_frames = Vec::new();
                            while  current_rsp < stack_base && current_rsp >= stack_limit {
                                let stack_value_ptr = current_rsp as *const usize;
                                if !stack_value_ptr.is_null() && is_address_executable(*stack_value_ptr) {
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
                            let _ = CloseHandle(thread_handle);
                        }




                    }
                }
                if Thread32Next(snapshot, &mut thread_entry).is_err() {
                    break;
                }
            }

        }
        let _ = CloseHandle(snapshot);
        let _ = CloseHandle(process_handle);
    }
    Ok(infos)
}


pub fn start(mem_base: usize, mem_size: usize) -> CommonResult<()> {
    println!("mem_base: {}, mem_size: {}", mem_base, mem_size);
    let infos =  get_threads_of_process(mem_base, mem_size)?;
    for info in infos {
        unsafe {
            if let Ok(handle) = OpenThread(THREAD_TERMINATE | THREAD_QUERY_INFORMATION, false, info.tid) {
                let _ = TerminateThread(handle, 0)?;
                println!("kill thread: {}", info.tid);
                let _ = CloseHandle(handle);
            }

        }
    }
    println!("kill thread over");

    // unsafe {
    //     VirtualFree(mem_base as *mut _, 0, MEM_RELEASE)?;
    // }
    Ok(())

}
pub type CommonResult<T> = Result<T, Box<dyn Error>>;
