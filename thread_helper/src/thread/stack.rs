use std::ffi::c_void;
use std::mem;
use crate::dll_helper::CommonResult;
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


#[derive(Default)]
pub struct FrameInfo {
    pub addr: usize,
    pub module_name: String,
    pub offset: usize,
}

#[allow(non_snake_case)]
pub unsafe fn stackback(max_frames: usize) -> CommonResult<Vec<FrameInfo>>{
    let module_infos = crate::thread::module::get_all_module_info()?;


    let mut frames: Vec<*mut c_void> = vec![std::ptr::null_mut(); max_frames];
    let kernel32 = new_dll!("kernel32.dll")?;
    let fnRtlCaptureStackBackTrace = get_dll_fn!(
            kernel32,
           "RtlCaptureStackBackTrace",
            fn(framestoskip : u32,
            framestocapture : u32,
            backtrace : *mut *mut c_void,
            backtracehash : *mut u32) -> u16
        )?;

    let captured = fnRtlCaptureStackBackTrace(0, frames.len().try_into().unwrap(), mem::transmute((&mut frames).as_ptr()),mem::zeroed());
    frames.truncate(captured as usize);

    let mut frame_infos = vec![];
    for frame in frames {
        let frame = frame as usize;
        let mut info = FrameInfo::default();
        info.addr = frame;

        if let Some(module_info) = module_infos.iter().find(|x| {
            frame >= x.code_base && frame <= x.code_base + x.code_size
        }) {
            info.module_name = module_info.name.clone();
            info.offset = frame - module_info.module_base;
        }
        frame_infos.push(info);
    }

    Ok(frame_infos)
}

