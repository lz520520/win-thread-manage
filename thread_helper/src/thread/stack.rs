use crate::dll_helper::CommonResult;
use crate::thread::{capture_stack, simple_stack, FrameInfo, FRAME_METHOD};

pub unsafe  fn get_thread_frames() -> CommonResult<Vec<FrameInfo>> {
    let method = *FRAME_METHOD.lock().unwrap();
    if method == 0 {
        capture_stack::stackback(64)
    } else {
        Ok(simple_stack::get_current_thread_frames()?.stack_frames.iter().map(|x| { FrameInfo{
            addr: *x,
            module_name: "".to_string(),
            offset: 0,
        }}).collect())
    }
}