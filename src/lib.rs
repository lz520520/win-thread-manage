use std::ffi::{c_char, CString};
use std::ptr;
use thread_helper::dll_helper::windef::*;

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
pub extern "C" fn gc_clean(mem_base: LPVOID, mem_size: SIZE_T, err: *mut c_char) -> DWORD {

    unsafe {
        match thread_helper::thread::thread_clean(mem_base as usize, mem_size) {
            Ok(_) => {
                0
            }
            Err(e) => {
                println!("thread err: {}", e.to_string());
                write_error_to_buffer(err, &e.to_string());
                1
            }
        }

    }
}

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
pub extern "C" fn initialize_hooks(){
    thread_helper::hook::hooks();
}


/// 将错误信息写入调用方提供的 `err` 缓冲区
unsafe fn write_error_to_buffer(err: *mut c_char, message: &str) {
    // 转换 Rust 字符串为 C 风格字符串
    let c_string = CString::new(message).unwrap_or_else(|_| CString::new("Unknown error").unwrap());
    // 拷贝 C 字符串的内容到调用方的缓冲区
    ptr::copy_nonoverlapping(c_string.as_ptr(), err, c_string.as_bytes_with_nul().len());
}