use std::ffi::{c_char, c_int, CString};
use std::ptr;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::{DWORD, LPVOID};

mod run;



#[no_mangle]
#[allow(non_snake_case, unused_variables)]
pub extern "C" fn gc_clean(mem_base: LPVOID, mem_size: SIZE_T, err: *mut c_char) -> DWORD {
    unsafe {
        match run::start(mem_base as usize, mem_size) {
            Ok(_) => {
                0
            }
            Err(e) => {
                write_error_to_buffer(err, &e.to_string());
                1
            }
        }

    }
}

/// 将错误信息写入调用方提供的 `err` 缓冲区
unsafe fn write_error_to_buffer(err: *mut c_char, message: &str) {
    // 转换 Rust 字符串为 C 风格字符串
    let c_string = CString::new(message).unwrap_or_else(|_| CString::new("Unknown error").unwrap());
    // 拷贝 C 字符串的内容到调用方的缓冲区
    ptr::copy_nonoverlapping(c_string.as_ptr(), err, c_string.as_bytes_with_nul().len());
}