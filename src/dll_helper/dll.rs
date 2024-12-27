use std::error::Error;
use std::ffi::{CString, OsStr};
use std::os::windows::ffi::OsStrExt;
use winapi::shared::minwindef::{FARPROC, HMODULE};
use winapi::um::libloaderapi::{FreeLibrary, GetModuleHandleW, GetProcAddress, LoadLibraryW};


pub type CommonResult<T> = Result<T, Box<dyn Error>>;
pub fn get_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}
pub struct DllHelper {
    handle: HMODULE,
    free: bool,
}

impl DllHelper {
    pub fn new(dll_name: &str) -> CommonResult<Self> {
        let handle = unsafe { LoadLibraryW(get_wide(dll_name).as_ptr()) };
        if handle.is_null() {
            return Err("handle is invalid".into());
        }
        Ok(DllHelper{ handle, free: true })
    }
    pub fn new_module(dll_name: &str) -> CommonResult<Self> {
        let handle =  Self::get_module(dll_name)?;
        Ok(DllHelper{ handle, free:false })
    }
    pub fn get_module(dll_name: &str) -> CommonResult<HMODULE> {
        let handle = unsafe { GetModuleHandleW(get_wide(dll_name).as_ptr()) };
        if handle.is_null() {
            return Err("handle is invalid".into());
        }
        Ok(handle)
    }

    pub fn is_valid(&self) -> bool {
        !self.handle.is_null() && self.free
    }

    pub fn get_fn(&self, fn_name: &str) -> CommonResult<FARPROC> {
        let c_str = CString::new(fn_name)?;
        let func = unsafe { GetProcAddress(self.handle, c_str.as_ptr() as _) };
        if func.is_null() {
            Err(format!("func {} is invalid", fn_name).into())
        } else {
            Ok(func)
        }
    }

}


impl Drop for DllHelper {
    fn drop(&mut self) {
        if self.is_valid() {
            // println!("{}", obfstr::obfstr!("free"));
            unsafe { let _ = FreeLibrary(self.handle); };
        }
    }
}

#[macro_export]
macro_rules! new_dll {
    ($dll_name:expr) => {{
        crate::dll_helper::DllHelper::new(obfstr::obfstr!($dll_name))
    }};
}

#[macro_export]
macro_rules! get_dll_fn {
    ($dll:expr, $fn_name:expr, fn($($arg_type:ty),*) -> $ret_type:ty) => {{
          let proc = $dll.get_fn(obfstr::obfstr!($fn_name));
        match proc {
            Ok(address) => Ok(unsafe {
                std::mem::transmute::<
                    _,
                    unsafe extern "system" fn($($arg_type),*) -> $ret_type
                >(address)
            }),
            Err(e) => Err(e),
        }
    }};
    
      ($dll:expr, $fn_name:expr, fn($($arg_name:ident : $arg_type:ty),*) -> $ret_type:ty) => {{
          let proc = $dll.get_fn(obfstr::obfstr!($fn_name));
        match proc {
            Ok(address) => Ok(unsafe {
                std::mem::transmute::<
                    _,
                    unsafe extern "system" fn($($arg_type),*) -> $ret_type
                >(address)
            }),
            Err(e) => Err(e),
        }
    }};
}


#[test]
fn test_dll() {
    {
        let k32_dll = DllHelper::new(obfstr::obfstr!("kernel32.dll")).unwrap();
        let func = k32_dll.get_fn(obfstr::obfstr!("GetProcAddress")).unwrap();
        println!("func: {:?}",func);
    }
    println!("other");
}

