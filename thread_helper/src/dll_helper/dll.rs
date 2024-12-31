use std::error::Error;
use std::ffi::{CString, OsStr};
use std::os::windows::ffi::OsStrExt;
use winapi::shared::minwindef::FARPROC;
use winapi::um::libloaderapi::{FreeLibrary, GetModuleHandleW, GetProcAddress, LoadLibraryW};
use windows::core::PCSTR;
use crate::dll_helper::peb_lookup::{my_get_proc_address, my_load_library, ModuleHandle, GLOBAL_IAT};

pub type CommonResult<T> = Result<T, Box<dyn Error>>;
pub fn get_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}
pub struct DllHelper {
    handle: ModuleHandle,
    free: bool,
}

impl DllHelper {
    pub fn new(dll_name: &str) -> CommonResult<Self> {
        let c_name =  CString::new(dll_name)?;
        let handle = my_load_library(c_name.as_ptr() as *const _);
        if handle.is_none() {
            return Err("handle is invalid".into());
        }
        Ok(DllHelper{ handle: handle.unwrap(), free: true })
    }
    pub fn new_module(dll_name: &str) -> CommonResult<Self> {
        let c_name =  CString::new(dll_name)?;
        let handle = my_load_library(c_name.as_ptr() as *const _);
        if handle.is_none() {
            return Err("handle is invalid".into());
        }
        Ok(DllHelper{ handle: handle.unwrap(), free: false })
    }

    pub fn is_valid(&self) -> bool {
        !self.handle.handle.is_null() && self.handle.use_load && self.free
    }

    pub fn get_fn(&self, fn_name: &str) -> CommonResult<FARPROC> {
        let c_str = CString::new(fn_name)?;
        let func = unsafe {GetProcAddress(self.handle.handle, c_str.as_ptr() as _)};
        // println!("name: {} addr: {:?}",fn_name, func);
        if func.is_null() {
            Err(format!("func {} is invalid", fn_name).into())
        } else {
            Ok(func)
        }
    }
    pub fn get_fn_with_hash(&self, fn_name: &str) -> CommonResult<FARPROC> {

        let c_str = CString::new(fn_name)?;
        // let sum = crate::dll_helper::peb_lookup::calc_checksum( c_str.as_ptr() as *const u8, true);
        // let func = crate::dll_helper::peb_lookup::get_func_by_checksum(self.handle.handle, sum);
        let func = my_get_proc_address(self.handle.handle, c_str.as_ptr() as _);
        // let func = unsafe {GLOBAL_IAT.MyGetProcAddress.unwrap()(self.handle.handle, PCSTR::from_raw(c_str.as_ptr() as *const _))};
        // println!("name: {} addr: {:?}",fn_name, func);

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
            unsafe {
                let _ =GLOBAL_IAT.MyFreeLibrary.unwrap()(self.handle.handle);
            };
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
macro_rules! new_dll_test {
    ($dll_name:expr) => {{
        thread_helper::dll_helper::DllHelper::new(obfstr::obfstr!($dll_name))
    }};
}

#[macro_export]
macro_rules! get_dll_fn {
    ($dll:expr, $fn_name:expr, fn($($arg_type:ty),*) -> $ret_type:ty) => {{
          let proc = $dll.get_fn_with_hash(obfstr::obfstr!($fn_name));
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
          let proc = $dll.get_fn_with_hash(obfstr::obfstr!($fn_name));
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

