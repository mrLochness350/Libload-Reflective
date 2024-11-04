use libc::{
    c_char, dladdr, dlclose, dlerror, dlopen, dlsym,  memfd_create, Dl_info, RTLD_NOW
};
use std::{
    ffi::{c_int, CStr, CString},
    fmt,
    fs::File,
    io::Write,
    marker, mem,
    os::{fd::FromRawFd, raw::{self}},
};

use crate::{error::ReflectError, utils::cstr_cow_from_bytes};
pub struct ReflectedLibrary {
    handle: *mut raw::c_void,
}

unsafe impl Send for ReflectedLibrary {}
unsafe impl Sync for ReflectedLibrary {}

pub struct Symbol<T> {
    pointer: *mut raw::c_void,
    pd: marker::PhantomData<T>,
}

impl<T> Symbol<T> {
    pub fn into_raw(self) -> *mut raw::c_void {
        self.pointer
    }

    pub fn as_raw_ptr(self) -> *mut raw::c_void {
        self.pointer
    }
}

impl<T> Symbol<Option<T>> {
    pub fn lift_option(self) -> Option<Symbol<T>> {
        if self.pointer.is_null() {
            None
        } else {
            Some(Symbol {
                pointer: self.pointer,
                pd: marker::PhantomData,
            })
        }
    }
}

unsafe impl<T: Send> Send for Symbol<T> {}
unsafe impl<T: Sync> Sync for Symbol<T> {}

impl<T> Clone for Symbol<T> {
    fn clone(&self) -> Symbol<T> {
        Symbol { ..*self }
    }
}

impl<T> ::std::ops::Deref for Symbol<T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*(&self.pointer as *const *mut _ as *const T) }
    }
}

impl<T> fmt::Debug for Symbol<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            let mut info = mem::MaybeUninit::<Dl_info>::uninit();
            if dladdr(self.pointer, info.as_mut_ptr()) != 0 {
                let info = info.assume_init();
                if info.dli_sname.is_null() {
                    f.write_str(&format!(
                        "Symbol@{:p} from {:?}",
                        self.pointer,
                        CStr::from_ptr(info.dli_fname)
                    ))
                } else {
                    f.write_str(&format!(
                        "Symbol {:?}@{:p} from {:?}",
                        CStr::from_ptr(info.dli_sname),
                        self.pointer,
                        CStr::from_ptr(info.dli_fname)
                    ))
                }
            } else {
                f.write_str(&format!("Symbol@{:p}", self.pointer))
            }
        }
    }
}

unsafe fn open_anonymous_fd() -> Result<c_int, ReflectError> {
    let name = cstr_cow_from_bytes(b"")?;
    let fd = memfd_create(name.as_ptr() as *const _, 0);
    if fd == -1 {
        return Err(ReflectError::GenericError {
            fmt: format!("Invalid File Descriptor: {}", fd),
        });
    }
    Ok(fd as c_int)
}

unsafe fn write_to_fd(bytes: Vec<u8>, fd: c_int) -> Result<(), ReflectError> {
    let mut file = File::from_raw_fd(fd);
    file.write_all(&bytes).expect("Failed to write bytes to fd");
    mem::forget(file);
    Ok(())
}

unsafe fn open_fd(fd: c_int) -> Result<*mut raw::c_void, ReflectError> {
    let fd_path = format!("/proc/self/fd/{fd}");
    let cstr = match CString::new(fd_path) {
        Ok(s) => s,
        Err(e) => return Err(ReflectError::InvalidCString { source: e }),
    };
    let ptr = cstr.as_ptr();
    let handle = dlopen(ptr, RTLD_NOW);
    if handle.is_null() {
        let err = dlerror();
        let str = CStr::from_ptr(err);
        println!("Dl Error: {}", str.to_string_lossy());
        return Err(ReflectError::GenericError {
            fmt: format!("dlopen handle was Null"),
        });
    };
    println!("Opened handle to library");
    Ok(handle)
}



impl ReflectedLibrary {
    
    #[inline]
    pub unsafe fn new(bytes: Vec<u8>) -> Result<ReflectedLibrary, ReflectError> {
        let a_fd = open_anonymous_fd()?;
        write_to_fd(bytes, a_fd)?;
        let handle = open_fd(a_fd)?;
        Ok(Self { handle })
    }
    unsafe fn get_impl<T>(&self, symbol: &[u8]) -> Result<Symbol<T>, ReflectError>
    {
        let symbol = cstr_cow_from_bytes(symbol)?;
        let symbol_ptr = dlsym(self.handle, symbol.as_ptr() as *const c_char);
        if symbol_ptr.is_null() {
            return Err(ReflectError::GenericError { fmt: format!("Undefined symbol '{}'",symbol.to_string_lossy()) });
        };
        Ok(Symbol {
            pointer: symbol_ptr,
            pd: marker::PhantomData
        })
    }
    #[inline(always)]
    unsafe fn get_singlethreaded<T>(&self, symbol: &[u8]) -> Result<Symbol<T>, ReflectError> {
        self.get_impl(symbol).map_err(|e| e)
    }

    #[inline(always)]
    pub unsafe fn get<T>(&self, symbol: &[u8]) -> Result<Symbol<T>, ReflectError> {
        extern crate cfg_if;
        cfg_if::cfg_if! {
            if #[cfg(any(
                target_os = "linux",
                target_os = "android",
                target_os = "openbsd",
                target_os = "macos",
                target_os = "ios",
                target_os = "solaris",
                target_os = "illumos",
                target_os = "redox",
                target_os = "fuchsia",

            ))] {
                self.get_singlethreaded(symbol)
            } else {
                self.get_impl(symbol, || Err(ReflectError::DlSymUnknown))
            }
        }
    }

    pub fn into_raw(self) -> *mut raw::c_void {
        let handle = self.handle;
        mem::forget(self);
        handle
    }

    pub unsafe fn from_raw(handle: *mut raw::c_void) -> ReflectedLibrary {
        ReflectedLibrary { handle }
    }
}

impl Drop for ReflectedLibrary {
    fn drop(&mut self) {
        unsafe {
            dlclose(self.handle);
        }
    }
}

impl fmt::Debug for ReflectedLibrary {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&format!("Library@{:p}", self.handle))
    }
}
