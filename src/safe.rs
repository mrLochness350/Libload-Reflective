

use std::{fmt, marker, ops, os::raw};

use crate::{error::ReflectError, os};
#[cfg(target_os="linux")]
use super::os::linux as imp;


#[cfg(target_os="windows")]
use super::os::windows as imp;

pub struct ReflectedLibrary(imp::ReflectedLibrary);
impl ReflectedLibrary {
    pub  fn new(buffer: Vec<u8>) -> Result<ReflectedLibrary, ReflectError> {
        unsafe { imp::ReflectedLibrary::new(buffer).map(From::from) }
    }

    pub fn get<'lib, T>(&'lib self, symbol: &[u8]) ->Result<Symbol<'lib, T>, ReflectError> {
        unsafe {self.0.get(symbol).map(|from| Symbol::from_raw(from,self)) }
    }
    pub fn close(self) -> Result<(), ReflectError> {
        unsafe { self.0.close() }
    }
}

#[cfg(target_os = "windows")]
impl From<os::windows::ReflectedLibrary> for ReflectedLibrary {
    fn from(lib: os::windows::ReflectedLibrary) -> Self {
        ReflectedLibrary(lib)
    }
}

#[cfg(target_os = "linux")]
impl From<os::linux::ReflectedLibrary> for ReflectedLibrary {
    fn from(lib: os::linux::ReflectedLibrary) -> Self {
        ReflectedLibrary(lib)
    }
}

impl fmt::Debug for ReflectedLibrary {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}


impl From<ReflectedLibrary> for imp::ReflectedLibrary {
    fn from(lib: ReflectedLibrary) -> imp::ReflectedLibrary {
        lib.0
    }
}

unsafe impl Send for ReflectedLibrary {}
unsafe impl Sync for ReflectedLibrary {}

pub struct Symbol<'lib, T: 'lib> {
    inner: imp::Symbol<T>,
    pd: marker::PhantomData<&'lib T>,
}

impl<'lib, T> Symbol<'lib, T> {
    pub unsafe fn into_raw(self) -> imp::Symbol<T> {
        self.inner
    }
    pub unsafe fn from_raw<L>(sym: imp::Symbol<T>, library: &'lib L) -> Symbol<'lib, T> {
        let _ = library; // ignore here for documentation purposes.
        Symbol {
            inner: sym,
            pd: marker::PhantomData,
        }
    }
    pub unsafe fn try_as_raw_ptr(self) -> Option<*mut raw::c_void> {
        Some(
            #[allow(unused_unsafe)] // 1.56.0 compat
            unsafe {
                // SAFE: the calling function has the same soundness invariants as this callee.
                self.into_raw()
            }
            .as_raw_ptr(),
        )
    }
}

impl<'lib, T> Symbol<'lib, Option<T>> {

    pub fn lift_option(self) -> Option<Symbol<'lib, T>> {
        self.inner.lift_option().map(|is| Symbol {
            inner: is,
            pd: marker::PhantomData,
        })
    }
}

impl<'lib, T> Clone for Symbol<'lib, T> {
    fn clone(&self) -> Symbol<'lib, T> {
        Symbol {
            inner: self.inner.clone(),
            pd: marker::PhantomData,
        }
    }
}

// FIXME: implement FnOnce for callable stuff instead.
impl<'lib, T> ops::Deref for Symbol<'lib, T> {
    type Target = T;
    fn deref(&self) -> &T {
        ops::Deref::deref(&self.inner)
    }
}

impl<'lib, T> fmt::Debug for Symbol<'lib, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(f)
    }
}

unsafe impl<'lib, T: Send> Send for Symbol<'lib, T> {}
unsafe impl<'lib, T: Sync> Sync for Symbol<'lib, T> {}