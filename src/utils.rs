use std::{borrow::Cow, ffi::{CStr, CString}, os::raw};

use crate::error::ReflectError;

pub fn cstr_cow_from_bytes(slice: &[u8]) -> Result<Cow<'_, CStr>, ReflectError> {
    static ZERO: raw::c_char = 0;
    Ok(match slice.last() {
        None => unsafe { Cow::Borrowed(CStr::from_ptr(&ZERO)) },
        Some(&0) => Cow::Borrowed(
            CStr::from_bytes_with_nul(slice)
                .map_err(|source| ReflectError::CStringWithTrailing { source })?,
        ),
        Some(_) => Cow::Owned(
            CString::new(slice).map_err(|source| ReflectError::InvalidCString { source })?,
        ),
    })
}