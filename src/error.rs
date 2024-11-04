use std::{ffi::{CStr, CString, FromBytesWithNulError, NulError}, io::Error};


pub struct DlDescrption(pub(crate) CString);

impl std::fmt::Debug for DlDescrption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl From<&CStr> for DlDescrption {
    fn from(value: &CStr) -> Self {
        Self(value.into())
    }
}

pub struct WindowsError(pub(crate) std::io::Error);
impl std::fmt::Debug for WindowsError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}
#[derive(Debug)]
pub enum ReflectError {
    InvalidCString{
        source: NulError,
    },
    WindowsError {
        source: WindowsError
    },
    CStringWithTrailing{ 
        source:FromBytesWithNulError,
    },
    GenericError{
        fmt: String
    },
    NoSymbol,
    IoError{
        source: Error
    },
    DlOpen {
        desc: DlDescrption
    },
    DlOpenUnknown,
    DlSym {
        desc: DlDescrption
    },
    DlSymUnknown,
    DlClose {
        desc: DlDescrption,
    },
    DlCloseUnknown


}

impl std::error::Error for ReflectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ReflectError::*;
        match *self {
            InvalidCString { ref source } => Some(source),
            WindowsError { ref source } => Some(&source.0),
            CStringWithTrailing { ref source } => Some(source),
            IoError { ref source} => Some(source),
            _=> None,      
        }
    }
}

impl std::fmt::Display for ReflectError{ 
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ReflectError::*;
        match *self {
            InvalidCString { .. } => write!(f,"could not create a C string from bytes"),
            WindowsError { .. } => write!(f,"Unknown Windows error has occured"),
            CStringWithTrailing { .. } => write!(f,"could not create a C string from bytes with trailing null"),
            GenericError { ..} => write!(f,"A Generic Error has occured"),
            NoSymbol => write!(f,"The given symbol was not found"),
            IoError { .. } => write!(f, "IO Error has occured"),
            DlOpen {ref desc} => write!(f, "{}", desc.0.to_string_lossy()),
            DlSym { ref desc } => write!(f, "{}", desc.0.to_string_lossy()),
            DlOpenUnknown => write!(f, "DlOpen failed, but the system did not report the error"),
            DlSymUnknown => write!(f, "DlSym failed, but the system did not report the error"),
            DlClose { ref desc } => write!(f, "{}",desc.0.to_string_lossy()),
            DlCloseUnknown => write!(f, "DlClose failed, but the system did not report the error")
        }
    }
}