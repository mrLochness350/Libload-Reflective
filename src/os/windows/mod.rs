use std::{
    ffi::{c_void, OsString},
    fmt, io, marker,
    mem::size_of,
    os::{raw, windows::ffi::OsStringExt},
    ptr::read_unaligned,
};
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{GetLastError, FARPROC, HMODULE},
        System::{
            Diagnostics::Debug::{
                IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_BASERELOC,
                IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_SECTION_HEADER,
            },
            LibraryLoader::{GetModuleFileNameW, GetProcAddress, LoadLibraryA},
            Memory::{VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, PAGE_EXECUTE_READWRITE},
            SystemServices::{
                IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE,
                IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE,
                IMAGE_REL_BASED_ABSOLUTE,
            },
        },
    },
};

#[cfg(target_arch = "x86")]
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;

#[cfg(target_arch = "x86_64")]
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;

use crate::error::{self, ReflectError};
use crate::utils::cstr_cow_from_bytes;

#[cfg(target_arch = "x86")]
const NT_HEADER_SIZE: usize = core::mem::size_of::<IMAGE_NT_HEADERS32>();

#[cfg(target_arch = "x86_64")]
const NT_HEADER_SIZE: usize = core::mem::size_of::<IMAGE_NT_HEADERS64>();

pub struct Symbol<T> {
    pointer: FARPROC,
    pd: marker::PhantomData<T>,
}

impl<T> Symbol<Option<T>> {
    pub fn lift_option(self) -> Option<Symbol<T>> {
        if self.pointer.is_none() {
            None
        } else {
            Some(Symbol {
                pointer: self.pointer,
                pd: marker::PhantomData,
            })
        }
    }
}

impl<T> ::std::ops::Deref for Symbol<T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*((&self.pointer) as *const FARPROC as *const T) }
    }
}
impl<T> Symbol<T> {
    pub fn into_raw(self) -> FARPROC {
        self.pointer
    }
    pub fn as_raw_ptr(self) -> *mut raw::c_void {
        self.pointer
            .map(|raw| raw as *mut raw::c_void)
            .unwrap_or(std::ptr::null_mut())
    }
}
unsafe impl<T: Send> Send for Symbol<T> {}
unsafe impl<T: Sync> Sync for Symbol<T> {}

impl<T> Clone for Symbol<T> {
    fn clone(&self) -> Symbol<T> {
        Symbol { ..*self }
    }
}

impl<T> fmt::Debug for Symbol<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.pointer {
            None => f.write_str("Symbol@0x0"),
            Some(ptr) => f.write_str(&format!("Symbol@{:p}", ptr as *const ())),
        }
    }
}



#[derive(Clone)]
struct ExportedFunction {
    name: Vec<u8>,
    address: *const (),
}

#[derive(Clone)]
pub struct ReflectedLibrary {
    base_address: *mut c_void,
    exported_fns: Vec<ExportedFunction>,
}

fn get_nt_header(image: *const c_void, dos_header: *const IMAGE_DOS_HEADER) -> *const c_void {
    #[cfg(target_arch = "x86_64")]
    let nt_header =
        unsafe { (image as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64 };
    #[cfg(target_arch = "x86")]
    let nt_header =
        unsafe { (image as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS32 };
    if unsafe { (*nt_header).Signature } != IMAGE_NT_SIGNATURE {
        return core::ptr::null_mut();
    }
    nt_header as *const c_void
}

impl ReflectedLibrary {
    fn get_number_of_sections(&self, nt_header: *const c_void) -> u16 {
        #[cfg(target_arch = "x86_64")]
        return unsafe {
            (*(nt_header as *const IMAGE_NT_HEADERS64))
                .FileHeader
                .NumberOfSections
        };
        #[cfg(target_arch = "x86")]
        return unsafe {
            (*(nt_header as *const IMAGE_NT_HEADERS32))
                .FileHeader
                .NumberOfSections
        };
    }

    fn write_sections(
        &self,
        base_ptr: *const c_void,
        buffer: Vec<u8>,
        nt_header: *const c_void,
        dos_header: *const IMAGE_DOS_HEADER,
    ) {
        let num_of_sections = self.get_number_of_sections(nt_header);
        let e_lfanew = unsafe { (*dos_header).e_lfanew as usize };
        let mut section_header_start =
            (base_ptr as usize + e_lfanew + NT_HEADER_SIZE) as *const IMAGE_SECTION_HEADER;

        for _ in 0..num_of_sections {
            unsafe {
                let section_header = *section_header_start;
                let raw_data_start = section_header.PointerToRawData as usize;
                let raw_data_size = section_header.SizeOfRawData as usize;
                let virtual_address = section_header.VirtualAddress as usize;

                if let Some(section_data) =
                    buffer.get(raw_data_start..raw_data_start + raw_data_size)
                {
                    core::ptr::copy_nonoverlapping(
                        section_data.as_ptr() as *const c_void,
                        (base_ptr as usize + virtual_address) as *mut c_void,
                        raw_data_size,
                    );
                }

                section_header_start = section_header_start.add(1);
            }
        }
    }

    fn fix_base_relocations(&self, base_ptr: *const c_void, nt_header: *const c_void) {
        #[cfg(target_arch = "x86_64")]
        let nt_header = unsafe { &(*(nt_header as *const IMAGE_NT_HEADERS64)).OptionalHeader };
        #[cfg(target_arch = "x86")]
        let nt_header = unsafe { &(*(nt_header as *const IMAGE_NT_HEADERS32)).OptionalHeader };
        let base_reloc = &nt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC.0 as usize];
        if base_reloc.Size == 0 {
            return;
        }
        let image_base = nt_header.ImageBase;
        let delta = base_ptr as usize - image_base as usize;
        let mut reloc_ptr = (base_ptr as usize + base_reloc.VirtualAddress as usize)
            as *const IMAGE_BASE_RELOCATION;
        unsafe {
            while (*reloc_ptr).SizeOfBlock != 0 {
                let block_size = (*reloc_ptr).SizeOfBlock as usize;
                let entries = (block_size - size_of::<IMAGE_BASE_RELOCATION>()) / 2;
                let reloc_block_start = reloc_ptr as usize + size_of::<IMAGE_BASE_RELOCATION>();

                for i in 0..entries {
                    let reloc_offset_ptr = (reloc_block_start + i * 2) as *const u16;
                    let current_reloc_offset = *reloc_offset_ptr;
                    if (current_reloc_offset >> 12) != IMAGE_REL_BASED_ABSOLUTE as u16 {
                        let final_address = base_ptr as usize
                            + (*reloc_ptr).VirtualAddress as usize
                            + (current_reloc_offset & 0x0fff) as usize;

                        let original_address = core::ptr::read(final_address as *const usize);
                        let fixed_address = original_address.wrapping_add(delta);

                        core::ptr::write(final_address as *mut usize, fixed_address);
                    }
                }
                reloc_ptr =
                    (reloc_ptr as *const u8).add(block_size) as *const IMAGE_BASE_RELOCATION;
            }
        }
    }

    fn get_import_directory(&self, nt_header: *const c_void) -> IMAGE_DATA_DIRECTORY {
        #[cfg(target_arch = "x86_64")]
        let data_directory = unsafe {
            (*(nt_header as *const IMAGE_NT_HEADERS64))
                .OptionalHeader
                .DataDirectory
        };

        #[cfg(target_arch = "x86")]
        let data_directory = unsafe {
            (*(nt_header as *const IMAGE_NT_HEADERS32))
                .OptionalHeader
                .DataDirectory
        };

        data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize]
    }

    fn get_export_directory(&self) -> Option<*mut IMAGE_EXPORT_DIRECTORY> {
        unsafe {
            let dos_header = self.base_address as *mut IMAGE_DOS_HEADER;
            if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
                return None;
            }

            #[cfg(target_arch = "x86_64")]
            let nt_headers = (self.base_address as usize + (*dos_header).e_lfanew as usize)
                as *mut IMAGE_NT_HEADERS64;
            #[cfg(target_arch = "x86")]
            let nt_headers = (self.base_address as usize + (*dos_header).e_lfanew as usize)
                as *mut IMAGE_NT_HEADERS32;
            if (*nt_headers).Signature != IMAGE_NT_SIGNATURE as _ {
                return None;
            }

            let export_directory_va = (*nt_headers).OptionalHeader.DataDirectory
                [IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize]
                .VirtualAddress;

            if export_directory_va == 0 {
                return None;
            }

            Some(
                (self.base_address as usize + export_directory_va as usize)
                    as *mut IMAGE_EXPORT_DIRECTORY,
            )
        }
    }

    fn read_string_from_memory(&self, base_address: *const u8) -> String {
        let mut buf: Vec<u8> = vec![0; 100];
        let mut i = 0;
        while i < buf.capacity() {
            let _res = unsafe {
                core::ptr::copy_nonoverlapping(
                    (base_address as usize + i) as *const u8,
                    (buf.as_mut_ptr() as usize + i as usize) as *mut u8,
                    1,
                )
            };
            if buf[i as usize] == 0 {
                break;
            }
            i += 1;
        }
        String::from_utf8_lossy(&buf).to_string()
    }

    fn fix_import_table(
        &self,
        base_ptr: *const c_void,
        nt_header: *const c_void,
    ) -> Result<(), ReflectError> {
        let import_dir = self.get_import_directory(nt_header);
        if import_dir.Size == 0 {
            return Err(ReflectError::GenericError {
                fmt: "Invalid Import Dir Size".to_string(),
            });
        }

        let mut original_first_thunk_ptr = (base_ptr as usize + import_dir.VirtualAddress as usize)
            as *const IMAGE_IMPORT_DESCRIPTOR;

        unsafe {
            while (*original_first_thunk_ptr).Name != 0
                && (*original_first_thunk_ptr).FirstThunk != 0
            {
                let import_descriptor = read_unaligned(original_first_thunk_ptr);
                let dll_name = self.read_string_from_memory(
                    (base_ptr as usize + import_descriptor.Name as usize) as *const u8,
                );
                let dll_name_bytes = dll_name.as_bytes();
                let trimmed_dll_name: &[u8] = dll_name_bytes
                    .split(|&b| b == 0)
                    .next()
                    .unwrap_or(dll_name_bytes);

                let dll_name_cow = cstr_cow_from_bytes(trimmed_dll_name)?;
                let dll_ptr = PCSTR::from_raw(dll_name_cow.as_ptr().cast());
                let dll_handle = match LoadLibraryA(dll_ptr) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("Failed to load library for DLL: {e}, {}", GetLastError().0);
                        return Err(ReflectError::WindowsError {
                            source: error::WindowsError(io::Error::from_raw_os_error(e.code().0)),
                        });
                    }
                };
                let mut thunk_ptr = base_ptr as usize
                    + (import_descriptor.Anonymous.OriginalFirstThunk as usize
                        | import_descriptor.Anonymous.Characteristics as usize);
                let mut i = 0;

                while read_unaligned(thunk_ptr as *const usize) != 0 {
                    let offset = read_unaligned(thunk_ptr as *const usize);
                    let func_name_ptr = (base_ptr as usize + offset as usize + 2) as *const u8;
                    let func_name = self.read_string_from_memory(func_name_ptr);

                    if !func_name.is_empty() {
                        let func_address = {
                            let func_name = PCSTR::from_raw(func_name.as_bytes().as_ptr());
                            GetProcAddress(dll_handle, func_name)
                        };

                        if let Some(address) = func_address {
                            let func_addr_ptr = (base_ptr as usize
                                + import_descriptor.FirstThunk as usize
                                + i * core::mem::size_of::<usize>())
                                as *mut usize;

                            core::ptr::write(func_addr_ptr, address as usize);
                        }
                    }
                    i += 1;
                    thunk_ptr += size_of::<usize>();
                }
                original_first_thunk_ptr = original_first_thunk_ptr.add(1);
            }
        }

        Ok(())
    }

    pub unsafe fn new(buffer: Vec<u8>) -> Result<Self, ReflectError> {
        let dos_header = (buffer.as_ptr() as *const c_void) as *mut IMAGE_DOS_HEADER;
        let nt_header = get_nt_header(buffer.as_ptr() as *const c_void, dos_header);
        let header_size = (*(nt_header as *mut IMAGE_NT_HEADERS64))
            .OptionalHeader
            .SizeOfHeaders as usize;
        let image_size = (*(nt_header as *mut IMAGE_NT_HEADERS64))
            .OptionalHeader
            .SizeOfImage as usize;
        let base_ptr = VirtualAlloc(None, image_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        let mut lib = ReflectedLibrary {
            base_address: base_ptr,
            exported_fns: Vec::new(),
        };
        core::ptr::copy_nonoverlapping(buffer.as_ptr() as *const c_void, base_ptr, header_size);
        lib.write_sections(base_ptr, buffer, nt_header, dos_header);
        lib.fix_base_relocations(base_ptr, nt_header);
        lib.fix_import_table(base_ptr, nt_header)?;
        let export_dir = lib
            .get_export_directory()
            .ok_or(ReflectError::GenericError {
                fmt: "No Export Directory".to_string(),
            })?;
        lib.get_exports(export_dir);
        Ok(lib)
    }

    pub unsafe fn close(self) -> Result<(), ReflectError> {
        match VirtualFree(self.base_address, 0, MEM_RELEASE) {
            Ok(()) => {
                std::mem::forget(self);
                println!("Unloaded library");
                return Ok(());
            }
            Err(e) => {
                eprintln!("Failed to unload library: {}", e.message());
                return Err(ReflectError::WindowsError {
                    source: error::WindowsError(io::Error::from_raw_os_error(e.code().0)),
                });
            }
        }
    }

    pub unsafe fn get<T>(&self, name: &[u8]) -> Result<Symbol<T>, ReflectError> {
        let symbol = cstr_cow_from_bytes(name)?;
        let symbol_ptr = PCSTR::from_raw(symbol.as_ptr().cast());
        let symbol = GetProcAddress(HMODULE(self.base_address), symbol_ptr);
        if symbol.is_none() {
            if let Some(exported) = self.exported_fns.iter().find(|func| func.name == name) {
                let func_ptr = std::mem::transmute(exported.address);
                return Ok(Symbol {
                    pointer: func_ptr,
                    pd: marker::PhantomData,
                });
            } else {
                return Err(ReflectError::NoSymbol);
            }
        } else {
            return Ok(Symbol {
                pointer: symbol,
                pd: marker::PhantomData,
            });
        }
    }

    fn get_exports(&mut self, export_directory: *const IMAGE_EXPORT_DIRECTORY) {
        unsafe {
            let export_directory = *(export_directory);
            let func_rva_array = (self.base_address as usize
                + export_directory.AddressOfFunctions as usize)
                as *const u32;
            let name_rva_array = (self.base_address as usize
                + export_directory.AddressOfNames as usize)
                as *const u32;
            let ordinal_array = (self.base_address as usize
                + export_directory.AddressOfNameOrdinals as usize)
                as *const u16;
            let num_names = export_directory.NumberOfNames as usize;
            for i in 0..num_names {
                let name_rva = *name_rva_array.add(i) as usize;
                let name_ptr = (self.base_address as usize + name_rva) as *const u8;
                let func_name = self.read_string_from_memory(name_ptr);

                let ordinal_index = *ordinal_array.add(i) as usize;
                let func_rva = *func_rva_array.add(ordinal_index) as usize;
                let func_address = (self.base_address as usize + func_rva) as *const ();
                let trimmed_func_name = func_name
                    .as_bytes()
                    .split(|&b| b == 0)
                    .next()
                    .unwrap_or(func_name.as_bytes());
                self.exported_fns.push(ExportedFunction {
                    name: trimmed_func_name.to_vec(),
                    address: func_address,
                });
            }
        }
    }
}

impl fmt::Debug for ReflectedLibrary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            // FIXME: use Maybeuninit::uninit_array when stable
            let mut buf = Vec::with_capacity(1024);
            let len = GetModuleFileNameW(HMODULE(self.base_address), &mut buf) as usize;
            if len == 0 {
                f.write_str(&format!("Library@{:#x}", self.base_address as u8))
            } else {
                let string: OsString =
                    OsString::from_wide(&*(&buf[..len] as *const [_] as *const [u16]));
                f.write_str(&format!(
                    "Library@{:#x} from {:?}",
                    self.base_address as u8, string
                ))
            }
        }
    }
}
