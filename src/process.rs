use hashbrown::HashMap;
use thiserror::Error;

use windows::core::{BOOL, PWSTR};

use windows::Win32::Foundation::{CloseHandle, FALSE, HANDLE, HWND, LPARAM, TRUE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows::Win32::System::Memory::{PAGE_PROTECTION_FLAGS, VirtualProtectEx};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_CREATE_THREAD, PROCESS_NAME_FORMAT, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    QueryFullProcessImageNameW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId,
};

use crate::{pattern, util};

#[derive(Error, Debug)]
pub enum ModuleError {
    #[error("Module not found: {0}")]
    NotFound(String),
    #[error("Failed to create module snapshot for PID {0}")]
    ModuleSnapshotCreation(u32),
}

pub struct ModuleInfo {
    pub base: u64,
    pub size: u64,
    pub name: String,
}

pub trait ModuleOps {
    fn find_module_by_pid(pid: u32, module_name: Option<&str>) -> Result<ModuleInfo, ModuleError> {
        let snapshot =
            match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) }
            {
                Ok(s) => s,
                Err(_) => return Err(ModuleError::ModuleSnapshotCreation(pid)),
            };

        let mut module_entry: MODULEENTRY32W = unsafe { std::mem::zeroed() };
        module_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

        let mut base: u64 = 0;
        let mut size: u64 = 0;
        let target = module_name.map(|s| s.to_lowercase());

        if unsafe { Module32FirstW(snapshot, &mut module_entry) }.is_ok() {
            loop {
                if module_name.is_none() {
                    base = module_entry.modBaseAddr as u64;
                    size = module_entry.modBaseSize as u64;
                    break;
                }

                let name = util::wide_to_owned(&module_entry.szModule);
                if name.to_lowercase() == *target.as_ref().unwrap() {
                    base = module_entry.modBaseAddr as u64;
                    size = module_entry.modBaseSize as u64;
                    break;
                }

                if unsafe { Module32NextW(snapshot, &mut module_entry) }.is_err() {
                    break;
                }
            }
        }

        unsafe { _ = CloseHandle(snapshot) };

        if base == 0 {
            Err(ModuleError::NotFound(
                module_name.unwrap_or("<unknown>").to_string(),
            ))
        } else {
            Ok(ModuleInfo {
                base,
                size,
                name: util::wide_to_owned(&module_entry.szModule),
            })
        }
    }
}

#[derive(Error, Debug)]
pub enum ProcessError {
    #[error("Failed to open process with PID {0}")]
    ProcessOpen(u32),
    #[error("Process handle is not valid")]
    InvalidHandle,
    #[error("Failed to change memory protection at address 0x{0:X}")]
    ChangeProtection(u64),
    #[error("Failed to read memory at address 0x{0:X}")]
    MemoryRead(u64),
    #[error("Read {0} bytes, expected {1} bytes at address 0x{2:X}")]
    MismatchedReadSize(usize, usize, u64),
    #[error("Failed to write memory at address 0x{0:X}")]
    MemoryWrite(u64),
    #[error("Wrote {0} bytes, expected {1} bytes at address 0x{2:X}")]
    UnexpectedWriteSize(usize, usize, u64),
    #[error("Expected {0} bytes at address 0x{1:X}")]
    UnexpectedReadSize(usize, u64),
    #[error("Failed to create module snapshot for PID {0}")]
    ModuleSnapshotCreation(u32),
    #[error("Module not found: {0}")]
    ModuleNotFound(String),

    #[error(transparent)]
    PatternError(#[from] pattern::PatternError),
}

pub struct Process {
    pub handle: HANDLE,
    pub pid: u32,
    pub title: String,
    pub exe_name: String,
    valid: bool,
}

impl ModuleOps for Process {}

pub trait HasPid {
    fn pid(&self) -> u32;
}

impl HasPid for Process {
    fn pid(&self) -> u32 {
        self.pid
    }
}

impl Process {
    pub fn open(proc_info: ProcessInfo) -> Result<Process, ProcessError> {
        let access = PROCESS_VM_READ
            | PROCESS_VM_WRITE
            | PROCESS_VM_OPERATION
            | PROCESS_QUERY_INFORMATION
            | PROCESS_CREATE_THREAD;

        let handle = match unsafe { OpenProcess(access, false, proc_info.pid) } {
            Ok(h) => h,
            Err(_) => {
                return Err(ProcessError::ProcessOpen(proc_info.pid));
            }
        };

        if handle.is_invalid() {
            return Err(ProcessError::ProcessOpen(proc_info.pid));
        }

        Ok(Process {
            handle,
            pid: proc_info.pid,
            title: proc_info.title,
            exe_name: proc_info.exename,
            valid: true,
        })
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    pub fn close(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
        self.valid = false;
    }

    #[inline]
    pub fn ensure_valid(&self) -> Result<(), ProcessError> {
        if !self.valid || self.handle.is_invalid() {
            return Err(ProcessError::InvalidHandle);
        }

        Ok(())
    }

    pub fn find_module(&self, module_name: Option<&str>) -> Result<ModuleInfo, ModuleError> {
        Self::find_module_by_pid(self.pid, module_name)
    }

    pub fn change_protection(
        &self,
        address: u64,
        size: usize,
        new_protection_flags: PAGE_PROTECTION_FLAGS,
    ) -> Result<PAGE_PROTECTION_FLAGS, ProcessError> {
        self.ensure_valid()?;

        let mut old_protection = PAGE_PROTECTION_FLAGS(0u32);

        let result = unsafe {
            VirtualProtectEx(
                self.handle,
                address as *const _,
                size,
                new_protection_flags,
                &mut old_protection,
            )
        };

        if result.is_err() {
            return Err(ProcessError::ChangeProtection(address));
        }

        Ok(old_protection)
    }
}

struct ProcessCacheEntry {
    title: String,
    exename: String,
}

struct EnumContext {
    callback: EnumProcessCallback,
    pid_cache: HashMap<u32, ProcessCacheEntry>,
    buf: Vec<u16>,
    info: Option<ProcessInfo>,
}

pub struct ProcessInfo {
    pub pid: u32,
    pub title: String,
    pub exename: String,
}

pub type EnumProcessCallback = fn(u32, &str, &str) -> bool;

unsafe extern "system" fn enum_window(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let ctx_ptr = lparam.0 as *mut EnumContext;
    if ctx_ptr.is_null() {
        return TRUE;
    }

    let context: &mut EnumContext = unsafe { &mut *ctx_ptr };

    let mut pid = 0u32;
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };

    if pid == 0 {
        return TRUE;
    }

    // cached path
    if let Some(entry) = context.pid_cache.get(&pid) {
        if (context.callback)(pid, &entry.title, &entry.exename) {
            context.info = Some(ProcessInfo {
                pid,
                title: entry.title.clone(),
                exename: entry.exename.clone(),
            });
            return FALSE;
        }
        return TRUE;
    }

    let len = unsafe { GetWindowTextLengthW(hwnd) };
    if len == 0 {
        return TRUE;
    }

    let proc = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(h) => h,
        Err(_) => return TRUE,
    };

    let mut buf_size = context.buf.len() as u32;
    let buf_ptr = context.buf.as_mut_ptr();

    let query_result = unsafe {
        QueryFullProcessImageNameW(proc, PROCESS_NAME_FORMAT(0), PWSTR(buf_ptr), &mut buf_size)
    };

    if query_result.is_err() {
        let _ = unsafe { CloseHandle(proc) };
        return TRUE;
    }

    let slice = &context.buf[..buf_size as usize];
    let mut start = 0usize;
    for (i, &ch) in slice.iter().enumerate() {
        if ch == b'\\' as u16 || ch == b'/' as u16 {
            start = i + 1;
        }
    }

    let exename = util::wide_to_owned(&slice[start..]);

    let title = {
        let mut tbuf = vec![0u16; (len + 1) as usize];
        let copied = unsafe { GetWindowTextW(hwnd, tbuf.as_mut_slice()) };
        if copied == 0 {
            String::new()
        } else {
            util::wide_to_owned(&tbuf)
        }
    };

    context.pid_cache.insert(
        pid,
        ProcessCacheEntry {
            title: title.clone(),
            exename: exename.clone(),
        },
    );

    let _ = unsafe { CloseHandle(proc) };

    TRUE
}

/// ### Arguments
/// * `callback` - Filter function called for each window and recieves params `(pid, title, exename)`.
///
pub fn find_process(callback: EnumProcessCallback) -> Option<ProcessInfo> {
    let mut context = EnumContext {
        callback,
        pid_cache: HashMap::new(),
        buf: vec![0u16; 260],
        info: None,
    };

    unsafe {
        let _ = EnumWindows(Some(enum_window), LPARAM(&mut context as *mut _ as isize));
    }

    context.info
}
