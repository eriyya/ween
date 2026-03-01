pub mod dll;
pub mod enumerate;
pub mod pattern;
mod util;

use thiserror::Error;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows::Win32::System::Memory::{
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtectEx,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE,
};

use crate::pattern::Pattern;

type Pid = u32;

mod sealed {
    pub trait Sealed {}

    impl Sealed for u8 {}
    impl Sealed for u16 {}
    impl Sealed for u32 {}
    impl Sealed for u64 {}
    impl Sealed for i8 {}
    impl Sealed for i16 {}
    impl Sealed for i32 {}
    impl Sealed for i64 {}
}

pub trait MemoryValue: sealed::Sealed + Copy {
    const SIZE: usize;

    fn from_le_slice(bytes: &[u8], address: u64) -> Result<Self, ProcessError>;
}

macro_rules! impl_memory_value {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl MemoryValue for $ty {
                const SIZE: usize = std::mem::size_of::<$ty>();

                fn from_le_slice(bytes: &[u8], address: u64) -> Result<Self, ProcessError> {
                    let arr: [u8; std::mem::size_of::<$ty>()] = bytes
                        .try_into()
                        .map_err(|_| {
                            ProcessError::UnexpectedReadSize(std::mem::size_of::<$ty>(), address)
                        })?;
                    Ok(<$ty>::from_le_bytes(arr))
                }
            }
        )+
    };
}

impl_memory_value!(u8, u16, u32, u64, i8, i16, i32, i64);

// Process implementation

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
    pub pid: Pid,
    pub title: String,
    pub exe_name: String,
    valid: bool,
}

impl Process {
    pub fn open(proc_info: enumerate::ProcessInfo) -> Result<Process, ProcessError> {
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

    #[inline]
    fn ensure_valid(&self) -> Result<(), ProcessError> {
        if !self.valid {
            return Err(ProcessError::InvalidHandle);
        }

        if self.handle.is_invalid() {
            return Err(ProcessError::InvalidHandle);
        }

        Ok(())
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

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    pub fn close(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
        self.valid = false;
    }

    // Memory reading/writing

    pub fn read_bytes(&self, address: u64, size: usize) -> Result<Vec<u8>, ProcessError> {
        self.ensure_valid()?;

        if size == 0 {
            return Ok(vec![]);
        }

        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0usize;

        let read_ok = unsafe {
            ReadProcessMemory(
                self.handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                size,
                Some(&mut bytes_read),
            )
        };

        if read_ok.is_err() {
            return Err(ProcessError::MemoryRead(address));
        }

        if bytes_read != size {
            return Err(ProcessError::MismatchedReadSize(bytes_read, size, address));
        }

        Ok(buffer)
    }

    pub fn read<T: MemoryValue>(&self, address: u64) -> Result<T, ProcessError> {
        let bytes = self.read_bytes(address, T::SIZE)?;
        T::from_le_slice(&bytes, address)
    }

    pub fn resolve_rip_relative_address(
        &self,
        instruction_addr: u64,
        displacement_offset: u64,
        instruction_size: u64,
    ) -> Result<u64, ProcessError> {
        let rip_offset = self.read::<i32>(instruction_addr + displacement_offset)?;
        if rip_offset >= 0 {
            Ok(instruction_addr + instruction_size + rip_offset as u64)
        } else {
            Ok((instruction_addr + instruction_size).wrapping_sub((-rip_offset) as u64))
        }
    }

    pub fn resolve_rip_relative_pointer(
        &self,
        instruction_addr: u64,
        displacement_offset: u64,
        instruction_size: u64,
    ) -> Result<u64, ProcessError> {
        let ptr_addr = self.resolve_rip_relative_address(
            instruction_addr,
            displacement_offset,
            instruction_size,
        )?;
        self.read::<u64>(ptr_addr)
    }

    pub fn write_bytes(&self, address: u64, data: &[u8]) -> Result<(), ProcessError> {
        self.ensure_valid()?;

        if data.is_empty() {
            return Ok(());
        }

        let old_protect = self.change_protection(address, data.len(), PAGE_EXECUTE_READWRITE)?;

        let mut bytes_written = 0usize;

        let write_ok = unsafe {
            WriteProcessMemory(
                self.handle,
                address as *mut _,
                data.as_ptr() as *const _,
                data.len(),
                Some(&mut bytes_written),
            )
            .is_ok()
        };

        _ = self.change_protection(address, data.len(), old_protect)?;

        if !write_ok {
            return Err(ProcessError::MemoryWrite(address));
        }

        if bytes_written != data.len() {
            return Err(ProcessError::UnexpectedWriteSize(
                bytes_written,
                data.len(),
                address,
            ));
        }

        Ok(())
    }

    pub fn find_module(&self, module_name: Option<&str>) -> Result<(u64, u64), ProcessError> {
        self.ensure_valid()?;

        let snapshot = match unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid)
        } {
            Ok(s) => s,
            Err(_) => return Err(ProcessError::ModuleSnapshotCreation(self.pid)),
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

        Ok((base, size))
    }

    pub fn aob_scan(
        &self,
        module: Option<&str>,
        pattern: &str,
        offset: u64,
    ) -> Result<u64, ProcessError> {
        self.ensure_valid()?;

        let p = Pattern::new(pattern)?;

        let (module_base, module_size) = self.find_module(module)?;

        if module_base == 0 || module_size == 0 {
            return Err(ProcessError::ModuleNotFound(
                module.unwrap_or("<main module>").to_string(),
            ));
        }

        const CHUNK_SIZE: usize = 0x1000;

        for addr in (module_base..module_base + module_size).step_by(CHUNK_SIZE) {
            let size = std::cmp::min(CHUNK_SIZE as u64, module_base + module_size - addr) as usize;
            let chunk = self.read_bytes(addr, size)?;

            if chunk.len() < p.pattern.len() {
                continue;
            }

            for i in 0..=chunk.len() - p.pattern.len() {
                if p.matches(&chunk[i..]) {
                    return Ok(addr + i as u64 + offset);
                }
            }
        }

        Ok(0)
    }
}
