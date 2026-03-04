use thiserror::Error;
use windows::Win32::System::{
    Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
    Memory::PAGE_EXECUTE_READWRITE,
};

use crate::{
    pattern::Pattern,
    process::{HasPid, ModuleError, ModuleOps, Process},
};

#[derive(Error, Debug)]
pub enum MemoryError {
    #[error("Failed to read memory at address {0:#x}")]
    MemoryRead(u64),
    #[error("Failed to write memory at address {0:#x}")]
    UnexpectedReadSize(usize, u64),
    #[error("Read {0} bytes, expected {1} bytes at address 0x{2:X}")]
    MismatchedReadSize(usize, usize, u64),
    #[error("Failed to write memory at address 0x{0:X}")]
    MemoryWrite(u64),
    #[error("Wrote {0} bytes, expected {1} bytes at address 0x{2:X}")]
    UnexpectedWriteSize(usize, usize, u64),
    #[error("Invalid handle for process")]
    InvalidHandle,
    #[error("Failed to change memory protection at address 0x{0:X}")]
    ChangeProtection(u64),

    #[error(transparent)]
    PatternError(#[from] crate::pattern::PatternError),

    #[error(transparent)]
    ModuleError(#[from] crate::process::ModuleError),
}

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

    fn from_le_slice(bytes: &[u8], address: u64) -> Result<Self, MemoryError>;
}

macro_rules! impl_memory_value {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl MemoryValue for $ty {
                const SIZE: usize = std::mem::size_of::<$ty>();

                fn from_le_slice(bytes: &[u8], address: u64) -> Result<Self, MemoryError> {
                    let arr: [u8; std::mem::size_of::<$ty>()] = bytes
                        .try_into()
                        .map_err(|_| {
                            MemoryError::UnexpectedReadSize(std::mem::size_of::<$ty>(), address)
                        })?;
                    Ok(<$ty>::from_le_bytes(arr))
                }
            }
        )+
    };
}

impl_memory_value!(u8, u16, u32, u64, i8, i16, i32, i64);

pub trait MemoryOps {
    fn read_bytes<E>(&self, address: u64, size: usize) -> Result<Vec<u8>, E>
    where
        E: From<MemoryError>;

    fn write_bytes(&self, address: u64, data: &[u8]) -> Result<(), MemoryError>;

    fn read<T: MemoryValue>(&self, address: u64) -> Result<T, MemoryError> {
        let bytes = self.read_bytes::<MemoryError>(address, T::SIZE)?;
        T::from_le_slice(&bytes, address)
    }

    fn resolve_rip_relative_address(
        &self,
        instr_addr: u64,
        disp_offset: u64,
        instr_size: u64,
    ) -> Result<u64, MemoryError> {
        let rip_offset = self.read::<i32>(instr_addr + disp_offset)?;
        if rip_offset >= 0 {
            Ok(instr_addr + instr_size + rip_offset as u64)
        } else {
            Ok((instr_addr + instr_size).wrapping_sub((-rip_offset) as u64))
        }
    }

    fn resolve_rip_relative_pointer(
        &self,
        instr_addr: u64,
        disp_offset: u64,
        instr_size: u64,
    ) -> Result<u64, MemoryError> {
        let addr = self.resolve_rip_relative_address(instr_addr, disp_offset, instr_size)?;
        self.read::<u64>(addr)
    }

    fn aob_scan(&self, module: Option<&str>, pattern: &str, offset: u64) -> Result<u64, MemoryError>
    where
        Self: ModuleOps + HasPid,
    {
        let p = Pattern::new(pattern)?;

        let minfo = Self::find_module_by_pid(self.pid(), module)?;

        if minfo.base == 0 || minfo.size == 0 {
            let err_msg = module.unwrap_or("<unknown>").to_string();
            return Err(MemoryError::ModuleError(ModuleError::NotFound(err_msg)));
        }

        const CHUNK_SIZE: usize = 0x1000;

        for addr in (minfo.base..minfo.base + minfo.size).step_by(CHUNK_SIZE) {
            let size = std::cmp::min(CHUNK_SIZE as u64, minfo.base + minfo.size - addr) as usize;
            let chunk = self.read_bytes::<MemoryError>(addr, size)?;

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

impl MemoryOps for Process {
    fn read_bytes<E>(&self, address: u64, size: usize) -> Result<Vec<u8>, E>
    where
        E: From<MemoryError>,
    {
        self.ensure_valid()
            .map_err(|_| MemoryError::InvalidHandle)?;

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
            return Err(MemoryError::MemoryRead(address).into());
        }

        if bytes_read != size {
            return Err(MemoryError::MismatchedReadSize(bytes_read, size, address).into());
        }

        Ok(buffer)
    }

    fn write_bytes(&self, address: u64, data: &[u8]) -> Result<(), MemoryError> {
        self.ensure_valid()
            .map_err(|_| MemoryError::InvalidHandle)?;

        if data.is_empty() {
            return Ok(());
        }

        let old_protect = self
            .change_protection(address, data.len(), PAGE_EXECUTE_READWRITE)
            .map_err(|_| MemoryError::ChangeProtection(address))?;

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

        _ = self
            .change_protection(address, data.len(), old_protect)
            .map_err(|_| MemoryError::ChangeProtection(address))?;

        if !write_ok {
            return Err(MemoryError::MemoryWrite(address));
        }

        if bytes_written != data.len() {
            return Err(MemoryError::UnexpectedWriteSize(
                bytes_written,
                data.len(),
                address,
            ));
        }

        Ok(())
    }
}
