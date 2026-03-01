use crate::{Process, util};
use thiserror::Error;
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx};

#[derive(Error, Debug)]
pub enum DllError {
    #[error("Virtual alloc failed")]
    VirtualAlloc,
    #[error("Failed to load DLL: {0}")]
    DllLoad(String),

    #[error(transparent)]
    ProcessError(#[from] crate::ProcessError),
}

pub trait DllOps {
    fn load_dll(&self, path: &str) -> Result<(), DllError>;
}

impl DllOps for Process {
    fn load_dll(&self, path: &str) -> Result<(), DllError> {
        unimplemented!("DLL injection is not implemented yet");

        self.ensure_valid()?;

        let dll_path = util::to_wide(path);
        let alloc_size = dll_path.len() * std::mem::size_of::<u16>();

        let remote_addr = unsafe {
            VirtualAllocEx(
                self.handle,
                None,
                alloc_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };

        if remote_addr.is_null() {
            return Err(DllError::VirtualAlloc);
        }

        // TODO: continue with WriteProcessMemory

        Ok(())
    }
}
