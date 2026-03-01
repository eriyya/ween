use crate::{Process, util};
use thiserror::Error;
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx};

/// Defines the Windows `DllMain` entrypoint and injects the provided block.
///
/// The block is inserted directly into `DllMain`.
///
/// For access to entrypoint arguments, use the parameterized form:
/// `dll_main!(|hinstance, reason, reserved| { ... })`.
/// The generated argument types are:
/// - `hinstance: *mut c_void`
/// - `reason: u32`
/// - `reserved: *mut c_void`
///
/// The generated function returns `BOOL(1)` unless the block returns early.
///
/// # Example
/// ```
/// use process::dll_main;
///
/// dll_main!(|_hinstance, reason, _reserved| {
///     if reason == 1 {
///         // DLL_PROCESS_ATTACH
///     }
/// });
/// ```
#[macro_export]
macro_rules! dll_main {
    ($body:block) => {
        $crate::dll_main!(|_hinstance, _reason, _reserved| $body);
    };
    (|$hinstance:ident, $reason:ident, $reserved:ident| $body:block) => {
        #[allow(non_snake_case)]
        #[unsafe(no_mangle)]
        pub extern "system" fn DllMain(
            $hinstance: *mut ::core::ffi::c_void,
            $reason: u32,
            $reserved: *mut ::core::ffi::c_void,
        ) -> i32 {
            $body
            1
        }
    };
}

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
