use crate::{Process, util};
use core::ffi::c_void;
use thiserror::Error;
use windows::Win32::Foundation::{CloseHandle, WAIT_FAILED};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, INFINITE, LPTHREAD_START_ROUTINE, WaitForSingleObject,
};
use windows::core::{s, w};

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
    fn eject_dll(&self, dll_module: u32) -> Result<(), DllError>;
}

impl DllOps for Process {
    fn load_dll(&self, path: &str) -> Result<(), DllError> {
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

        let mut bytes_written = 0usize;
        let write_result = unsafe {
            WriteProcessMemory(
                self.handle,
                remote_addr,
                dll_path.as_ptr() as *const c_void,
                alloc_size,
                Some(&mut bytes_written),
            )
        };

        if write_result.is_err() || bytes_written != alloc_size {
            unsafe {
                let _ = VirtualFreeEx(self.handle, remote_addr, 0, MEM_RELEASE);
            }
            return Err(DllError::DllLoad("WriteProcessMemory failed".to_string()));
        }

        let kernel32 = unsafe { GetModuleHandleW(w!("kernel32.dll")) }
            .map_err(|_| DllError::DllLoad("GetModuleHandleW(kernel32.dll) failed".to_string()))?;

        let load_library_addr = unsafe { GetProcAddress(kernel32, s!("LoadLibraryW")) }
            .ok_or_else(|| DllError::DllLoad("GetProcAddress(LoadLibraryW) failed".to_string()))?;

        let load_library: LPTHREAD_START_ROUTINE = Some(unsafe {
            std::mem::transmute::<
                unsafe extern "system" fn() -> isize,
                unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
            >(load_library_addr)
        });

        let remote_thread = unsafe {
            CreateRemoteThread(
                self.handle,
                None,
                0,
                load_library,
                Some(remote_addr),
                Default::default(),
                None,
            )
        }
        .map_err(|_| DllError::DllLoad("CreateRemoteThread failed".to_string()))?;

        let wait_result = unsafe { WaitForSingleObject(remote_thread, INFINITE) };

        if wait_result == WAIT_FAILED {
            unsafe {
                let _ = CloseHandle(remote_thread);
                let _ = VirtualFreeEx(self.handle, remote_addr, 0, MEM_RELEASE);
            }
            return Err(DllError::DllLoad("WaitForSingleObject failed".to_string()));
        }

        let mut remote_module = 0u32;
        let exit_code_result = unsafe { GetExitCodeThread(remote_thread, &mut remote_module) };

        unsafe {
            let _ = CloseHandle(remote_thread);
            let _ = VirtualFreeEx(self.handle, remote_addr, 0, MEM_RELEASE);
        }

        if exit_code_result.is_err() || remote_module == 0 {
            return Err(DllError::DllLoad(
                "LoadLibraryW failed in remote process".to_string(),
            ));
        }

        Ok(())
    }

    fn eject_dll(&self, dll_module: u32) -> Result<(), DllError> {
        self.ensure_valid()?;

        if dll_module == 0 {
            return Err(DllError::DllLoad(
                "Invalid DLL module handle (0)".to_string(),
            ));
        }

        let kernel32 = unsafe { GetModuleHandleW(w!("kernel32.dll")) }
            .map_err(|_| DllError::DllLoad("GetModuleHandleW(kernel32.dll) failed".to_string()))?;

        let free_library_addr = unsafe { GetProcAddress(kernel32, s!("FreeLibrary")) }
            .ok_or_else(|| DllError::DllLoad("GetProcAddress(FreeLibrary) failed".to_string()))?;

        let free_library: LPTHREAD_START_ROUTINE = Some(unsafe {
            std::mem::transmute::<
                unsafe extern "system" fn() -> isize,
                unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
            >(free_library_addr)
        });

        let remote_thread = unsafe {
            CreateRemoteThread(
                self.handle,
                None,
                0,
                free_library,
                Some(dll_module as usize as *mut c_void),
                Default::default(),
                None,
            )
        }
        .map_err(|_| DllError::DllLoad("CreateRemoteThread failed".to_string()))?;

        let wait_result = unsafe { WaitForSingleObject(remote_thread, INFINITE) };

        if wait_result == WAIT_FAILED {
            unsafe {
                let _ = CloseHandle(remote_thread);
            }
            return Err(DllError::DllLoad("WaitForSingleObject failed".to_string()));
        }

        let mut free_library_result = 0u32;
        let exit_code_result =
            unsafe { GetExitCodeThread(remote_thread, &mut free_library_result) };

        unsafe {
            let _ = CloseHandle(remote_thread);
        }

        if exit_code_result.is_err() || free_library_result == 0 {
            return Err(DllError::DllLoad(
                "FreeLibrary failed in remote process".to_string(),
            ));
        }

        Ok(())
    }
}
