use hashbrown::HashMap;

use windows::{
    Win32::{
        Foundation::{CloseHandle, FALSE, HWND, LPARAM, TRUE},
        System::Threading::{
            OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW,
        },
        UI::WindowsAndMessaging::{
            EnumWindows, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId,
        },
    },
    core::{BOOL, PWSTR},
};

use crate::util;

type Pid = u32;

struct ProcessCacheEntry {
    title: String,
    exename: String,
}

struct EnumContext {
    callback: EnumProcessCallback,
    pid_cache: HashMap<Pid, ProcessCacheEntry>,
    buf: Vec<u16>,
    info: Option<ProcessInfo>,
}

pub struct ProcessInfo {
    pub pid: Pid,
    pub title: String,
    pub exename: String,
}

pub type EnumProcessCallback = fn(Pid, &str, &str) -> bool;

unsafe extern "system" fn enum_window(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let ctx_ptr = lparam.0 as *mut EnumContext;
    if ctx_ptr.is_null() {
        return TRUE;
    }

    let context: &mut EnumContext = unsafe { &mut *ctx_ptr };

    let mut pid: Pid = 0;
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
