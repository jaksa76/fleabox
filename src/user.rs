use std::{
    ffi::{CStr, CString},
    path::PathBuf,
};

// User info extracted from getpwnam
#[derive(Clone)]
pub(crate) struct UserInfo {
    pub(crate) home_dir: PathBuf,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

// Get user info (home, uid, gid) via getpwnam_r (thread-safe)
pub(crate) fn get_user_info(username: &str) -> Option<(PathBuf, u32, u32)> {
    unsafe {
        let c_username = CString::new(username).ok()?;
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut pwd_ptr: *mut libc::passwd = std::ptr::null_mut();

        // Allocate buffer for getpwnam_r (recommended size per POSIX)
        const GETPWNAM_BUFFER_SIZE: usize = 16384;
        let mut buf = vec![0u8; GETPWNAM_BUFFER_SIZE];

        let result = libc::getpwnam_r(
            c_username.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            GETPWNAM_BUFFER_SIZE,
            &mut pwd_ptr,
        );

        if result != 0 || pwd_ptr.is_null() {
            return None;
        }

        let home = CStr::from_ptr(pwd.pw_dir);
        let home_str = home.to_str().ok()?;
        Some((PathBuf::from(home_str), pwd.pw_uid, pwd.pw_gid))
    }
}

// Get user home directory via getpwnam_r (thread-safe)
pub(crate) fn get_user_home(username: &str) -> Option<PathBuf> {
    get_user_info(username).map(|(home, _, _)| home)
}

// Get the current system user
pub(crate) fn get_current_user() -> Option<String> {
    unsafe {
        let uid = libc::getuid();
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut pwd_ptr: *mut libc::passwd = std::ptr::null_mut();

        const GETPWUID_BUFFER_SIZE: usize = 16384;
        let mut buf = vec![0u8; GETPWUID_BUFFER_SIZE];

        let result = libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            GETPWUID_BUFFER_SIZE,
            &mut pwd_ptr,
        );

        if result != 0 || pwd_ptr.is_null() {
            return None;
        }

        let username = CStr::from_ptr(pwd.pw_name);
        username.to_str().ok().map(|s| s.to_string())
    }
}

// Get current process's UID and GID
pub(crate) fn get_current_uid_gid() -> (u32, u32) {
    unsafe { (libc::getuid(), libc::getgid()) }
}
