use crate::{auth::AuthType, cli::Config, error::ErrorResponse};
use std::{
    ffi::{CStr, CString},
    path::PathBuf,
    sync::Arc,
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

// Validate user_id contains only safe characters (alphanumeric, hyphens, underscores, dots)
// Prevents path traversal and injection attacks
pub(crate) fn validate_user_id(user_id: &str) -> Result<(), ErrorResponse> {
    if user_id.is_empty() {
        return Err(ErrorResponse::new(
            "bad_request",
            Some("User ID cannot be empty".to_string()),
        ));
    }

    if user_id == "." || user_id == ".." {
        return Err(ErrorResponse::new(
            "bad_request",
            Some("Invalid user ID".to_string()),
        ));
    }

    // Only allow alphanumeric, hyphens, underscores, and dots
    if !user_id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(ErrorResponse::new(
            "bad_request",
            Some("User ID contains invalid characters".to_string()),
        ));
    }

    Ok(())
}

// Resolve the base data directory for a given user
// Returns ~/.local/share/fleabox for PAM/None auth
// Returns config data_dir for Config auth
// Returns current user's ~/.local/share/fleabox for dev mode
pub(crate) fn resolve_user_data_dir(
    username: &str,
    auth_type: &AuthType,
    config: &Option<Arc<Config>>,
    dev_mode: bool,
) -> Result<PathBuf, ErrorResponse> {
    // Dev mode: use current user's home directory
    if dev_mode {
        let current_user = get_current_user().ok_or_else(|| {
            ErrorResponse::new(
                "internal_error",
                Some("Failed to get current user".to_string()),
            )
        })?;

        let home = get_user_home(&current_user).ok_or_else(|| {
            ErrorResponse::new(
                "internal_error",
                Some("Failed to get current user's home directory".to_string()),
            )
        })?;

        return Ok(home.join(".local/share/fleabox"));
    }

    match auth_type {
        AuthType::Pam | AuthType::None => {
            // Use system user's home directory
            let home = get_user_home(username).ok_or_else(|| {
                ErrorResponse::new("not_found", Some("User not found".to_string()))
            })?;

            Ok(home.join(".local/share/fleabox"))
        }
        AuthType::Config => {
            // Look up user in config
            let cfg = config.as_ref().ok_or_else(|| {
                ErrorResponse::new(
                    "internal_error",
                    Some("Config not available".to_string()),
                )
            })?;

            let user_config = cfg
                .users
                .iter()
                .find(|u| u.username == username)
                .ok_or_else(|| {
                    ErrorResponse::new("not_found", Some("User not found".to_string()))
                })?;

            Ok(PathBuf::from(&user_config.data_dir))
        }
    }
}
