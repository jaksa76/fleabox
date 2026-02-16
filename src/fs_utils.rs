use crate::error::ErrorResponse;
use std::{
    ffi::CString,
    path::{Path as StdPath, PathBuf},
};

pub(crate) fn chown_path(path: &StdPath, uid: u32, gid: u32) -> std::io::Result<()> {
    // File ownership changes require root privileges on typical Linux systems.
    // In non-root mode, fleabox should still function (and tests expect this),
    // so we treat chown as a no-op.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }

    let c_path =
        CString::new(path.to_str().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid path")
        })?)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid path"))?;

    let result = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };

    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

// Helper function to set ownership on a newly created directory hierarchy
// Sets ownership from the deepest (most nested) directory up to base_dir (exclusive)
pub(crate) fn chown_created_dirs(target_dir: &StdPath, base_dir: &StdPath, uid: u32, gid: u32) {
    let mut dirs_to_chown = Vec::new();
    let mut current = target_dir;

    // Collect directories from target up to (but not including) base
    while current != base_dir {
        if let Some(parent) = current.parent() {
            dirs_to_chown.push(current);
            current = parent;
        } else {
            break;
        }
    }

    // Change ownership (already in correct order: deepest to shallowest)
    for dir in dirs_to_chown.iter() {
        let _ = chown_path(dir, uid, gid);
    }
}

pub(crate) fn validate_path_component(component: &str) -> Result<(), ErrorResponse> {
    if component.is_empty() {
        return Err(ErrorResponse::new(
            "bad_request",
            Some("Empty path component".to_string()),
        ));
    }
    if component == "." || component == ".." {
        return Err(ErrorResponse::new(
            "bad_request",
            Some("Path contains '.' or '..' components".to_string()),
        ));
    }
    if component.contains('\0') {
        return Err(ErrorResponse::new(
            "bad_request",
            Some("Path contains NUL byte".to_string()),
        ));
    }
    // Reject Windows drive prefixes
    if component.len() == 2 && component.chars().nth(1) == Some(':') {
        return Err(ErrorResponse::new(
            "bad_request",
            Some("Invalid path format".to_string()),
        ));
    }
    Ok(())
}

pub(crate) fn validate_and_resolve_path(
    base_dir: &StdPath,
    relative_path: &str,
) -> Result<PathBuf, ErrorResponse> {
    // Reject leading slash
    if relative_path.starts_with('/') {
        return Err(ErrorResponse::new(
            "bad_request",
            Some("Path must be relative".to_string()),
        ));
    }

    // Strip trailing slash (used for directory listing) before splitting
    let trimmed_path = relative_path.trim_end_matches('/');

    // Split and validate each component
    let components: Vec<&str> = if trimmed_path.is_empty() {
        Vec::new()
    } else {
        let parts: Vec<&str> = trimmed_path.split('/').collect();
        for component in &parts {
            validate_path_component(component)?;
        }
        parts
    };

    // Build the full path
    let mut full_path = base_dir.to_path_buf();
    for component in components {
        full_path.push(component);
    }

    // Get canonical base for validation
    let canonical_base = if base_dir.exists() {
        base_dir.canonicalize().map_err(|_| {
            ErrorResponse::new(
                "internal_error",
                Some("Base path resolution failed".to_string()),
            )
        })?
    } else {
        base_dir.to_path_buf()
    };

    // Canonicalize if it exists, otherwise validate parent hierarchy
    let canonical = if full_path.exists() {
        let resolved = full_path.canonicalize().map_err(|_| {
            ErrorResponse::new("internal_error", Some("Path resolution failed".to_string()))
        })?;

        // Verify it's under base_dir
        if !resolved.starts_with(&canonical_base) {
            return Err(ErrorResponse::new(
                "bad_request",
                Some("Path escapes data root".to_string()),
            ));
        }
        resolved
    } else {
        // For non-existent paths (PUT), validate the parent hierarchy
        let parent = full_path
            .parent()
            .ok_or_else(|| ErrorResponse::new("bad_request", Some("Invalid path".to_string())))?;

        if parent.exists() {
            // Parent exists - canonicalize and verify
            let canonical_parent = parent.canonicalize().map_err(|_| {
                ErrorResponse::new("internal_error", Some("Path resolution failed".to_string()))
            })?;

            // Verify parent is under base_dir
            if !canonical_parent.starts_with(&canonical_base) {
                return Err(ErrorResponse::new(
                    "bad_request",
                    Some("Path escapes data root".to_string()),
                ));
            }

            // Return the full non-canonical path for creation
            full_path
        } else {
            // Parent doesn't exist yet - verify it would be under base_dir when created
            // We've already validated that relative_path doesn't contain .. or . components,
            // so a simple prefix check on the constructed path is safe
            if !full_path.starts_with(&canonical_base) {
                return Err(ErrorResponse::new(
                    "bad_request",
                    Some("Path escapes data root".to_string()),
                ));
            }
            full_path
        }
    };

    Ok(canonical)
}
