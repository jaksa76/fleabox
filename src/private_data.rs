use crate::{
    error::ErrorResponse,
    fs_utils::{chown_created_dirs, chown_path, validate_and_resolve_path},
    user::UserInfo,
};
use axum::{
    Json,
    extract::{Path, Request},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::SystemTime,
};
use tokio::{
    fs::{File, create_dir_all, remove_dir_all, remove_file},
    io::{AsyncReadExt, AsyncWriteExt},
};

// Global counter for unique temp file names
// Used to prevent race conditions when multiple requests write to the same file concurrently
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize)]
struct DirEntry {
    name: String,
    #[serde(rename = "type")]
    entry_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    mtime: i64,
}

// GET /api/<app_id>/data/<path>
pub(crate) async fn api_get_data(
    Path((app_id, path)): Path<(String, String)>,
    req: Request,
) -> Result<Response, ErrorResponse> {
    let user_info = req
        .extensions()
        .get::<UserInfo>()
        .ok_or_else(|| ErrorResponse::new("unauthorized", None))?;

    let data_root = user_info.home_dir.join(&app_id).join("data");

    let resolved_path = validate_and_resolve_path(&data_root, &path)?;

    if !resolved_path.exists() {
        // Special case: if requesting the root data directory and it doesn't exist,
        // treat it as an empty directory rather than 404
        if resolved_path == data_root {
            return Ok((StatusCode::OK, Json(Vec::<DirEntry>::new())).into_response());
        }
        
        return Err(ErrorResponse::new(
            "not_found",
            Some("Path not found".to_string()),
        ));
    }

    let metadata = tokio::fs::metadata(&resolved_path).await.map_err(|_| {
        ErrorResponse::new(
            "internal_error",
            Some("Failed to read metadata".to_string()),
        )
    })?;

    if metadata.is_file() {
        // Serve file with content type
        let mut file = File::open(&resolved_path).await.map_err(|_| {
            ErrorResponse::new("internal_error", Some("Failed to open file".to_string()))
        })?;

        let mut contents = Vec::new();
        file.read_to_end(&mut contents).await.map_err(|_| {
            ErrorResponse::new("internal_error", Some("Failed to read file".to_string()))
        })?;

        let content_type = mime_guess::from_path(&resolved_path)
            .first_or_octet_stream()
            .to_string();

        Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, content_type)],
            contents,
        )
            .into_response())
    } else if metadata.is_dir() {
        // Return directory listing as JSON
        let mut entries = Vec::new();
        let mut read_dir = tokio::fs::read_dir(&resolved_path).await.map_err(|_| {
            ErrorResponse::new(
                "internal_error",
                Some("Failed to read directory".to_string()),
            )
        })?;

        while let Some(entry) = read_dir.next_entry().await.map_err(|_| {
            ErrorResponse::new(
                "internal_error",
                Some("Failed to read directory entry".to_string()),
            )
        })? {
            let metadata = entry.metadata().await.map_err(|_| {
                ErrorResponse::new(
                    "internal_error",
                    Some("Failed to read entry metadata".to_string()),
                )
            })?;

            let mtime = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);

            let name = entry.file_name().to_string_lossy().to_string();
            let entry_type = if metadata.is_dir() { "dir" } else { "file" };
            let size = if metadata.is_file() {
                Some(metadata.len())
            } else {
                None
            };

            entries.push(DirEntry {
                name,
                entry_type: entry_type.to_string(),
                size,
                mtime,
            });
        }

        Ok((StatusCode::OK, Json(entries)).into_response())
    } else {
        Err(ErrorResponse::new(
            "internal_error",
            Some("Unsupported file type".to_string()),
        ))
    }
}

// GET /api/<app_id>/data/ (root directory listing)
pub(crate) async fn api_get_data_root(
    Path(app_id): Path<String>,
    req: Request,
) -> Result<Response, ErrorResponse> {
    // Call api_get_data with an empty path
    api_get_data(Path((app_id, String::new())), req).await
}

// PUT /api/<app_id>/data/<path>
pub(crate) async fn api_put_data(
    Path((app_id, path)): Path<(String, String)>,
    req: Request,
) -> Result<Response, ErrorResponse> {
    let user_info = req
        .extensions()
        .get::<UserInfo>()
        .ok_or_else(|| ErrorResponse::new("unauthorized", None))?
        .clone();

    let data_root = user_info.home_dir.join(&app_id).join("data");

    // Create data root lazily on first write
    if !data_root.exists() {
        create_dir_all(&data_root).await.map_err(|_| {
            ErrorResponse::new(
                "internal_error",
                Some("Failed to create data root".to_string()),
            )
        })?;

        // Set ownership on created directories
        chown_created_dirs(
            &data_root,
            &user_info.home_dir,
            user_info.uid,
            user_info.gid,
        );
    }

    let resolved_path = validate_and_resolve_path(&data_root, &path)?;

    // Ensure parent directory exists
    if let Some(parent) = resolved_path.parent() {
        if !parent.exists() {
            create_dir_all(parent).await.map_err(|_| {
                ErrorResponse::new(
                    "internal_error",
                    Some("Failed to create parent directory".to_string()),
                )
            })?;

            // Set ownership on created parent directories
            chown_created_dirs(parent, &user_info.home_dir, user_info.uid, user_info.gid);
        }
    }

    // Read body with size limit (10MB to prevent DoS)
    const MAX_BODY_SIZE: usize = 10 * 1024 * 1024; // 10MB
    let body_bytes = match axum::body::to_bytes(req.into_body(), MAX_BODY_SIZE).await {
        Ok(bytes) => bytes,
        Err(e) => {
            // Check if error is due to size limit by examining error source chain
            let err_str = format!("{:?}", e);
            if err_str.contains("length limit") || err_str.contains("body too large") {
                return Err(ErrorResponse::new(
                    "payload_too_large",
                    Some("Request body exceeds 10MB limit".to_string()),
                ));
            } else {
                return Err(ErrorResponse::new(
                    "internal_error",
                    Some("Failed to read request body".to_string()),
                ));
            }
        }
    };

    // Atomic write: write to temp file then rename
    // Use unique temp file name to avoid race conditions
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let temp_filename = format!(
        ".{}.tmp.{}.{}",
        resolved_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file"),
        std::process::id(),
        counter
    );
    let temp_path = resolved_path
        .parent()
        .map(|p| p.join(&temp_filename))
        .unwrap_or_else(|| PathBuf::from(&temp_filename));

    // Helper to cleanup temp file on error
    let cleanup_temp = || async {
        let _ = tokio::fs::remove_file(&temp_path).await;
    };

    let mut temp_file = File::create(&temp_path).await.map_err(|_| {
        ErrorResponse::new(
            "internal_error",
            Some("Failed to create temp file".to_string()),
        )
    })?;

    if let Err(_) = temp_file.write_all(&body_bytes).await {
        cleanup_temp().await;
        return Err(ErrorResponse::new(
            "internal_error",
            Some("Failed to write temp file".to_string()),
        ));
    }

    if let Err(_) = temp_file.sync_all().await {
        cleanup_temp().await;
        return Err(ErrorResponse::new(
            "internal_error",
            Some("Failed to sync temp file".to_string()),
        ));
    }

    drop(temp_file);

    // Set ownership on temp file before renaming
    if let Err(e) = chown_path(&temp_path, user_info.uid, user_info.gid) {
        eprintln!("Failed to chown {}: {}", temp_path.display(), e);
        cleanup_temp().await;
        return Err(ErrorResponse::new(
            "internal_error",
            Some("Failed to set file ownership".to_string()),
        ));
    }

    if let Err(_) = tokio::fs::rename(&temp_path, &resolved_path).await {
        cleanup_temp().await;
        return Err(ErrorResponse::new(
            "internal_error",
            Some("Failed to rename temp file".to_string()),
        ));
    }

    Ok((StatusCode::CREATED, "").into_response())
}

// DELETE /api/<app_id>/data/<path>
pub(crate) async fn api_delete_data(
    Path((app_id, path)): Path<(String, String)>,
    req: Request,
) -> Result<Response, ErrorResponse> {
    let user_info = req
        .extensions()
        .get::<UserInfo>()
        .ok_or_else(|| ErrorResponse::new("unauthorized", None))?;

    let data_root = user_info.home_dir.join(&app_id).join("data");

    if !data_root.exists() {
        return Err(ErrorResponse::new(
            "not_found",
            Some("Data root does not exist".to_string()),
        ));
    }

    let resolved_path = validate_and_resolve_path(&data_root, &path)?;

    if !resolved_path.exists() {
        return Err(ErrorResponse::new(
            "not_found",
            Some("Path not found".to_string()),
        ));
    }

    let metadata = tokio::fs::metadata(&resolved_path).await.map_err(|_| {
        ErrorResponse::new(
            "internal_error",
            Some("Failed to read metadata".to_string()),
        )
    })?;

    if metadata.is_file() {
        remove_file(&resolved_path).await.map_err(|_| {
            ErrorResponse::new("internal_error", Some("Failed to delete file".to_string()))
        })?;
    } else if metadata.is_dir() {
        remove_dir_all(&resolved_path).await.map_err(|_| {
            ErrorResponse::new(
                "internal_error",
                Some("Failed to delete directory".to_string()),
            )
        })?;
    }

    Ok((StatusCode::OK, "").into_response())
}
