use crate::{
    error::ErrorResponse,
    fs_utils::{chown_created_dirs, chown_path, validate_and_resolve_path},
    user::{resolve_user_data_dir, validate_user_id, UserInfo},
    AppState,
};
use axum::{
    Json,
    extract::{Path, Request, State},
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

// GET /api/<app_id>/public/<path> - Owner's GET handler
pub(crate) async fn api_get_public_data(
    Path((app_id, path)): Path<(String, String)>,
    req: Request,
) -> Result<Response, ErrorResponse> {
    let user_info = req
        .extensions()
        .get::<UserInfo>()
        .ok_or_else(|| ErrorResponse::new("unauthorized", None))?;

    let public_root = user_info.home_dir.join(&app_id).join("public");

    let resolved_path = validate_and_resolve_path(&public_root, &path)?;

    if !resolved_path.exists() {
        // Special case: if requesting the root public directory and it doesn't exist,
        // treat it as an empty directory rather than 404
        if resolved_path == public_root {
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

// GET /api/<app_id>/public/ (root directory listing)
pub(crate) async fn api_get_public_data_root(
    Path(app_id): Path<String>,
    req: Request,
) -> Result<Response, ErrorResponse> {
    // Call api_get_public_data with an empty path
    api_get_public_data(Path((app_id, String::new())), req).await
}

// PUT /api/<app_id>/public/<path> - Owner's PUT handler
pub(crate) async fn api_put_public_data(
    Path((app_id, path)): Path<(String, String)>,
    req: Request,
) -> Result<Response, ErrorResponse> {
    let user_info = req
        .extensions()
        .get::<UserInfo>()
        .ok_or_else(|| ErrorResponse::new("unauthorized", None))?
        .clone();

    let public_root = user_info.home_dir.join(&app_id).join("public");

    // Create public root lazily on first write
    if !public_root.exists() {
        create_dir_all(&public_root).await.map_err(|_| {
            ErrorResponse::new(
                "internal_error",
                Some("Failed to create public folder".to_string()),
            )
        })?;

        // Set ownership on created directories
        chown_created_dirs(
            &public_root,
            &user_info.home_dir,
            user_info.uid,
            user_info.gid,
        );
    }

    let resolved_path = validate_and_resolve_path(&public_root, &path)?;

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

// DELETE /api/<app_id>/public/<path> - Owner's DELETE handler
pub(crate) async fn api_delete_public_data(
    Path((app_id, path)): Path<(String, String)>,
    req: Request,
) -> Result<Response, ErrorResponse> {
    let user_info = req
        .extensions()
        .get::<UserInfo>()
        .ok_or_else(|| ErrorResponse::new("unauthorized", None))?;

    let public_root = user_info.home_dir.join(&app_id).join("public");

    if !public_root.exists() {
        return Err(ErrorResponse::new(
            "not_found",
            Some("Public folder does not exist".to_string()),
        ));
    }

    let resolved_path = validate_and_resolve_path(&public_root, &path)?;

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

// GET /<app_id>/~<user_id>/<path> - Public read-only access
pub(crate) async fn api_get_user_public_data(
    Path((app_id, user_id, path)): Path<(String, String, String)>,
    State(state): State<AppState>,
) -> Result<Response, ErrorResponse> {
    // Validate user_id to prevent injection attacks
    validate_user_id(&user_id)?;

    // Resolve user's data directory
    let base_dir = resolve_user_data_dir(&user_id, &state.auth_type, &state.config, state.dev_mode)?;

    let public_root = base_dir.join(&app_id).join("public");

    // If public root doesn't exist, return 404
    if !public_root.exists() {
        return Err(ErrorResponse::new(
            "not_found",
            Some("Public folder does not exist".to_string()),
        ));
    }

    // Normalize path - treat empty path as root directory
    let normalized_path = if path.is_empty() || path == "/" {
        "".to_string()
    } else {
        // Remove trailing slash if present
        path.trim_end_matches('/').to_string()
    };

    let resolved_path = validate_and_resolve_path(&public_root, &normalized_path)?;

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
        // Check if index.html exists in directory
        let index_path = resolved_path.join("index.html");
        if index_path.exists() && index_path.is_file() {
            // Serve index.html
            let mut file = File::open(&index_path).await.map_err(|_| {
                ErrorResponse::new("internal_error", Some("Failed to open file".to_string()))
            })?;

            let mut contents = Vec::new();
            file.read_to_end(&mut contents).await.map_err(|_| {
                ErrorResponse::new("internal_error", Some("Failed to read file".to_string()))
            })?;

            Ok((
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/html".to_string())],
                contents,
            )
                .into_response())
        } else {
            // No index.html - return 403
            Err(ErrorResponse::new(
                "forbidden",
                Some("Directory listing not allowed".to_string()),
            ))
        }
    } else {
        Err(ErrorResponse::new(
            "internal_error",
            Some("Unsupported file type".to_string()),
        ))
    }
}

// GET /<app_id>/~<user_id>/ and /<app_id>/~<user_id> - Public read-only access to root
pub(crate) async fn api_get_user_public_data_root(
    Path((app_id, user_id)): Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<Response, ErrorResponse> {
    // Validate user_id to prevent injection attacks
    validate_user_id(&user_id)?;

    // Resolve user's data directory
    let base_dir = resolve_user_data_dir(&user_id, &state.auth_type, &state.config, state.dev_mode)?;

    let public_root = base_dir.join(&app_id).join("public");

    // If public root doesn't exist, return 404
    if !public_root.exists() {
        return Err(ErrorResponse::new(
            "not_found",
            Some("Public folder does not exist".to_string()),
        ));
    }

    // Check if index.html exists in the root directory
    let index_path = public_root.join("index.html");
    if index_path.exists() && index_path.is_file() {
        // Serve index.html
        let mut file = File::open(&index_path).await.map_err(|_| {
            ErrorResponse::new("internal_error", Some("Failed to open file".to_string()))
        })?;

        let mut contents = Vec::new();
        file.read_to_end(&mut contents).await.map_err(|_| {
            ErrorResponse::new("internal_error", Some("Failed to read file".to_string()))
        })?;

        Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html".to_string())],
            contents,
        )
            .into_response())
    } else {
        // No index.html - return 403
        Err(ErrorResponse::new(
            "forbidden",
            Some("Directory listing not allowed".to_string()),
        ))
    }
}

pub(crate) async fn redirect_to_public_folder(
    Path((app_id, user_id)): Path<(String, String)>
) -> impl IntoResponse {
    axum::response::Redirect::to(&format!("/{}/~{}/", app_id, user_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_redirect_to_public_folder() {
        let response = redirect_to_public_folder(
            Path(("myapp".to_string(), "user123".to_string()))
        ).await.into_response();
        
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        
        let location = response.headers().get("location").unwrap();
        assert_eq!(location, "/myapp/~user123/");
    }
}
