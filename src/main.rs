use axum::{
    extract::{Path, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, put},
    Json, Router,
};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use serde::Serialize;
use std::{
    collections::HashMap,
    env,
    ffi::{CStr, CString},
    fs,
    path::{Path as StdPath, PathBuf},
    sync::{atomic::{AtomicU64, Ordering}, Arc, RwLock},
    time::{Duration, SystemTime},
};
use tokio::{
    fs::{create_dir_all, remove_dir_all, remove_file, File},
    io::{AsyncReadExt, AsyncWriteExt},
};
use uuid::Uuid;

// Global counter for unique temp file names
// Used to prevent race conditions when multiple requests write to the same file concurrently
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

// Token store for access control
// Maps token -> TokenInfo
type TokenStore = Arc<RwLock<HashMap<String, TokenInfo>>>;

// Information stored for each token
#[derive(Clone, Debug)]
struct TokenInfo {
    user: String,
    app: String,
    expiry: SystemTime,
}

impl TokenInfo {
    fn is_expired(&self) -> bool {
        SystemTime::now() > self.expiry
    }
}

// Application state
#[derive(Clone)]
struct AppState {
    token_store: TokenStore,
}

// Error response structure
#[derive(Serialize, Debug)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

impl ErrorResponse {
    fn new(error: &str, message: Option<String>) -> Self {
        Self {
            error: error.to_string(),
            message,
        }
    }
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        let status = match self.error.as_str() {
            "bad_request" => StatusCode::BAD_REQUEST,
            "unauthorized" => StatusCode::UNAUTHORIZED,
            "not_found" => StatusCode::NOT_FOUND,
            "conflict" => StatusCode::CONFLICT,
            "payload_too_large" => StatusCode::PAYLOAD_TOO_LARGE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(self)).into_response()
    }
}

// Directory entry structure for listings
#[derive(Serialize)]
struct DirEntry {
    name: String,
    #[serde(rename = "type")]
    entry_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    mtime: i64,
}

// User info extracted from getpwnam
#[derive(Clone)]
struct UserInfo {
    home_dir: PathBuf,
}

// Get user home directory via getpwnam_r (thread-safe)
fn get_user_home(username: &str) -> Option<PathBuf> {
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
        Some(PathBuf::from(home_str))
    }
}

// Path validation and security functions
fn validate_path_component(component: &str) -> Result<(), ErrorResponse> {
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

fn validate_and_resolve_path(
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

    // Split and validate each component
    let components: Vec<&str> = relative_path.split('/').collect();
    for component in &components {
        validate_path_component(component)?;
    }

    // Build the full path
    let mut full_path = base_dir.to_path_buf();
    for component in components {
        full_path.push(component);
    }

    // Get canonical base for validation
    let canonical_base = if base_dir.exists() {
        base_dir.canonicalize().map_err(|_| {
            ErrorResponse::new("internal_error", Some("Base path resolution failed".to_string()))
        })?
    } else {
        base_dir.to_path_buf()
    };

    // Canonicalize if it exists, otherwise validate parent hierarchy
    let canonical = if full_path.exists() {
        let resolved = full_path
            .canonicalize()
            .map_err(|_| ErrorResponse::new("internal_error", Some("Path resolution failed".to_string())))?;
        
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
        let parent = full_path.parent().ok_or_else(|| {
            ErrorResponse::new("bad_request", Some("Invalid path".to_string()))
        })?;
        
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

// Get the current system user
fn get_current_user() -> Option<String> {
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

// Middleware to validate token from cookie and ensure it matches the app being accessed
async fn token_auth_middleware(
    State(state): State<AppState>,
    jar: CookieJar,
    mut req: Request,
    next: Next,
) -> Result<Response, ErrorResponse> {
    // Extract token from cookie
    let token = jar
        .get("fleabox_token")
        .ok_or_else(|| ErrorResponse::new("unauthorized", Some("Missing authentication token".to_string())))?
        .value()
        .to_string();
    
    // Look up token in store
    let token_info = {
        let store = state.token_store.read().unwrap();
        store.get(&token).cloned()
    };
    
    let token_info = token_info.ok_or_else(|| {
        ErrorResponse::new("unauthorized", Some("Invalid token".to_string()))
    })?;
    
    // Check if token is expired
    if token_info.is_expired() {
        // Clean up expired token
        let mut store = state.token_store.write().unwrap();
        store.remove(&token);
        return Err(ErrorResponse::new("unauthorized", Some("Token expired".to_string())));
    }
    
    // Extract app_id from the request path
    // Path format: /api/<app_id>/data/<path>
    let uri_path = req.uri().path();
    let app_id = uri_path
        .strip_prefix("/api/")
        .and_then(|s| s.split('/').next())
        .ok_or_else(|| ErrorResponse::new("bad_request", Some("Invalid API path".to_string())))?;
    
    // Verify token's app matches the requested app
    if token_info.app != app_id {
        return Err(ErrorResponse::new(
            "unauthorized",
            Some(format!("Token not valid for app '{}'", app_id)),
        ));
    }
    
    // Get user's home directory
    let home_dir = get_user_home(&token_info.user).ok_or_else(|| {
        ErrorResponse::new(
            "unauthorized",
            Some(format!("User '{}' not found", token_info.user)),
        )
    })?;
    
    // Store user info in request extensions
    req.extensions_mut().insert(UserInfo { home_dir });
    
    Ok(next.run(req).await)
}

// GET /api/<app_id>/data/<path>
async fn api_get_data(
    Path((app_id, path)): Path<(String, String)>,
    req: Request,
) -> Result<Response, ErrorResponse> {
    let user_info = req
        .extensions()
        .get::<UserInfo>()
        .ok_or_else(|| ErrorResponse::new("unauthorized", None))?;

    let data_root = user_info
        .home_dir
        .join(".local/share/fleabox")
        .join(&app_id)
        .join("data");

    // If data root doesn't exist, return 404
    if !data_root.exists() {
        return Err(ErrorResponse::new("not_found", Some("Data root does not exist".to_string())));
    }

    let resolved_path = validate_and_resolve_path(&data_root, &path)?;

    if !resolved_path.exists() {
        return Err(ErrorResponse::new("not_found", Some("Path not found".to_string())));
    }

    let metadata = tokio::fs::metadata(&resolved_path)
        .await
        .map_err(|_| ErrorResponse::new("internal_error", Some("Failed to read metadata".to_string())))?;

    if metadata.is_file() {
        // Serve file with content type
        let mut file = File::open(&resolved_path)
            .await
            .map_err(|_| ErrorResponse::new("internal_error", Some("Failed to open file".to_string())))?;

        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .await
            .map_err(|_| ErrorResponse::new("internal_error", Some("Failed to read file".to_string())))?;

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
        let mut read_dir = tokio::fs::read_dir(&resolved_path)
            .await
            .map_err(|_| ErrorResponse::new("internal_error", Some("Failed to read directory".to_string())))?;

        while let Some(entry) = read_dir
            .next_entry()
            .await
            .map_err(|_| ErrorResponse::new("internal_error", Some("Failed to read directory entry".to_string())))?
        {
            let metadata = entry
                .metadata()
                .await
                .map_err(|_| ErrorResponse::new("internal_error", Some("Failed to read entry metadata".to_string())))?;

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
        Err(ErrorResponse::new("internal_error", Some("Unsupported file type".to_string())))
    }
}

// PUT /api/<app_id>/data/<path>
async fn api_put_data(
    Path((app_id, path)): Path<(String, String)>,
    req: Request,
) -> Result<Response, ErrorResponse> {
    let user_info = req
        .extensions()
        .get::<UserInfo>()
        .ok_or_else(|| ErrorResponse::new("unauthorized", None))?;

    let data_root = user_info
        .home_dir
        .join(".local/share/fleabox")
        .join(&app_id)
        .join("data");

    // Create data root lazily on first write
    if !data_root.exists() {
        create_dir_all(&data_root)
            .await
            .map_err(|_| ErrorResponse::new("internal_error", Some("Failed to create data root".to_string())))?;
    }

    let resolved_path = validate_and_resolve_path(&data_root, &path)?;

    // Ensure parent directory exists
    if let Some(parent) = resolved_path.parent() {
        if !parent.exists() {
            create_dir_all(parent)
                .await
                .map_err(|_| ErrorResponse::new("internal_error", Some("Failed to create parent directory".to_string())))?;
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
        resolved_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file"),
        std::process::id(),
        counter
    );
    let temp_path = resolved_path.parent()
        .map(|p| p.join(&temp_filename))
        .unwrap_or_else(|| PathBuf::from(&temp_filename));
    
    // Helper to cleanup temp file on error
    let cleanup_temp = || async {
        let _ = tokio::fs::remove_file(&temp_path).await;
    };
    
    let mut temp_file = File::create(&temp_path)
        .await
        .map_err(|_| ErrorResponse::new("internal_error", Some("Failed to create temp file".to_string())))?;

    if let Err(_) = temp_file.write_all(&body_bytes).await {
        cleanup_temp().await;
        return Err(ErrorResponse::new("internal_error", Some("Failed to write temp file".to_string())));
    }

    if let Err(_) = temp_file.sync_all().await {
        cleanup_temp().await;
        return Err(ErrorResponse::new("internal_error", Some("Failed to sync temp file".to_string())));
    }

    drop(temp_file);

    if let Err(_) = tokio::fs::rename(&temp_path, &resolved_path).await {
        cleanup_temp().await;
        return Err(ErrorResponse::new("internal_error", Some("Failed to rename temp file".to_string())));
    }

    Ok((StatusCode::CREATED, "").into_response())
}

// DELETE /api/<app_id>/data/<path>
async fn api_delete_data(
    Path((app_id, path)): Path<(String, String)>,
    req: Request,
) -> Result<Response, ErrorResponse> {
    let user_info = req
        .extensions()
        .get::<UserInfo>()
        .ok_or_else(|| ErrorResponse::new("unauthorized", None))?;

    let data_root = user_info
        .home_dir
        .join(".local/share/fleabox")
        .join(&app_id)
        .join("data");

    if !data_root.exists() {
        return Err(ErrorResponse::new("not_found", Some("Data root does not exist".to_string())));
    }

    let resolved_path = validate_and_resolve_path(&data_root, &path)?;

    if !resolved_path.exists() {
        return Err(ErrorResponse::new("not_found", Some("Path not found".to_string())));
    }

    let metadata = tokio::fs::metadata(&resolved_path)
        .await
        .map_err(|_| ErrorResponse::new("internal_error", Some("Failed to read metadata".to_string())))?;

    if metadata.is_file() {
        remove_file(&resolved_path)
            .await
            .map_err(|_| ErrorResponse::new("internal_error", Some("Failed to delete file".to_string())))?;
    } else if metadata.is_dir() {
        remove_dir_all(&resolved_path)
            .await
            .map_err(|_| ErrorResponse::new("internal_error", Some("Failed to delete directory".to_string())))?;
    }

    Ok((StatusCode::OK, "").into_response())
}

async fn list_directories() -> Html<String> {
    let path = "/srv/fleabox";
    let mut directories = Vec::new();

    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        directories.push(name.to_string());
                    }
                }
            }
        }
    }

    directories.sort();

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fleabox</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            padding: 40px;
            max-width: 600px;
            width: 100%;
        }}
        h1 {{
            font-size: 2.5rem;
            font-weight: 700;
            color: #333;
            margin-bottom: 10px;
            text-align: center;
        }}
        .subtitle {{
            text-align: center;
            color: #666;
            margin-bottom: 30px;
            font-size: 0.95rem;
        }}
        .apps-list {{
            list-style: none;
        }}
        .app-item {{
            margin-bottom: 12px;
        }}
        .app-link {{
            display: block;
            padding: 16px 20px;
            background: #f8f9fa;
            border-radius: 8px;
            text-decoration: none;
            color: #333;
            font-weight: 500;
            transition: all 0.2s ease;
            border: 2px solid transparent;
        }}
        .app-link:hover {{
            background: #667eea;
            color: white;
            transform: translateX(5px);
            border-color: #667eea;
        }}
        .empty-state {{
            text-align: center;
            padding: 40px 20px;
            color: #999;
        }}
        .empty-state svg {{
            width: 64px;
            height: 64px;
            margin-bottom: 16px;
            opacity: 0.5;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🦎 Fleabox</h1>
        <p class="subtitle">Your self-hosted apps</p>
        {}
    </div>
</body>
</html>"#,
        if directories.is_empty() {
            r#"<div class="empty-state">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
            </svg>
            <p>No apps found</p>
        </div>"#.to_string()
        } else {
            format!(
                r#"<ul class="apps-list">
            {}
        </ul>"#,
                directories
                    .iter()
                    .map(|dir| format!(r#"<li class="app-item"><a href="/{}" class="app-link">{}</a></li>"#, dir, dir))
                    .collect::<Vec<_>>()
                    .join("\n            ")
            )
        }
    );

    Html(html)
}

async fn serve_app_file(
    Path((app, file)): Path<(String, String)>,
    _jar: CookieJar,
) -> Response {
    // For now, allow access to static files without token validation
    // since they're just HTML/CSS/JS that gets loaded initially
    let file_path = format!("/srv/fleabox/{}/{}", app, file);
    
    match fs::read_to_string(&file_path) {
        Ok(content) => {
            let content_type = if file_path.ends_with(".html") {
                "text/html"
            } else if file_path.ends_with(".css") {
                "text/css"
            } else if file_path.ends_with(".js") {
                "application/javascript"
            } else if file_path.ends_with(".json") {
                "application/json"
            } else {
                "text/plain"
            };
            
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, content_type)],
                content,
            )
                .into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "File not found").into_response(),
    }
}

async fn serve_app_index(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(app): Path<String>,
    req: Request,
) -> Response {
    let index_path = format!("/srv/fleabox/{}/index.html", app);
    
    match fs::read_to_string(&index_path) {
        Ok(content) => {
            // Get username from either header (prod) or current user (dev)
            let username = if let Some(user_header) = req.headers().get("X-Remote-User") {
                user_header.to_str().unwrap_or("unknown").to_string()
            } else {
                get_current_user().unwrap_or_else(|| "unknown".to_string())
            };
            
            // Generate a new token for this app access
            let token = Uuid::new_v4().to_string();
            let token_info = TokenInfo {
                user: username,
                app: app.clone(),
                expiry: SystemTime::now() + Duration::from_secs(3600 * 24), // 24 hour expiry
            };
            
            // Store token
            {
                let mut store = state.token_store.write().unwrap();
                store.insert(token.clone(), token_info);
            }
            
            // Set cookie with token
            let cookie: Cookie = Cookie::build(("fleabox_token", token))
                .path("/")
                .same_site(SameSite::Strict)
                .http_only(true)
                .into();
            
            let jar = jar.add(cookie);
            
            (
                StatusCode::OK,
                jar,
                [(axum::http::header::CONTENT_TYPE, "text/html")],
                content,
            )
                .into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "App not found").into_response(),
    }
}

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let _dev_mode = args.contains(&"--dev".to_string());

    // Create shared application state
    let state = AppState {
        token_store: Arc::new(RwLock::new(HashMap::new())),
    };

    // API routes with token-based authentication
    let api_routes = Router::new()
        .route("/api/:app_id/data/*path", get(api_get_data))
        .route("/api/:app_id/data/*path", put(api_put_data))
        .route("/api/:app_id/data/*path", delete(api_delete_data))
        .layer(middleware::from_fn_with_state(state.clone(), token_auth_middleware))
        .with_state(state.clone());

    // Main app with both API and static routes
    let app = Router::new()
        .merge(api_routes)
        .route("/", get(list_directories))
        .route("/:app", get(serve_app_index))
        .route("/:app/*file", get(serve_app_file))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();
    
    println!("Server running on http://0.0.0.0:3000");
    println!("Token-based authentication enabled");
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::create_dir_all as std_create_dir_all;
    use tempfile::TempDir;

    #[test]
    fn test_validate_path_component_valid() {
        assert!(validate_path_component("test").is_ok());
        assert!(validate_path_component("test-file").is_ok());
        assert!(validate_path_component("test_file").is_ok());
        assert!(validate_path_component("test.txt").is_ok());
    }

    #[test]
    fn test_validate_path_component_dot() {
        assert!(validate_path_component(".").is_err());
        assert!(validate_path_component("..").is_err());
    }

    #[test]
    fn test_validate_path_component_empty() {
        assert!(validate_path_component("").is_err());
    }

    #[test]
    fn test_validate_path_component_nul() {
        assert!(validate_path_component("test\0file").is_err());
    }

    #[test]
    fn test_validate_path_component_windows_drive() {
        assert!(validate_path_component("C:").is_err());
        assert!(validate_path_component("D:").is_err());
    }

    #[test]
    fn test_validate_and_resolve_path_leading_slash() {
        let temp_dir = TempDir::new().unwrap();
        let result = validate_and_resolve_path(temp_dir.path(), "/test");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_and_resolve_path_dot_components() {
        let temp_dir = TempDir::new().unwrap();
        assert!(validate_and_resolve_path(temp_dir.path(), "./test").is_err());
        assert!(validate_and_resolve_path(temp_dir.path(), "../test").is_err());
        assert!(validate_and_resolve_path(temp_dir.path(), "test/../other").is_err());
    }

    #[test]
    fn test_validate_and_resolve_path_double_slash() {
        let temp_dir = TempDir::new().unwrap();
        let result = validate_and_resolve_path(temp_dir.path(), "test//file");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_and_resolve_path_valid_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        std::fs::File::create(&test_file).unwrap();

        let result = validate_and_resolve_path(temp_dir.path(), "test.txt");
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert_eq!(resolved, test_file.canonicalize().unwrap());
    }

    #[test]
    fn test_validate_and_resolve_path_valid_nested() {
        let temp_dir = TempDir::new().unwrap();
        let nested_dir = temp_dir.path().join("dir1").join("dir2");
        std_create_dir_all(&nested_dir).unwrap();
        let test_file = nested_dir.join("test.txt");
        std::fs::File::create(&test_file).unwrap();

        let result = validate_and_resolve_path(temp_dir.path(), "dir1/dir2/test.txt");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_and_resolve_path_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let parent_dir = temp_dir.path().join("parent");
        std_create_dir_all(&parent_dir).unwrap();

        // Non-existent file in existing parent should be ok for PUT
        let result = validate_and_resolve_path(temp_dir.path(), "parent/newfile.txt");
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_user_home_invalid() {
        // Test with a user that should not exist
        let result = get_user_home("nonexistent_user_12345");
        assert!(result.is_none());
    }
}
