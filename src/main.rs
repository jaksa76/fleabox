use axum::{
    extract::{Path, Query, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use serde::{Deserialize, Serialize};
use rsa::{RsaPrivateKey, pkcs8::EncodePublicKey, Oaep};
use sha2::Sha256;
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
use std::os::raw::{c_char, c_int, c_void};
use libloading::{Library, Symbol};
use uuid::Uuid;

// Global counter for unique temp file names
// Used to prevent race conditions when multiple requests write to the same file concurrently
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

// Authentication type
#[derive(Clone, Debug, PartialEq)]
enum AuthType {
    Pam,
    Config,
    None,
}

// User configuration for config-based authentication
#[derive(Clone, Debug, Deserialize)]
struct UserConfig {
    username: String,
    password: String,
    data_dir: String,
}

// Configuration file structure
#[derive(Clone, Debug, Deserialize)]
struct Config {
    users: Vec<UserConfig>,
}

// Token store for access control
// Maps token -> TokenInfo
type TokenStore = Arc<RwLock<HashMap<String, TokenInfo>>>;

// Information stored for each token
#[derive(Clone, Debug)]
struct TokenInfo {
    user: String,
    app: String,
    expiry: SystemTime,
    data_dir: PathBuf,
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
    apps_dir: String,
    rsa_private_key: Arc<RsaPrivateKey>,
    auth_type: AuthType,
    config: Option<Arc<Config>>,
    dev_mode: bool,
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

// Login request structure
#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    encrypted_password: String, // base64-encoded RSA-encrypted password
}

// Query params for login redirect
#[derive(Deserialize)]
struct LoginQuery {
    next: Option<String>,
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

// Authenticate user with PAM
// PAM constants and types for dynamic loading
const PAM_SUCCESS: c_int = 0;
const PAM_PROMPT_ECHO_OFF: c_int = 1;

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: extern "C" fn(
        num_msg: c_int,
        msg: *const *const PamMessage,
        resp: *mut *mut PamResponse,
        appdata_ptr: *mut c_void,
    ) -> c_int,
    appdata_ptr: *mut c_void,
}

// Conversation handler that provides the password
extern "C" fn conversation_handler(
    num_msg: c_int,
    msg: *const *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int {
    if num_msg <= 0 || msg.is_null() || resp.is_null() {
        return libc::EINVAL; // Invalid argument
    }

    unsafe {
        // Allocate array of pointers to PamResponse
        let responses = libc::calloc(num_msg as usize, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
        if responses.is_null() {
            return libc::ENOMEM;
        }
        
        // Initialize responses
        *resp = responses;

        let msgs = std::slice::from_raw_parts(msg, num_msg as usize);
        let responses_slice = std::slice::from_raw_parts_mut(responses, num_msg as usize);
        let password = appdata_ptr as *const c_char;

        for i in 0..num_msg as usize {
            let m = &*msgs[i];
            
            // Default initialization
            responses_slice[i].resp = std::ptr::null_mut();
            responses_slice[i].resp_retcode = 0;

            if m.msg_style == PAM_PROMPT_ECHO_OFF {
                // Password prompt
                responses_slice[i].resp = libc::strdup(password);
            }
        }
    }

    PAM_SUCCESS
}

// Authenticate user with PAM (dynamically loaded)
fn authenticate_with_pam(username: &str, password: &str) -> Result<(), String> {
    unsafe {
        // Try to load libpam.so.0 (common on Linux), then libpam.so
        let lib = Library::new("libpam.so.0")
            .or_else(|_| Library::new("libpam.so"))
            .map_err(|e| format!("Failed to load libpam: {}", e))?;

        // Define function signatures
        type PamStart = unsafe extern "C" fn(
            service_name: *const c_char,
            user: *const c_char,
            pam_conversation: *const PamConv,
            pamh: *mut *mut c_void,
        ) -> c_int;

        type PamAuthenticate = unsafe extern "C" fn(
            pamh: *mut c_void,
            flags: c_int,
        ) -> c_int;

        type PamAcctMgmt = unsafe extern "C" fn(
            pamh: *mut c_void,
            flags: c_int,
        ) -> c_int;

        type PamEnd = unsafe extern "C" fn(
            pamh: *mut c_void,
            pam_status: c_int,
        ) -> c_int;

        // Load symbols
        let pam_start: Symbol<PamStart> = lib.get(b"pam_start\0")
            .map_err(|e| format!("Failed to load pam_start: {}", e))?;
        let pam_authenticate: Symbol<PamAuthenticate> = lib.get(b"pam_authenticate\0")
            .map_err(|e| format!("Failed to load pam_authenticate: {}", e))?;
        let pam_acct_mgmt: Symbol<PamAcctMgmt> = lib.get(b"pam_acct_mgmt\0")
            .map_err(|e| format!("Failed to load pam_acct_mgmt: {}", e))?;
        let pam_end: Symbol<PamEnd> = lib.get(b"pam_end\0")
            .map_err(|e| format!("Failed to load pam_end: {}", e))?;

        // Prepare arguments
        let c_service = CString::new("login").unwrap();
        let c_user = CString::new(username).unwrap();
        let c_password = CString::new(password).unwrap();
        
        let conv = PamConv {
            conv: conversation_handler,
            appdata_ptr: c_password.as_ptr() as *mut c_void,
        };

        let mut pamh: *mut c_void = std::ptr::null_mut();

        // Start PAM transaction
        let retval = pam_start(
            c_service.as_ptr(),
            c_user.as_ptr(),
            &conv,
            &mut pamh
        );

        if retval != PAM_SUCCESS {
            return Err(format!("pam_start failed: {}", retval));
        }

        // Authenticate
        let retval = pam_authenticate(pamh, 0);
        if retval != PAM_SUCCESS {
            pam_end(pamh, retval);
            return Err(format!("pam_authenticate failed: {}", retval));
        }

        // Account management (check if account acts expired, etc.)
        let retval = pam_acct_mgmt(pamh, 0);
        if retval != PAM_SUCCESS {
            pam_end(pamh, retval);
            return Err(format!("pam_acct_mgmt failed: {}", retval));
        }

        // End transaction
        pam_end(pamh, PAM_SUCCESS);
        Ok(())
    }
}

// Authenticate user with config file
fn authenticate_with_config(config: &Config, username: &str, password: &str) -> Result<String, String> {
    for user in &config.users {
        if user.username == username && user.password == password {
            return Ok(user.data_dir.clone());
        }
    }
    Err("Invalid username or password".to_string())
}

// Get user from reverse proxy header
fn get_user_from_header(username: &str) -> Result<(), String> {
    if username.is_empty() {
        return Err("No username provided in header".to_string());
    }
    // Validate username contains only safe characters
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.') {
        return Err("Invalid username format".to_string());
    }
    Ok(())
}

// Check if user is authenticated (has valid token cookie)
fn is_authenticated(jar: &CookieJar, state: &AppState) -> bool {
    if let Some(token_cookie) = jar.get("fleabox_token") {
        let token = token_cookie.value();
        let store = state.token_store.read().unwrap();
        if let Some(token_info) = store.get(token) {
            return !token_info.is_expired();
        }
    }
    false
}

// Middleware to check authentication for public pages and redirect to login if needed
async fn public_page_auth_middleware(
    State(state): State<AppState>,
    jar: CookieJar,
    mut req: Request,
    next: Next,
) -> Result<Response, Redirect> {
    // For reverse proxy auth, check X-Remote-User header
    if state.auth_type == AuthType::None {
        if let Some(username) = req.headers().get("X-Remote-User") {
            if let Ok(username_str) = username.to_str() {
                if get_user_from_header(username_str).is_ok() {
                    // Create auto-login token for this user
                    // For reverse proxy auth, try to get system home dir, fallback to /home/{username}
                    let home_dir = get_user_home(username_str)
                        .unwrap_or_else(|| PathBuf::from(format!("/home/{}", username_str)));
                    let data_dir = home_dir.join(".local/share/fleabox");
                    
                    let token = Uuid::new_v4().to_string();
                    let token_info = TokenInfo {
                        user: username_str.to_string(),
                        app: "*".to_string(),
                        expiry: SystemTime::now() + Duration::from_secs(8 * 3600),
                        data_dir,
                    };
                    
                    {
                        let mut store = state.token_store.write().unwrap();
                        store.insert(token.clone(), token_info);
                    }
                    
                    // Add token to request extensions for downstream handlers
                    req.extensions_mut().insert(token);
                    let response = next.run(req).await;
                    return Ok((jar, response).into_response());
                }
            }
        }
        
        // In dev mode, fallback to current user if no header
        if state.dev_mode {
             if let Some(username) = get_current_user() {
                 let home_dir = get_user_home(&username)
                     .unwrap_or_else(|| PathBuf::from(format!("/home/{}", username)));
                 let data_dir = home_dir.join(".local/share/fleabox");
                 
                 let token = Uuid::new_v4().to_string();
                 let token_info = TokenInfo {
                     user: username,
                     app: "*".to_string(),
                     expiry: SystemTime::now() + Duration::from_secs(8 * 3600),
                     data_dir,
                 };
                 
                 {
                     let mut store = state.token_store.write().unwrap();
                     store.insert(token.clone(), token_info);
                 }
                 
                 req.extensions_mut().insert(token);
                 let response = next.run(req).await;
                 return Ok((jar, response).into_response());
             }
        }

        // No valid header found
        return Ok((
            StatusCode::UNAUTHORIZED,
            "X-Remote-User header required but not found or invalid"
        ).into_response());
    }
    
    // For PAM and Config auth, check cookie
    if !is_authenticated(&jar, &state) {
        let uri = req.uri();
        let next_url = urlencoding::encode(uri.path());
        return Err(Redirect::to(&format!("/login?next={}", next_url)));
    }
    Ok(next.run(req).await)
}

// GET /login - Serve login page
async fn login_page(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> Result<Html<String>, ErrorResponse> {
    // Don't show login page for reverse proxy auth
    if state.auth_type == AuthType::None {
        return Err(ErrorResponse::new(
            "bad_request",
            Some("Login page not available with reverse proxy authentication".to_string())
        ));
    }
    
    // Export public key as SPKI PEM format
    let public_key_pem = state
        .rsa_private_key
        .to_public_key()
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap_or_else(|_| "ERROR".to_string());
    
    let next_url = query.next.unwrap_or_else(|| "/".to_string());
    
    let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Fleabox</title>
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
            max-width: 400px;
            width: 100%;
        }}
        h1 {{
            font-size: 2rem;
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
        .form-group {{
            margin-bottom: 20px;
        }}
        label {{
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
            font-size: 0.9rem;
        }}
        input {{
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.2s;
        }}
        input:focus {{
            outline: none;
            border-color: #667eea;
        }}
        button {{
            width: 100%;
            padding: 14px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }}
        button:hover {{
            background: #5568d3;
        }}
        button:disabled {{
            background: #ccc;
            cursor: not-allowed;
        }}
        .error {{
            background: #fee;
            border: 1px solid #fcc;
            color: #c33;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 0.9rem;
        }}
        .lock-icon {{
            text-align: center;
            font-size: 3rem;
            margin-bottom: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="lock-icon">🔒</div>
        <h1>Login to Fleabox</h1>
        <p class="subtitle">Enter your system credentials</p>
        <div id="error" class="error" style="display: none;"></div>
        <form id="loginForm">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autocomplete="username">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            <button type="submit" id="submitBtn">Login</button>
        </form>
    </div>
    <script>
        const PUBLIC_KEY_PEM = `{public_key_pem}`;
        const NEXT_URL = {next_json};
        
        async function importPublicKey(pem) {{
            const pemContents = pem
                .replace(/-----BEGIN PUBLIC KEY-----/, '')
                .replace(/-----END PUBLIC KEY-----/, '')
                .replace(/\s/g, '');
            const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
            
            return await crypto.subtle.importKey(
                'spki',
                binaryDer,
                {{
                    name: 'RSA-OAEP',
                    hash: 'SHA-256'
                }},
                false,
                ['encrypt']
            );
        }}
        
        async function encryptPassword(password, publicKey) {{
            const encoder = new TextEncoder();
            const data = encoder.encode(password);
            
            const encrypted = await crypto.subtle.encrypt(
                {{
                    name: 'RSA-OAEP'
                }},
                publicKey,
                data
            );
            
            return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
        }}
        
        document.getElementById('loginForm').addEventListener('submit', async (e) => {{
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const submitBtn = document.getElementById('submitBtn');
            const errorDiv = document.getElementById('error');
            
            errorDiv.style.display = 'none';
            submitBtn.disabled = true;
            submitBtn.textContent = 'Logging in...';
            
            try {{
                const publicKey = await importPublicKey(PUBLIC_KEY_PEM);
                const encryptedPassword = await encryptPassword(password, publicKey);
                
                const response = await fetch('/login', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json'
                    }},
                    body: JSON.stringify({{
                        username,
                        encrypted_password: encryptedPassword
                    }})
                }});
                
                if (response.ok) {{
                    window.location.href = NEXT_URL;
                }} else {{
                    const data = await response.json();
                    errorDiv.textContent = data.message || 'Login failed';
                    errorDiv.style.display = 'block';
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Login';
                }}
            }} catch (error) {{
                errorDiv.textContent = 'An error occurred during login';
                errorDiv.style.display = 'block';
                submitBtn.disabled = false;
                submitBtn.textContent = 'Login';
            }}
        }});
    </script>
</body>
</html>"#, 
        public_key_pem = public_key_pem,
        next_json = serde_json::to_string(&next_url).unwrap()
    );
    
    Ok(Html(html))
}

// POST /login - Handle login
async fn login_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(login_req): Json<LoginRequest>,
) -> Result<(CookieJar, StatusCode), ErrorResponse> {
    // Decrypt the password using the private key
    use base64::{Engine as _, engine::general_purpose};
    let encrypted_bytes = general_purpose::STANDARD.decode(&login_req.encrypted_password)
        .map_err(|_| ErrorResponse::new("bad_request", Some("Invalid base64 encoding".to_string())))?;
    
    let padding = Oaep::new::<Sha256>();
    let decrypted_bytes = state
        .rsa_private_key
        .decrypt(padding, &encrypted_bytes)
        .map_err(|_| ErrorResponse::new("bad_request", Some("Decryption failed".to_string())))?;
    
    let password = String::from_utf8(decrypted_bytes)
        .map_err(|_| ErrorResponse::new("bad_request", Some("Invalid UTF-8 in password".to_string())))?;
    
    // Authenticate based on auth type and get data directory
    let data_dir = match state.auth_type {
        AuthType::Pam => {
            authenticate_with_pam(&login_req.username, &password)
                .map_err(|e| ErrorResponse::new("unauthorized", Some(format!("Authentication failed: {}", e))))?;
            
            // Verify user exists on the system and get home dir
            let home = get_user_home(&login_req.username)
                .ok_or_else(|| ErrorResponse::new("unauthorized", Some("User not found".to_string())))?;
            home.join(".local/share/fleabox")
        }
        AuthType::Config => {
            let config = state.config.as_ref()
                .ok_or_else(|| ErrorResponse::new("unauthorized", Some("Config not loaded".to_string())))?;
            
            let data_dir_str = authenticate_with_config(config, &login_req.username, &password)
                .map_err(|e| ErrorResponse::new("unauthorized", Some(e)))?;
            PathBuf::from(data_dir_str)
        }
        AuthType::None => {
            return Err(ErrorResponse::new("bad_request", Some("Login not available with header-based authentication".to_string())));
        }
    };
    
    // Create session token (valid for 8 hours, no app restriction for root token)
    let token = Uuid::new_v4().to_string();
    let token_info = TokenInfo {
        user: login_req.username.clone(),
        app: "*".to_string(), // Wildcard for root authentication
        expiry: SystemTime::now() + Duration::from_secs(8 * 3600),
        data_dir,
    };
    
    // Store token
    {
        let mut store = state.token_store.write().unwrap();
        store.insert(token.clone(), token_info);
    }
    
    // Set cookie
    let cookie = Cookie::build(("fleabox_token", token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::hours(8));
    
    let jar = jar.add(cookie);
    
    Ok((jar, StatusCode::OK))
}

// Middleware to validate token from cookie and ensure it matches the app being accessed
async fn token_auth_middleware(
    State(state): State<AppState>,
    jar: CookieJar,
    mut req: Request,
    next: Next,
) -> Result<Response, ErrorResponse> {
    // For reverse proxy auth, check X-Remote-User header
    if state.auth_type == AuthType::None {
        if let Some(username) = req.headers().get("X-Remote-User") {
            if let Ok(username_str) = username.to_str() {
                if get_user_from_header(username_str).is_ok() {
                    // Extract app_id from path
                    let path = req.uri().path().to_string();
                    if let Some(app_id) = path.strip_prefix("/api/").and_then(|p| p.split('/').next()) {
                        let username_owned = username_str.to_string();
                        let app_id_owned = app_id.to_string();
                        
                        let home_dir = get_user_home(username_str)
                            .unwrap_or_else(|| PathBuf::from(format!("/home/{}", username_str)));
                        let data_dir = home_dir.join(".local/share/fleabox");
                        
                        // Add user and app info to request extensions
                        req.extensions_mut().insert(username_owned);
                        req.extensions_mut().insert(app_id_owned);
                        req.extensions_mut().insert(UserInfo { home_dir: data_dir });
                        return Ok(next.run(req).await);
                    }
                }
            }
        }

        // In dev mode, fallback to current user if no header
        if state.dev_mode {
            if let Some(username) = get_current_user() {
                 let path = req.uri().path().to_string();
                 if let Some(app_id) = path.strip_prefix("/api/").and_then(|p| p.split('/').next()) {
                     let home_dir = get_user_home(&username)
                         .unwrap_or_else(|| PathBuf::from(format!("/home/{}", username)));
                     let data_dir = home_dir.join(".local/share/fleabox");

                     req.extensions_mut().insert(username);
                     req.extensions_mut().insert(app_id.to_string());
                     req.extensions_mut().insert(UserInfo { home_dir: data_dir });
                     return Ok(next.run(req).await);
                 }
            }
        }

        return Err(ErrorResponse::new("unauthorized", Some("X-Remote-User header required but not found or invalid".to_string())));
    }
    
    // For PAM and Config auth, extract token from cookie
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
    
    // Store user info in request extensions (use data_dir from token)
    req.extensions_mut().insert(UserInfo { home_dir: token_info.data_dir });
    
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

async fn list_directories(State(state): State<AppState>) -> Html<String> {
    let path = &state.apps_dir;
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
        * {{box-sizing: border-box; margin: 0; padding: 0;}}
        html,body {{height: 100%;}}
        body {{
            font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
            background: radial-gradient(1200px 600px at 10% 10%, rgba(156,163,175,0.04), transparent),
                        linear-gradient(180deg, #090912 0%, #0f1724 100%);
            color: #e6eef8c4;
            -webkit-font-smoothing:antialiased;
            -moz-osx-font-smoothing:grayscale;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 48px 24px 88px;
        }}
        .apps {{
            display: flex;
            flex-direction: column;
            gap: 18px;
            align-items: center;
            text-align: center;
        }}
        .apps a {{
            color: inherit;
            text-decoration: none;
            font-size: 3.2rem;
            font-weight: 100;
            letter-spacing: -0.02em;
            padding: 8px 16px;
            transition: transform 220ms cubic-bezier(.2,.9,.2,1), color 180ms ease, text-shadow 220ms ease;
            will-change: transform;
        }}
        .apps a:hover {{
            transform: scale(1.08);
            color: #ffffff;
            text-shadow: 0 6px 24px rgba(125,211,252,0.06);
        }}
        .empty {{
            color: #9aa4b2;
            font-size: 1rem;
            letter-spacing: 0.02em;
        }}
        .footer {{
            position: fixed;
            left: 0; right: 0;
            bottom: 12px;
            display: flex;
            justify-content: center;
            pointer-events: none;
        }}
        .footer .meta {{
            color: #728096;
            font-size: 0.82rem;
            background: rgba(255,255,255,0.02);
            padding: 6px 10px;
            border-radius: 999px;
            pointer-events: auto;
            backdrop-filter: blur(4px);
        }}
    </style>
</head>
<body>
    <main class="apps">
        {}
    </main>
    <div class="footer"><div class="meta">fleabox {}</div></div>
</body>
</html>"#,
        if directories.is_empty() {
            r#"<div class="empty">No apps found</div>"#.to_string()
        } else {
            directories
                .iter()
                .map(|dir| format!(r#"<a href="/{}/">{}</a>"#, dir, dir))
                .collect::<Vec<_>>()
                .join("\n        ")
        },
        env!("CARGO_PKG_VERSION")
    );

    Html(html)
}

async fn serve_app_file(
    State(state): State<AppState>,
    Path((app, file)): Path<(String, String)>,
    _jar: CookieJar,
) -> Response {
    // For now, allow access to static files without token validation
    // since they're just HTML/CSS/JS that gets loaded initially
    let file_path = format!("{}/{}/{}", state.apps_dir, app, file);
    
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
    // Handle requests ending with '/' by trying index.html or index.htm
    let index_path = if app.ends_with('/') {
        let app_name = app.trim_end_matches('/');
        let html_path = format!("{}/{}/index.html", state.apps_dir, app_name);
        let htm_path = format!("{}/{}/index.htm", state.apps_dir, app_name);
        
        if StdPath::new(&html_path).exists() {
            html_path
        } else if StdPath::new(&htm_path).exists() {
            htm_path
        } else {
            html_path // Try html by default for error message
        }
    } else {
        format!("{}/{}/index.html", state.apps_dir, app)
    };
    
    let app_name = app.trim_end_matches('/');
    
    match fs::read_to_string(&index_path) {
        Ok(content) => {
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "text/html")],
                content,
            )
                .into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "App not found").into_response(),
    }
}

// Parse --auth argument from command line
fn parse_auth_arg(args: &[String]) -> Result<AuthType, String> {
    match args.iter().position(|arg| arg.starts_with("--auth=")) {
        Some(pos) => {
            let arg = &args[pos];
            let value = arg.strip_prefix("--auth=").unwrap();
            match value {
                "pam" => Ok(AuthType::Pam),
                "config" => Ok(AuthType::Config),
                "none" => Ok(AuthType::None),
                _ => Err(format!("Error: Invalid auth type '{}'. Valid options: pam, config, none", value)),
            }
        }
        None => Ok(AuthType::Pam), // Default to PAM for backward compatibility
    }
}

// Load configuration file
fn load_config(path: &str) -> Result<Config, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config file: {}", e))?;
    
    let config: Config = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse config file: {}", e))?;
    
    if config.users.is_empty() {
        return Err("Config file must contain at least one user".to_string());
    }
    
    Ok(config)
}

// Parse --apps-dir argument from command line with validation
fn parse_apps_dir_arg(args: &[String]) -> Result<String, String> {
    match args.iter().position(|arg| arg == "--apps-dir") {
        Some(pos) => {
            match args.get(pos + 1) {
                Some(value) if !value.starts_with("--") && !value.is_empty() => {
                    Ok(value.to_string())
                }
                Some(value) if value.starts_with("--") => {
                    Err(format!("Error: --apps-dir requires a directory path argument, got '{}' instead", value))
                }
                _ => {
                    Err("Error: --apps-dir requires a directory path argument".to_string())
                }
            }
        }
        None => Ok("/srv/fleabox".to_string()),
    }
}

// Parse --port argument from command line
fn parse_port_arg(args: &[String]) -> Result<u16, String> {
    match args.iter().position(|arg| arg == "--port") {
        Some(pos) => {
            match args.get(pos + 1) {
                Some(value) => {
                    value.parse::<u16>().map_err(|_| format!("Error: Invalid port number '{}'", value))
                }
                None => Err("Error: --port requires a port number argument".to_string()),
            }
        }
        None => Ok(3000), // Default port
    }
}

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let dev_mode = args.contains(&"--dev".to_string());

    // Print concise instructions when called with --help
    if args.contains(&"--help".to_string()) {
        println!("fleabox - self-hosted app server");
        println!("Usage: fleabox [--dev] [--apps-dir <directory>] [--auth=<type>] [--config=<file>]");
        println!("");
        println!("Options:");
        println!("  --dev            Run in development mode (uses current user)");
        println!("  --apps-dir DIR   Path to apps directory (default: /srv/fleabox)");
        println!("  --port PORT      Port to listen on (default: 3000)");
        println!("  --auth=TYPE      Authentication type: pam, config, or none (default: pam)");
        println!("                   - pam: Use system PAM authentication");
        println!("                   - config: Use config file with username/password");
        println!("                   - none: Use X-Remote-User header from reverse proxy");
        println!("  --config=FILE    Path to config file (required for --auth=config)");
        std::process::exit(0);
    }

    // Parse --apps-dir argument
    let apps_dir = match parse_apps_dir_arg(&args) {
        Ok(dir) => dir,
        Err(msg) => {
            eprintln!("{}", msg);
            eprintln!("\nUsage: fleabox [--dev] [--apps-dir <directory>] [--auth=<type>] [--config=<file>]");
            std::process::exit(1);
        }
    };

    // Parse --port argument
    let port = match parse_port_arg(&args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{}", msg);
             eprintln!("\nUsage: fleabox [--dev] [--apps-dir <directory>] [--port <port>] [--auth=<type>] [--config=<file>]");
            std::process::exit(1);
        }
    };

    // Parse --auth argument
    let auth_arg_present = args.iter().any(|arg| arg.starts_with("--auth="));
    let auth_type = if !auth_arg_present && dev_mode {
        AuthType::None
    } else {
        match parse_auth_arg(&args) {
            Ok(auth) => auth,
            Err(msg) => {
                eprintln!("{}", msg);
                eprintln!("\nUsage: fleabox [--dev] [--apps-dir <directory>] [--auth=<type>] [--config=<file>]");
                std::process::exit(1);
            }
        }
    };



    // Load config file if needed
    let config = if auth_type == AuthType::Config {
        let config_path = args.iter()
            .position(|arg| arg.starts_with("--config="))
            .and_then(|pos| args[pos].strip_prefix("--config="));
        
        let config_path = match config_path {
            Some(path) => path,
            None => {
                eprintln!("Error: --auth=config requires --config=<file> argument");
                eprintln!("\nUsage: fleabox [--dev] [--apps-dir <directory>] [--auth=<type>] [--config=<file>]");
                std::process::exit(1);
            }
        };
        
        match load_config(config_path) {
            Ok(cfg) => Some(Arc::new(cfg)),
            Err(msg) => {
                eprintln!("{}", msg);
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // Generate RSA keypair for password encryption
    println!("Generating RSA keypair...");
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let rsa_private_key = RsaPrivateKey::new(&mut rng, bits)
        .expect("Failed to generate RSA key");
    println!("RSA keypair generated successfully");

    // Create shared application state
    let state = AppState {
        token_store: Arc::new(RwLock::new(HashMap::new())),
        apps_dir,
        rsa_private_key: Arc::new(rsa_private_key),
        auth_type: auth_type.clone(),
        config,
        dev_mode,
    };

    // API routes with token-based authentication
    let api_routes = Router::new()
        .route("/api/:app_id/data/*path", get(api_get_data))
        .route("/api/:app_id/data/*path", put(api_put_data))
        .route("/api/:app_id/data/*path", delete(api_delete_data))
        .layer(middleware::from_fn_with_state(state.clone(), token_auth_middleware))
        .with_state(state.clone());

    // Public pages with authentication middleware (redirect to login if not authenticated)
    let protected_routes = Router::new()
        .route("/", get(list_directories))
        .route("/:app/", get(serve_app_index))
        .route("/:app", get(serve_app_index))
        .route("/:app/*file", get(serve_app_file))
        .layer(middleware::from_fn_with_state(state.clone(), public_page_auth_middleware))
        .with_state(state.clone());

    // Main app with all routes
    let app = Router::new()
        .merge(api_routes)
        .merge(protected_routes)
        .route("/login", get(login_page))
        .route("/login", post(login_handler))
        .with_state(state);



    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .unwrap();
    
    println!("Server running on http://0.0.0.0:{}", port);
    match auth_type {
        AuthType::Pam => println!("Authentication: PAM (system users)"),
        AuthType::Config => println!("Authentication: Config file"),
        AuthType::None => println!("Authentication: Reverse proxy (X-Remote-User header)"),
    }
    println!("Password encryption: RSA-2048 with OAEP");
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

    #[test]
    fn test_parse_apps_dir_argument() {
        // Test default apps_dir (no flag provided)
        let args = vec!["fleabox".to_string()];
        let apps_dir = parse_apps_dir_arg(&args).unwrap();
        assert_eq!(apps_dir, "/srv/fleabox");

        // Test custom apps_dir
        let args = vec![
            "fleabox".to_string(),
            "--apps-dir".to_string(),
            "/custom/path".to_string(),
        ];
        let apps_dir = parse_apps_dir_arg(&args).unwrap();
        assert_eq!(apps_dir, "/custom/path");

        // Test with --apps-dir in the middle of other arguments
        let args = vec![
            "fleabox".to_string(),
            "--dev".to_string(),
            "--apps-dir".to_string(),
            "/another/path".to_string(),
        ];
        let apps_dir = parse_apps_dir_arg(&args).unwrap();
        assert_eq!(apps_dir, "/another/path");
    }

    #[test]
    fn test_parse_apps_dir_missing_value() {
        // Test that --apps-dir without a value returns an error
        let args = vec!["fleabox".to_string(), "--apps-dir".to_string()];
        let result = parse_apps_dir_arg(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("requires a directory path argument"));
    }

    #[test]
    fn test_parse_apps_dir_followed_by_flag() {
        // Test that --apps-dir followed by another flag (not a value) returns an error
        let args = vec![
            "fleabox".to_string(),
            "--apps-dir".to_string(),
            "--dev".to_string(),
        ];
        let result = parse_apps_dir_arg(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("requires a directory path argument"));
    }
}
