use crate::{
    AppState,
    cli::Config,
    error::ErrorResponse,
    user::{UserInfo, get_current_uid_gid, get_current_user, get_user_home, get_user_info},
};
use axum::{
    Json,
    extract::{Query, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use libloading::{Library, Symbol};
use rsa::{Oaep, pkcs8::EncodePublicKey};
use serde::Deserialize;
use sha2::Sha256;
use std::{
    collections::HashMap,
    ffi::CString,
    os::raw::{c_char, c_int, c_void},
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AuthType {
    Pam,
    Config,
    None,
}

// Token store for access control
// Maps token -> TokenInfo
pub(crate) type TokenStore = Arc<RwLock<HashMap<String, TokenInfo>>>;

// Information stored for each active token
#[derive(Clone, Debug)]
pub(crate) struct TokenInfo {
    #[allow(dead_code)]
    pub(crate) user: String,
    pub(crate) app: String,
    pub(crate) expiry: SystemTime,
    pub(crate) data_dir: PathBuf,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

impl TokenInfo {
    pub(crate) fn is_expired(&self) -> bool {
        SystemTime::now() > self.expiry
    }
}

#[derive(Deserialize)]
pub(crate) struct LoginRequest {
    username: String,
    encrypted_password: String, // base64-encoded RSA-encrypted password
}

#[derive(Deserialize)]
pub(crate) struct LoginQuery {
    pub(crate) next: Option<String>,
}

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

// PAM conversation structure
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

// Conversation handler for PAM authentication
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
        let responses =
            libc::calloc(num_msg as usize, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
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

        type PamAuthenticate = unsafe extern "C" fn(pamh: *mut c_void, flags: c_int) -> c_int;

        type PamAcctMgmt = unsafe extern "C" fn(pamh: *mut c_void, flags: c_int) -> c_int;

        type PamEnd = unsafe extern "C" fn(pamh: *mut c_void, pam_status: c_int) -> c_int;

        // Load symbols
        let pam_start: Symbol<PamStart> = lib
            .get(b"pam_start\0")
            .map_err(|e| format!("Failed to load pam_start: {}", e))?;
        let pam_authenticate: Symbol<PamAuthenticate> = lib
            .get(b"pam_authenticate\0")
            .map_err(|e| format!("Failed to load pam_authenticate: {}", e))?;
        let pam_acct_mgmt: Symbol<PamAcctMgmt> = lib
            .get(b"pam_acct_mgmt\0")
            .map_err(|e| format!("Failed to load pam_acct_mgmt: {}", e))?;
        let pam_end: Symbol<PamEnd> = lib
            .get(b"pam_end\0")
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
        let retval = pam_start(c_service.as_ptr(), c_user.as_ptr(), &conv, &mut pamh);

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

fn authenticate_with_config(
    config: &Config,
    username: &str,
    password: &str,
) -> Result<String, String> {
    for user in &config.users {
        if user.username == username && user.password == password {
            return Ok(user.data_dir.clone());
        }
    }
    Err("Invalid username or password".to_string())
}

fn get_user_from_header(username: &str) -> Result<(), String> {
    if username.is_empty() {
        return Err("No username provided in header".to_string());
    }
    // Validate username contains only safe characters
    if !username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err("Invalid username format".to_string());
    }
    Ok(())
}

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

// Middleware for public page authentication
// Redirects to login page if not authenticated
// For reverse proxy auth, checks X-Remote-User header
// Creates auto-login token if valid header found
// In dev mode, falls back to current user if no header
pub(crate) async fn public_page_auth_middleware(
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
                    let (home_dir, uid, gid) = get_user_info(username_str).unwrap_or_else(|| {
                        (PathBuf::from(format!("/home/{}", username_str)), 0, 0)
                    });
                    let data_dir = home_dir.join(".local/share/fleabox");

                    let token = Uuid::new_v4().to_string();
                    let token_info = TokenInfo {
                        user: username_str.to_string(),
                        app: "*".to_string(),
                        expiry: SystemTime::now() + Duration::from_secs(8 * 3600),
                        data_dir,
                        uid,
                        gid,
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

                // In dev mode, use current process's uid/gid (don't chown files)
                let (uid, gid) = get_current_uid_gid();

                let token = Uuid::new_v4().to_string();
                let token_info = TokenInfo {
                    user: username,
                    app: "*".to_string(),
                    expiry: SystemTime::now() + Duration::from_secs(8 * 3600),
                    data_dir,
                    uid,
                    gid,
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
            "X-Remote-User header required but not found or invalid",
        )
            .into_response());
    }

    // For PAM and Config auth, check cookie
    if !is_authenticated(&jar, &state) {
        let uri = req.uri();
        let next_url = urlencoding::encode(uri.path());
        return Err(Redirect::to(&format!("/login?next={}", next_url)));
    }
    Ok(next.run(req).await)
}


// Render login page
// The page includes client-side RSA encryption of the password
// using the server's public key in PEM format
// The encrypted password is sent to the /login endpoint
// via AJAX for authentication
pub(crate) async fn login_page(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> Result<Html<String>, ErrorResponse> {
    // Don't show login page for reverse proxy auth
    if state.auth_type == AuthType::None {
        return Err(ErrorResponse::new(
            "bad_request",
            Some("Login page not available with reverse proxy authentication".to_string()),
        ));
    }

    // Export public key as SPKI PEM format
    let public_key_pem = state
        .rsa_private_key
        .to_public_key()
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap_or_else(|_| "ERROR".to_string());

    let next_url = query.next.unwrap_or_else(|| "/".to_string());

    let html = format!(
        r#"<!DOCTYPE html>
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
        html, body {{
            height: 100%;
        }}
        body {{
            font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
            background: radial-gradient(1200px 600px at 10% 10%, rgba(156,163,175,0.04), transparent),
                        linear-gradient(180deg, #090912 0%, #0f1724 100%);
            color: #e6eef8c4;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            padding: 48px 40px;
            max-width: 420px;
            width: 100%;
        }}
        h1 {{
            font-size: 2rem;
            font-weight: 200;
            color: #ffffff;
            margin-bottom: 8px;
            text-align: center;
            letter-spacing: -0.02em;
        }}
        .subtitle {{
            text-align: center;
            color: #9aa4b2;
            margin-bottom: 32px;
            font-size: 0.9rem;
            letter-spacing: 0.01em;
        }}
        .form-group {{
            margin-bottom: 24px;
        }}
        label {{
            display: block;
            margin-bottom: 8px;
            color: #9aa4b2;
            font-weight: 500;
            font-size: 0.875rem;
            letter-spacing: 0.01em;
        }}
        input {{
            width: 100%;
            padding: 12px 16px;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(230, 238, 248, 0.12);
            border-radius: 8px;
            font-size: 1rem;
            color: #e6eef8;
            transition: all 0.2s ease;
        }}
        input:focus {{
            outline: none;
            background: rgba(255, 255, 255, 0.05);
            border-color: rgba(230, 238, 248, 0.24);
        }}
        input::placeholder {{
            color: #728096;
        }}
        button {{
            width: 100%;
            padding: 14px;
            background: rgba(230, 238, 248, 0.08);
            color: #ffffff;
            border: 1px solid rgba(230, 238, 248, 0.12);
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            margin-top: 8px;
        }}
        button:hover {{
            background: rgba(230, 238, 248, 0.12);
            border-color: rgba(230, 238, 248, 0.2);
            transform: translateY(-1px);
        }}
        button:active {{
            transform: translateY(0);
        }}
        button:disabled {{
            background: rgba(230, 238, 248, 0.04);
            border-color: rgba(230, 238, 248, 0.06);
            color: #728096;
            cursor: not-allowed;
            transform: none;
        }}
        .error {{
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #fca5a5;
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 24px;
            font-size: 0.875rem;
        }}
        .lock-icon {{
            text-align: center;
            font-size: 2.5rem;
            margin-bottom: 24px;
            opacity: 0.6;
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
    <div class="container">
        <div id="error" class="error" style="display: none;"></div>
        <form id="loginForm">
            <div class="form-group">
                <input type="text" id="username" name="username" required autocomplete="username" placeholder="Username">
            </div>
            <div class="form-group">
                <input type="password" id="password" name="password" required autocomplete="current-password" placeholder="Password">
            </div>
            <button type="submit" id="submitBtn">Login</button>
        </form>
    </div>
    <div class="footer"><div class="meta">fleabox {}</div></div>
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
        env!("CARGO_PKG_VERSION"),
        public_key_pem = public_key_pem,
        next_json = serde_json::to_string(&next_url).unwrap()
    );

    Ok(Html(html))
}

pub(crate) async fn login_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(login_req): Json<LoginRequest>,
) -> Result<(CookieJar, StatusCode), ErrorResponse> {
    // Decrypt the password using the private key
    use base64::{Engine as _, engine::general_purpose};

    let encrypted_bytes = general_purpose::STANDARD
        .decode(&login_req.encrypted_password)
        .map_err(|_| {
            ErrorResponse::new("bad_request", Some("Invalid base64 encoding".to_string()))
        })?;

    let padding = Oaep::new::<Sha256>();
    let decrypted_bytes = state
        .rsa_private_key
        .decrypt(padding, &encrypted_bytes)
        .map_err(|_| ErrorResponse::new("bad_request", Some("Decryption failed".to_string())))?;

    let password = String::from_utf8(decrypted_bytes).map_err(|_| {
        ErrorResponse::new("bad_request", Some("Invalid UTF-8 in password".to_string()))
    })?;

    // Authenticate based on auth type and get data directory
    let (data_dir, uid, gid) = match state.auth_type {
        AuthType::Pam => {
            authenticate_with_pam(&login_req.username, &password).map_err(|e| {
                ErrorResponse::new(
                    "unauthorized",
                    Some(format!("Authentication failed: {}", e)),
                )
            })?;

            // Verify user exists on the system and get home dir, uid, gid
            let (home, uid, gid) = get_user_info(&login_req.username).ok_or_else(|| {
                ErrorResponse::new("unauthorized", Some("User not found".to_string()))
            })?;
            (home.join(".local/share/fleabox"), uid, gid)
        }
        AuthType::Config => {
            let config = state.config.as_ref().ok_or_else(|| {
                ErrorResponse::new("unauthorized", Some("Config not loaded".to_string()))
            })?;

            let data_dir_str = authenticate_with_config(config, &login_req.username, &password)
                .map_err(|e| ErrorResponse::new("unauthorized", Some(e)))?;

            // For config-based auth, try to get uid/gid from system user, fallback to 0:0
            let (uid, gid) = get_user_info(&login_req.username)
                .map(|(_, uid, gid)| (uid, gid))
                .unwrap_or((0, 0));
            (PathBuf::from(data_dir_str), uid, gid)
        }
        AuthType::None => {
            return Err(ErrorResponse::new(
                "bad_request",
                Some("Login not available with header-based authentication".to_string()),
            ));
        }
    };

    // Create session token (valid for 8 hours, no app restriction for root token)
    let token = Uuid::new_v4().to_string();
    let token_info = TokenInfo {
        user: login_req.username.clone(),
        app: "*".to_string(), // Wildcard for root authentication
        expiry: SystemTime::now() + Duration::from_secs(8 * 3600),
        data_dir,
        uid,
        gid,
    };

    // Store token
    {
        let mut store = state.token_store.write().unwrap();
        store.insert(token.clone(), token_info);
    }

    // Set authentication cookie
    let cookie = Cookie::build(("fleabox_token", token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::hours(8));

    let jar = jar.add(cookie);

    // set username cookie for client-side use (not http-only)
    let username_cookie = Cookie::build(("fleabox_username", login_req.username))
        .path("/")
        .same_site(SameSite::Lax)
        .max_age(time::Duration::hours(8));

    let jar = jar.add(username_cookie);

    Ok((jar, StatusCode::OK))
}

pub(crate) async fn token_auth_middleware(
    State(state): State<AppState>,
    jar: CookieJar,
    mut req: Request,
    next: Next,
) -> Result<Response, ErrorResponse> {
    // In dev mode, always use current user regardless of headers
    if state.dev_mode {
        if let Some(username) = get_current_user() {
            let path = req.uri().path().to_string();
            if let Some(app_id) = path.strip_prefix("/api/").and_then(|p| p.split('/').next()) {
                let home_dir = get_user_home(&username)
                    .unwrap_or_else(|| PathBuf::from(format!("/home/{}", username)));
                let data_dir = home_dir.join(".local/share/fleabox");

                // In dev mode, use current process's uid/gid (don't chown files)
                let (uid, gid) = get_current_uid_gid();

                req.extensions_mut().insert(username);
                req.extensions_mut().insert(app_id.to_string());
                req.extensions_mut().insert(UserInfo {
                    home_dir: data_dir,
                    uid,
                    gid,
                });
                return Ok(next.run(req).await);
            }
        }
    }

    // For reverse proxy auth, check X-Remote-User header
    if state.auth_type == AuthType::None {
        if let Some(username) = req.headers().get("X-Remote-User") {
            if let Ok(username_str) = username.to_str() {
                if get_user_from_header(username_str).is_ok() {
                    // Extract app_id from path
                    let path = req.uri().path().to_string();
                    if let Some(app_id) =
                        path.strip_prefix("/api/").and_then(|p| p.split('/').next())
                    {
                        let username_owned = username_str.to_string();
                        let app_id_owned = app_id.to_string();

                        let (home_dir, uid, gid) =
                            get_user_info(username_str).unwrap_or_else(|| {
                                (PathBuf::from(format!("/home/{}", username_str)), 0, 0)
                            });
                        let data_dir = home_dir.join(".local/share/fleabox");

                        // Add user and app info to request extensions
                        req.extensions_mut().insert(username_owned);
                        req.extensions_mut().insert(app_id_owned);
                        req.extensions_mut().insert(UserInfo {
                            home_dir: data_dir,
                            uid,
                            gid,
                        });
                        return Ok(next.run(req).await);
                    }
                }
            }
        }

        return Err(ErrorResponse::new(
            "unauthorized",
            Some("X-Remote-User header required but not found or invalid".to_string()),
        ));
    }

    // For PAM and Config auth, extract token from cookie
    let token = jar
        .get("fleabox_token")
        .ok_or_else(|| {
            ErrorResponse::new(
                "unauthorized",
                Some("Missing authentication token".to_string()),
            )
        })?
        .value()
        .to_string();

    // Look up token in store
    let token_info = {
        let store = state.token_store.read().unwrap();
        store.get(&token).cloned()
    };

    let token_info = token_info
        .ok_or_else(|| ErrorResponse::new("unauthorized", Some("Invalid token".to_string())))?;

    // Check if token is expired
    if token_info.is_expired() {
        // Clean up expired token
        let mut store = state.token_store.write().unwrap();
        store.remove(&token);
        return Err(ErrorResponse::new(
            "unauthorized",
            Some("Token expired".to_string()),
        ));
    }

    // Extract app_id from the request path
    // Path format: /api/<app_id>/data/<path>
    let uri_path = req.uri().path();
    let app_id = uri_path
        .strip_prefix("/api/")
        .and_then(|s| s.split('/').next())
        .ok_or_else(|| ErrorResponse::new("bad_request", Some("Invalid API path".to_string())))?;

    // Verify token's app matches the requested app (or is wildcard)
    if token_info.app != "*" && token_info.app != app_id {
        return Err(ErrorResponse::new(
            "unauthorized",
            Some(format!("Token not valid for app '{}'", app_id)),
        ));
    }

    // Store user info in request extensions (use data_dir, uid, gid from token)
    req.extensions_mut().insert(UserInfo {
        home_dir: token_info.data_dir,
        uid: token_info.uid,
        gid: token_info.gid,
    });

    Ok(next.run(req).await)
}
