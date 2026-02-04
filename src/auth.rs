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
        .card {{
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 16px;
            padding: 28px;
            backdrop-filter: blur(6px);
        }}
        label {{
            display: block;
            margin-bottom: 8px;
            font-size: 0.88rem;
            color: #c7d2fe;
        }}
        input {{
            width: 100%;
            padding: 12px 12px;
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.10);
            background: rgba(0,0,0,0.28);
            color: white;
            outline: none;
            font-size: 1rem;
        }}
        input:focus {{
            border-color: rgba(56, 189, 248, 0.45);
            box-shadow: 0 0 0 4px rgba(56,189,248,0.10);
        }}
        .field {{
            margin-bottom: 16px;
        }}
        button {{
            width: 100%;
            margin-top: 8px;
            padding: 12px 14px;
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.10);
            background: linear-gradient(180deg, rgba(56,189,248,0.22), rgba(56,189,248,0.12));
            color: white;
            font-size: 1rem;
            cursor: pointer;
        }}
        button:disabled {{
            opacity: 0.6;
            cursor: not-allowed;
        }}
        .error {{
            display: none;
            margin-top: 14px;
            padding: 10px 12px;
            border-radius: 12px;
            background: rgba(239,68,68,0.12);
            border: 1px solid rgba(239,68,68,0.25);
            color: rgba(254,226,226,0.95);
            font-size: 0.9rem;
        }}
        .footer {{
            margin-top: 18px;
            text-align: center;
            color: #728096;
            font-size: 0.82rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Login</h1>
        <div class="subtitle">fleabox {}</div>
        <div class="card">
            <form id="loginForm">
                <div class="field">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required autofocus autocomplete="username" />
                </div>
                <div class="field">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required autocomplete="current-password" />
                </div>
                <button type="submit" id="submitBtn">Login</button>
                <div class="error" id="error"></div>
            </form>
        </div>
        <div class="footer">Passwords are encrypted in-browser (RSA-OAEP).</div>
    </div>

    <script>
        const publicKeyPem = `{public_key_pem}`;
        const nextUrl = {next_json};

        async function importPublicKey(pem) {{
            const pemHeader = "-----BEGIN PUBLIC KEY-----";
            const pemFooter = "-----END PUBLIC KEY-----";
            const pemContents = pem
                .replace(pemHeader, "")
                .replace(pemFooter, "")
                .replace(/\s/g, "");

            const binaryDerString = atob(pemContents);
            const binaryDer = new Uint8Array(binaryDerString.length);
            for (let i = 0; i < binaryDerString.length; i++) {{
                binaryDer[i] = binaryDerString.charCodeAt(i);
            }}

            return crypto.subtle.importKey(
                "spki",
                binaryDer.buffer,
                {{ name: "RSA-OAEP", hash: "SHA-256" }},
                false,
                ["encrypt"]
            );
        }}

        async function encryptPassword(password) {{
            const publicKey = await importPublicKey(publicKeyPem);
            const enc = new TextEncoder();
            const encrypted = await crypto.subtle.encrypt(
                {{ name: "RSA-OAEP" }},
                publicKey,
                enc.encode(password)
            );
            const bytes = new Uint8Array(encrypted);
            let binary = "";
            for (let i = 0; i < bytes.byteLength; i++) {{
                binary += String.fromCharCode(bytes[i]);
            }}
            return btoa(binary);
        }}

        document.getElementById('loginForm').addEventListener('submit', async (e) => {{
            e.preventDefault();
            const errorDiv = document.getElementById('error');
            const submitBtn = document.getElementById('submitBtn');
            errorDiv.style.display = 'none';
            submitBtn.disabled = true;
            submitBtn.textContent = 'Signing in…';

            try {{
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const encrypted_password = await encryptPassword(password);

                const response = await fetch('/login', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ username, encrypted_password }})
                }});

                if (response.ok) {{
                    window.location.href = nextUrl || '/';
                }} else {{
                    let msg = 'Login failed';
                    try {{
                        const data = await response.json();
                        msg = data.message || data.error || msg;
                    }} catch (_) {{}}
                    errorDiv.textContent = msg;
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

    // Set cookie
    let cookie = Cookie::build(("fleabox_token", token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::hours(8));

    let jar = jar.add(cookie);

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
