Add the ability to have a public folder.

- Each user has an app specific public folder.
- A user has full access over their public folder via /api/<app-id>/public/. The semantics are the same as for the user's private folder.
- Other users have read-only access to another user's public folder via /<app-id>/~<user-id>/*path
- Other users cannot list folders/files in another user's public folder, they can only access a file if they know the exact path.
- Users don't need to be authenticated to access another user's public folder.
- fleabox stores the public folder under ~<user-id>/.local/share/fleabox/public/<app-id>/ if PAM or reverse proxy authentication is used.
- fleabox stores the public folder under <user_data_dir>/public/<app-id>/ if config authentication is used.
- Users should be able to generate static websites in their public folder.
- if a user uploads an index.html file to a folder in their public folder, accessing that folder should serve the index.html file.
- public folder structure should be created on the first write.
- accessing a non existing public folder should return a 404.
- files should be served with correct mime types.
- in dev mode there is only one user with user-id "dev"
- in dev mode the public folder is stored under ~/.local/share/fleabox/public/<app-id>/

## Implementation Plan

### Modules and Functions to Add/Update

#### New Module: `src/public_data.rs`
**New Functions:**
- `api_get_public_data(Path<(String, String)>, Request) -> Result<Response, ErrorResponse>`
  - Owner's GET handler for `/api/:app_id/public/*path`
  - Allows directory listing for owner
  - Mirrors `api_get_data()` but uses `public/` subdirectory
  
- `api_put_public_data(Path<(String, String)>, Request) -> Result<Response, ErrorResponse>`
  - Owner's PUT handler for `/api/:app_id/public/*path`
  - Creates public folder structure lazily on first write
  - Mirrors `api_put_data()` but uses `public/` subdirectory
  
- `api_delete_public_data(Path<(String, String)>, Request) -> Result<Response, ErrorResponse>`
  - Owner's DELETE handler for `/api/:app_id/public/*path`
  - Mirrors `api_delete_data()` but uses `public/` subdirectory
  
- `api_get_user_public_data(Path<(String, String, String)>, State<AppState>) -> Result<Response, ErrorResponse>`
  - Public read-only GET handler for `/:app_id/~:user_id/*path`
  - No authentication required
  - No directory listing (returns 403 for directories without index.html)
  - Serves index.html if present in directory
  - Resolves user data directory based on auth type

#### Updated Module: `src/user.rs`
**New Functions:**
- `resolve_user_data_dir(username: &str, auth_type: &AuthType, config: &Option<Arc<Config>>, dev_mode: bool) -> Result<PathBuf, ErrorResponse>`
  - Resolves the base data directory for a given user
  - PAM/None auth: Returns `~/.local/share/fleabox` for the user
  - Config auth: Returns `user_data_dir` from config for the user
  - Dev mode: Returns current user's `~/.local/share/fleabox`
  - Returns ErrorResponse if user not found

**New Functions:**
- `validate_user_id(user_id: &str) -> Result<(), ErrorResponse>`
  - Validates user_id contains only alphanumeric, hyphens, underscores, and dots
  - Prevents path traversal and injection attacks

#### Updated Module: `src/main.rs`
**Changes:**
- Add `mod public_data;` declaration at top
- In `main()` function:
  - Add owner public folder routes to `api_routes`:
    ```rust
    .route("/api/:app_id/public/*path", get(public_data::api_get_public_data))
    .route("/api/:app_id/public/*path", put(public_data::api_put_public_data))
    .route("/api/:app_id/public/*path", delete(public_data::api_delete_public_data))
    ```
  - Add public read access route (before merging with api_routes):
    ```rust
    .route("/:app_id/~:user_id/*path", get(public_data::api_get_user_public_data))
    ```

#### Updated Module: `src/fs_utils.rs`
**New Functions (optional helper):**
- `serve_file_with_mime(path: &PathBuf) -> Result<Response, ErrorResponse>`
  - Helper to read file and serve with correct MIME type
  - Can be reused by both private and public data handlers
  - Currently this logic is inline in handlers, extracting for reuse

#### Module: `src/cli.rs`
**No changes required** - Config structure already supports data_dir

#### Module: `src/auth.rs`  
**No changes required** - Existing token_auth_middleware will be used for owner routes

---

## Detailed Implementation Steps

### Step 1: Create `src/user.rs` helper functions

**Function: `validate_user_id(user_id: &str) -> Result<(), ErrorResponse>`**
- Validates user_id contains only safe characters (alphanumeric, hyphens, underscores, dots)
- Rejects "." and ".." to prevent path traversal
- Returns ErrorResponse with "bad_request" status if invalid

**Function: `resolve_user_data_dir(username: &str, auth_type: &AuthType, config: &Option<Arc<Config>>, dev_mode: bool) -> Result<PathBuf, ErrorResponse>`**
- If dev_mode is true: return current user's `~/.local/share/fleabox`
- If auth_type is PAM or None:
  - Call `get_user_home(username)` to get user's home directory
  - Return `home_dir.join(".local/share/fleabox")`
  - Return 404 ErrorResponse if user not found
- If auth_type is Config:
  - Look up user in config.users
  - Return `PathBuf::from(user.data_dir)`
  - Return 404 ErrorResponse if user not found

### Step 2: Create new module `src/public_data.rs`

**Function: `api_get_public_data(Path<(String, String)>, Request) -> Result<Response, ErrorResponse>`**
- Extract `UserInfo` from request extensions (set by token_auth_middleware)
- Build public_root: `user_info.home_dir.join(&app_id).join("public")`
- Return 404 if public_root doesn't exist
- Call `validate_and_resolve_path(&public_root, &path)`
- If path is a file: read and serve with MIME type (same as `api_get_data`)
- If path is a directory: return JSON listing (same as `api_get_data`)

**Function: `api_put_public_data(Path<(String, String)>, Request) -> Result<Response, ErrorResponse>`**
- Extract `UserInfo` from request extensions
- Build public_root: `user_info.home_dir.join(&app_id).join("public")`
- Create public_root lazily if it doesn't exist using `create_dir_all`
- Call `chown_created_dirs` on newly created directories
- Call `validate_and_resolve_path(&public_root, &path)`
- Create parent directories if needed with `create_dir_all`
- Write file atomically using temp file + rename pattern (same as `api_put_data`)
- Call `chown_path` to set ownership
- Return 201 CREATED on success

**Function: `api_delete_public_data(Path<(String, String)>, Request) -> Result<Response, ErrorResponse>`**
- Extract `UserInfo` from request extensions
- Build public_root: `user_info.home_dir.join(&app_id).join("public")`
- Return 404 if public_root doesn't exist
- Call `validate_and_resolve_path(&public_root, &path)`
- If file: call `remove_file`
- If directory: call `remove_dir_all`
- Return 200 OK on success

**Function: `api_get_user_public_data(Path<(String, String, String)>, State<AppState>) -> Result<Response, ErrorResponse>`**
- Extract `(app_id, user_id, path)` from path parameters
- Extract `AppState` from state
- Call `validate_user_id(&user_id)` to prevent injection attacks
- Call `resolve_user_data_dir(&user_id, &state.auth_type, &state.config, state.dev_mode)`
- Build public_root: `base_dir.join("public").join(&app_id)`
- Return 404 if public_root doesn't exist
- Call `validate_and_resolve_path(&public_root, &path)`
- Return 404 if resolved_path doesn't exist
- Get metadata of resolved_path
- If path is a file:
  - Read file contents
  - Detect MIME type with `mime_guess::from_path`
  - Return response with appropriate Content-Type header
- If path is a directory:
  - Check if `index.html` exists in directory
  - If yes: read and serve `index.html` with `text/html` MIME type
  - If no: return 403 with message "Directory listing not allowed"

### Step 3: Update `src/main.rs`

**At top of file:**
- Add `mod public_data;` declaration

**In `main()` function, in the `api_routes` Router:**
- After the existing `/api/:app_id/data/*path` routes, add:
  ```rust
  .route("/api/:app_id/public/*path", get(public_data::api_get_public_data))
  .route("/api/:app_id/public/*path", put(public_data::api_put_public_data))
  .route("/api/:app_id/public/*path", delete(public_data::api_delete_public_data))
  ```
- These will be covered by the existing `token_auth_middleware` layer

**In `main()` function, when building the final app Router:**
- Before `.merge(api_routes)`, add:
  ```rust
  .route("/:app_id/~:user_id/*path", get(public_data::api_get_user_public_data))
  ```
- This route has no authentication middleware

### Step 4: Testing Strategy

**Owner CRUD Operations:**
- Test PUT to create file in public folder (should create structure lazily)
- Test GET to read file from public folder
- Test GET to list directory in public folder
- Test DELETE to remove file from public folder
- Test DELETE to remove directory from public folder
- Test PUT to nested paths (should create parent directories)

**Public Read Access:**
- Test unauthenticated GET to read file via `/:app_id/~:user_id/file.txt`
- Test GET to directory without index.html (should return 403)
- Test GET to directory with index.html (should serve index.html)
- Test GET to non-existent file (should return 404)
- Test GET with invalid user_id (should return 404)
- Test GET with path traversal attempts (should return 400)

**Auth Mode Tests:**
- Test with PAM auth (uses ~/.local/share/fleabox)
- Test with Config auth (uses data_dir from config)
- Test with Dev mode (uses current user's home)

**Security Tests:**
- Test path traversal protection (../../../etc/passwd)
- Test user_id injection attempts
- Test that public routes don't allow POST/PUT/DELETE
- Test that owner can only access their own public folder

---

## API Endpoints Summary

### Owner Access (Authenticated)
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/:app_id/public/*path` | Read file or list directory | Yes (token) |
| PUT | `/api/:app_id/public/*path` | Create/update file | Yes (token) |
| DELETE | `/api/:app_id/public/*path` | Delete file/directory | Yes (token) |

### Public Read Access (Unauthenticated)
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/:app_id/~:user_id/*path` | Read file only | No |

---

## Storage Paths by Auth Type

| Auth Type | Storage Location |
|-----------|------------------|
| PAM | `~<user>/.local/share/fleabox/public/<app-id>/` |
| Config | `<user_data_dir>/public/<app-id>/` |
| Reverse Proxy (None) | `~<user>/.local/share/fleabox/public/<app-id>/` |
| Dev Mode | `~/.local/share/fleabox/public/<app-id>/` |

---

## Security Considerations

1. **Path Traversal Protection**: Reuse existing `validate_and_resolve_path()` function which:
   - Rejects leading slashes
   - Validates each path component
   - Prevents ".." and "." components
   - Ensures resolved path stays within base directory

2. **User ID Validation**: New `validate_user_id()` function ensures:
   - Only alphanumeric, hyphens, underscores, and dots allowed
   - Prevents injection attacks
   - Blocks "." and ".." to prevent path traversal

3. **Authentication Enforcement**:
   - Owner routes protected by existing `token_auth_middleware`
   - Public routes are read-only by design (no POST/PUT/DELETE routes registered)
   - Public access cannot escalate to write operations

4. **User Existence Check**:
   - `resolve_user_data_dir()` returns 404 if user doesn't exist
   - Prevents probing for valid usernames via error messages

5. **File Size Limits**:
   - Reuse existing 10MB limit from `api_put_data()` to prevent DoS

6. **Directory Listing Privacy**:
   - Public access explicitly blocks directory listing
   - Returns 403 for directories without index.html
   - Owner can still list their own directories

---

## Edge Cases

1. **Non-existent user**: `resolve_user_data_dir()` returns 404 ErrorResponse
2. **Non-existent file in public route**: Standard 404 response
3. **Directory without index.html**: Return 403 "Directory listing not allowed"
4. **Directory with index.html**: Serve the index.html file
5. **Empty path**: Treat as root of public folder
6. **Nested directory creation**: `create_dir_all` handles this automatically
7. **First write to public folder**: Creates `public/<app-id>/` structure lazily
8. **Symbolic links**: Follow standard filesystem behavior (system resolves symlinks)
9. **Concurrent writes**: Atomic write pattern (temp file + rename) prevents corruption
10. **Dev mode user**: Special handling for "dev" user_id maps to current user

---

## Implementation Checklist

- [ ] Create `src/public_data.rs` module
  - [ ] Implement `api_get_public_data()`
  - [ ] Implement `api_put_public_data()`
  - [ ] Implement `api_delete_public_data()`
  - [ ] Implement `api_get_user_public_data()`
- [ ] Update `src/user.rs`
  - [ ] Implement `validate_user_id()`
  - [ ] Implement `resolve_user_data_dir()`
- [ ] Update `src/main.rs`
  - [ ] Add `mod public_data;` declaration
  - [ ] Add owner public folder routes to `api_routes`
  - [ ] Add public read access route to main router
- [ ] Write tests
  - [ ] Owner CRUD operations
  - [ ] Public read access
  - [ ] Auth mode variations
  - [ ] Security tests (path traversal, user validation)
  - [ ] Edge cases (404s, 403s, index.html)
- [ ] Manual testing
  - [ ] Test with PAM auth
  - [ ] Test with Config auth
  - [ ] Test with Dev mode
  - [ ] Test static website hosting with index.html



