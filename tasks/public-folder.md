Add the ability to have a public folder.

- Each user has an app specific public folder.
- A user has full access over their public folder via /api/<app-id>/public/. The semantics are teh same as for the user's private folder.
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

### 1. Storage Structure
- Store each user's public folder at:
  - PAM/Reverse Proxy: `~<user>/.local/share/fleabox/public/<app-id>/`
  - Config auth: `<user_data_dir>/public/<app-id>/`
  - Dev mode: `~/.local/share/fleabox/public/<app-id>/`
- Create public directory lazily on first write operation
- Follow existing data folder pattern but use `/public/` instead of `/data/`

### 2. API Endpoints

#### Owner Access (Full CRUD)
- **GET** `/api/<app-id>/public/*path` - Read files or list directories
- **PUT** `/api/<app-id>/public/*path` - Create/update files
- **DELETE** `/api/<app-id>/public/*path` - Delete files/directories
- Uses existing `token_auth_middleware` for authentication
- Same semantics as `/api/<app-id>/data/*path`

#### Public Read Access (No Authentication)
- **GET** `/<app-id>/~<user-id>/*path` - Read files only
- No directory listing allowed (return 403 if path is a directory)
- No authentication required
- Only GET method supported
- If path is a directory and `index.html` exists, serve `index.html`
- If path is a directory and no `index.html`, return 403
- Clean URL pattern following Unix tilde convention for user content

### 3. Implementation Steps

#### Step 1: Add helper function for user data directory resolution
```rust
fn resolve_user_data_dir(
    username: &str,
    auth_type: &AuthType,
    config: &Option<Arc<Config>>
) -> Result<PathBuf, ErrorResponse>
```
- For PAM/Reverse Proxy: use `get_user_home()` → `~/.local/share/fleabox`
- For Config: lookup user in config, return `<user_data_dir>`
- For Dev mode: return current user's `~/.local/share/fleabox`
- Return 404 error if user not found

#### Step 2: Add new API handlers
- `api_get_public_data(Path, Request)` - Owner GET with directory listing
  - Similar to `api_get_data()` but uses `public/` instead of `data/`
- `api_put_public_data(Path, Request)` - Owner PUT
  - Similar to `api_put_data()` but uses `public/` instead of `data/`
- `api_delete_public_data(Path, Request)` - Owner DELETE
  - Similar to `api_delete_data()` but uses `public/` instead of `data/`
- `api_get_user_public_data(Path((app_id, user_id, path)), State)` - Public read-only
  - No authentication required
  - Resolve user's data directory using `resolve_user_data_dir()`
  - Validate and resolve path
  - If directory: check for `index.html`, serve it if exists, else return 403
  - If file: serve with proper MIME type

#### Step 3: Add routes in main()
```rust
// Owner's public folder routes (authenticated, in api_routes)
.route("/api/:app_id/public/*path", get(api_get_public_data))
.route("/api/:app_id/public/*path", put(api_put_public_data))
.route("/api/:app_id/public/*path", delete(api_delete_public_data))
.layer(middleware::from_fn_with_state(state.clone(), token_auth_middleware))

// Public read access routes (no auth, separate from api_routes)
.route("/:app_id/~:user_id/*path", get(api_get_user_public_data))
```

#### Step 4: Handle index.html serving for directories
- In `api_get_user_public_data()`:
  - Check if resolved path is a directory
  - If directory: check for `index.html` in that directory
  - If `index.html` exists: read and serve with `text/html` MIME type
  - If `index.html` doesn't exist: return 403 with message "Directory listing not allowed"
  - If file: serve normally with MIME type detection

#### Step 5: Path validation and security
- Reuse existing `validate_and_resolve_path()` for path traversal protection
- Validate `user_id` parameter to prevent injection attacks
- Public root for owner: `user_info.home_dir.join("public").join(&app_id)`
- Public root for public access: `resolve_user_data_dir().join("public").join(&app_id)`

#### Step 6: Dev mode handling
- In dev mode, treat user-id "dev" as the current user
- Use current user's home directory for "dev" user
- Allow unauthenticated access to `/api/<app-id>/users/dev/public/*path`

#### Step 7: Testing
- Test owner CRUD operations on public folder
- Test public read access from unauthenticated requests
- Test directory listing blocked (403) for public access
- Test index.html serving for directories in public access
- Test with all three auth modes (PAM, Config, Reverse Proxy)
- Test dev mode with user-id "dev" (/<app-id>/~dev/*path)
- Test path traversal attack prevention
- Test file MIME types served correctly
- Test 404 for non-existent users
- Test 404 for non-existent files
- Test nested folder creation on PUT

### 4. Security Considerations
- Reuse existing path traversal protection from `validate_and_resolve_path()`
- Validate user_id in public access routes (alphanumeric, hyphens, underscores only)
- Check that user exists before attempting file access (return 404 if not)
- Public access has no authentication but is read-only (enforced by routing)
- Ensure public access cannot escalate to write operations

### 5. Edge Cases to Handle
- Non-existent user in public access route: return 404 "User not found"
- Non-existent file in public access route: return 404 "File not found"
- Directory without index.html in public route: return 403 "Directory listing not allowed"
- Directory with index.html in public route: serve the index.html
- Empty path handling: treat as root of public folder
- Create nested directories automatically on PUT operations
- First write to public folder: create `public/<app-id>` structure
- Symbolic links: should be followed or rejected?

