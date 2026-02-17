# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

Fleabox is a self-hosted application hub written in Rust. It's a single binary that serves static web apps (HTML/CSS/JS) over HTTP, with per-user, per-app data stored on the filesystem via a simple REST API. There is no database and no server-side app logic — apps are pure static files that talk to the data API.

## Commands

### Build & Run

```bash
cargo build                          # Debug build
cargo build --release                # Release build

cargo run -- --dev --apps-dir ./examples   # Dev mode (no auth, current user)
cargo run -- --auth config --config config.json  # Config-file auth
cargo run -- --help                  # Show all CLI options
```

### Tests

```bash
cargo test                           # Run all unit tests
cargo test test_name                 # Run a single test by name

# E2E tests (Playwright/TypeScript)
cd e2e && npm install
npm test                             # Run all e2e tests
npm run test:auth                    # Auth tests only (spin up own server)
npm run test:app                     # App tests only (shared dev server)
npm run test:debug                   # Interactive UI mode
```

### Lint

```bash
cargo clippy
```

## Architecture

### Server (src/)

The binary is built with **Axum** (async web framework) on **Tokio**. The router is assembled in `main.rs` with these route groups:

- `/login`, `/logout` — Auth pages/handlers
- `/api/:app_id/data/*` — Private per-user data (requires session token)
- `/api/:app_id/public/*` — Public data (requires session token to write)
- `/:app_id/~:user_id/*` — Cross-user public data reads (no auth required)
- `/:app_id/`, `/:app_id/*file` — Static file serving for app assets

**Two middleware layers**:
- `public_page_auth_middleware` — handles page requests, redirects to login
- `token_auth_middleware` — validates session tokens for API requests

### Auth Modes (`src/auth.rs`)

Three modes selectable via `--auth` flag:
1. **PAM** (default) — System user login via PAM, requires root. RSA-2048 (OAEP) encrypts passwords client-to-server.
2. **Config** — Standalone user/password file (`config.json`). No root required.
3. **None** — Trusts `X-Remote-User` header from a reverse proxy.

Session tokens are stored in an `Arc<RwLock<HashMap>>` with 8-hour expiry.

### Data Storage (`src/private_data.rs`, `src/public_data.rs`)

Files are stored on the filesystem:
- **PAM auth**: `~/.local/share/fleabox/<app-id>/data/` and `.../public/`
- **Config auth**: `<data_dir>/<app-id>/data/` and `.../public/`

The REST API is GET (read/list), PUT (write, max 10MB, auto-creates dirs), DELETE (supports `?recursive=true`). Directory GETs return JSON metadata listings.

### Apps (`examples/`)

Apps are directories containing `index.html` and optionally a `static/` subfolder. They run entirely client-side and call the Fleabox data API via `fetch`. See `AGENT_INSTRUCTIONS.md` for the API contract that apps use.

### Security (`src/fs_utils.rs`, `src/user.rs`)

Path components are strictly validated to prevent traversal: no `.`, `..`, null bytes, Windows drive letters, or double slashes. User IDs are validated before use in paths. When running as root (PAM mode), created files are `chown`ed to the authenticated user's uid/gid.

## Key Files

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI parsing, router setup, server startup |
| `src/auth.rs` | All three auth modes, session tokens, login page |
| `src/private_data.rs` | Private data CRUD API |
| `src/public_data.rs` | Public data CRUD API + cross-user reads |
| `src/static_pages.rs` | Homepage rendering, static file serving |
| `src/fs_utils.rs` | `chown`, path validation helpers |
| `src/user.rs` | POSIX user lookup (getpwnam_r) |
| `src/error.rs` | `ErrorResponse` with HTTP status mapping |
| `AGENT_INSTRUCTIONS.md` | API reference for building apps on Fleabox |
| `e2e/` | Playwright tests; auth tests spin up their own server instances |
