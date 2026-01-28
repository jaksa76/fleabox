# Fleabox

**Fleabox** is a tiny, self-hosted application hub.

It is a single Rust executable that serves multiple static web apps over HTTP,
with per-user, per-app data stored directly on the filesystem.
There is no database, no plugin system, and no server-side app code.

The goal is to make personal web apps boring, inspectable, and easy to back up.

## User's Guide

### Setup

Fleabag will serve any static app in /srv/fleabox/<app-id>. For the time being, you need to create this directory structure manually. App installation is an upcoming feature.

Once you have placed your app in the appropriate directory, start the Fleabox server:

```bash
fleabox
```

This will serve the app at `http://localhost:3000/<app-id>`.

### Configuration

#### Custom Apps Directory

You can override the default apps directory (`/srv/fleabox`) using the `--apps-dir` command line option:

```bash
fleabox --apps-dir /path/to/your/apps
```

This is useful for development or when you want to store your apps in a custom location.

### Data Storage

Each app can read and write its own data in JSON format. The data storage location depends on the authentication mode:

- **PAM authentication**: Data is stored in `~/.local/share/fleabox/<app-id>/data/` where `~` is the authenticated user's home directory
- **Config authentication**: Data is stored in `<data_dir>/<app-id>/data/` where `<data_dir>` is specified for each user in the config file
- **Reverse proxy authentication**: Data is stored in `~/.local/share/fleabox/<app-id>/data/` where `~` is the home directory of the user identified by the `X-Remote-User` header
- **Dev mode**: Data is stored in `~/.local/share/fleabox/<app-id>/data/` where `~` is the home directory of the user running fleabox

### Authentication

Fleabox supports three authentication modes:

#### 1. PAM Authentication (default)

Uses system PAM authentication to verify users against OS credentials. This requires the PAM library at both compile time and runtime.

```bash
# Build with PAM support
cargo build --features pam --release

# Run with PAM authentication
fleabox --auth=pam
```

Data is stored in each user's home directory at `~/.local/share/fleabox/<app-id>/data/`.

**Requirements:**
- Compile time: `libpam-dev` (Debian/Ubuntu) or `pam-devel` (RHEL/Fedora)
- Runtime: `libpam0g` (usually pre-installed on Linux systems)

#### 2. Config File Authentication

Uses a JSON configuration file to define users, passwords, and data directories. This mode does not require PAM.

```bash
# Run with config-based authentication
fleabox --auth=config --config=/path/to/config.json
```

**Config file format:**
```json
{
  "users": [
    {
      "username": "alice",
      "password": "changeme123",
      "data_dir": "/home/alice"
    },
    {
      "username": "bob",
      "password": "secret456",
      "data_dir": "/mnt/data/bob"
    }
  ]
}
```

Each user's data is stored in their configured `data_dir` at `<data_dir>/<app-id>/data/`.

See [config.example.json](config.example.json) for a complete example.

#### 3. Reverse Proxy Authentication

Expects authentication to be handled by a reverse proxy (like nginx, Apache, or Caddy) that sets the `X-Remote-User` header. Fleabox trusts this header to identify the user.

```bash
# Run with reverse proxy authentication
fleabox --auth=none
```

Data is stored in `~<username>/.local/share/fleabox/<app-id>/data/` where `<username>` is from the `X-Remote-User` header.

**Example nginx configuration:**
```nginx
location / {
    auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/.htpasswd;
    
    proxy_pass http://localhost:3000;
    proxy_set_header X-Remote-User $remote_user;
}
```

**Security note:** Only use this mode when fleabox is behind a properly configured reverse proxy. Never expose it directly to the internet with `--auth=none`.


## Developer's Guide

### Building

Building the application without PAM support:

```bash
cargo build --release
```

Building with PAM support:

```bash
cargo build --features pam --release
```

### Running Tests

Unit tests:

```bash
cargo test
```

End-to-end tests:

```bash
cd e2e
npm install
npm test
```

The e2e tests include comprehensive testing of all authentication modes.

### Development Mode

You can copy the examples folder into /srv/fleabox/ to try out the sample apps. Then you should run it with:

```bash
cargo run -- --dev
```

Or you can use a custom directory:

```bash
cargo run -- --dev --apps-dir ./examples
```

Dev mode bypasses authentication and uses the current user running the process. This makes it easy to develop and test apps locally without setting up authentication.
