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

### Data Storage

Each app can read and write its own data in JSON format. The data is stored in the user's home directory under `~/.local/share/fleabox/<app-id>/data/`.


### Authentication

Fleabox relies on having a reverse proxy in front of it that handles authentication. Each user's data is isolated in their own directory. The username must be passed to Fleabox via the `X-Remote-User` HTTP header.


## Developer's Guide

Building the application:

```bash
cargo build --release
```

Running tests:

```bash
cargo test
```

You can copy the examples folder into /srv/fleabox/ to try out the sample apps. Then you should run it with:

```bash
cargo run -- --dev
```
