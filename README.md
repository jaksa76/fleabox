# Fleabox

**Fleabox** is a tiny, self-hosted application hub.

It is a single Rust executable that serves multiple static web apps over HTTP,
with per-user, per-app data stored directly on the filesystem.
There is no database, no plugin system, and no server-side app code.

The goal is to make personal web apps boring, inspectable, and easy to back up.
