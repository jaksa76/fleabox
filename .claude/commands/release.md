Release the project. If no arguments are provided, ask the user for the version before proceeding.

The version must not include a leading `v` (e.g. `0.3.1`).

Available options (pass after the version):
- `--dry-run` — print actions without modifying files or running commands
- `--allow-dirty` — allow releasing with uncommitted changes
- `--skip-tests` — skip `cargo test`
- `--e2e` — also run Playwright e2e tests
- `--draft` — create the GitHub Release as a draft

Steps to perform:
1. Run `cargo clippy` and confirm there are no errors before proceeding.
2. Run `scripts/release.sh $ARGUMENTS` from the repo root.

The script will:
1. Bump the version in `Cargo.toml`
2. Run `cargo test` and `cargo build --release` (unless skipped)
3. Commit the version bump, tag it `v<version>`, and push
4. Create a GitHub Release with the release binary attached

This is an irreversible operation that pushes commits and tags to the remote and publishes a GitHub Release. Confirm with the user before running unless `--dry-run` was specified.
