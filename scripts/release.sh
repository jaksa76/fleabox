#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/release.sh <version> [options]

Automates a local release for the fleabox Rust crate.

Arguments:
  <version>           Version to release (e.g. 0.3.0). Do not include a leading 'v'.

Options:
  --dry-run           Print actions; do not modify files or run commands.
  --allow-dirty       Allow releasing with uncommitted changes.
  --skip-tests        Skip `cargo test`.
  --e2e               Run Playwright e2e tests (requires `npm install` in ./e2e).
  --skip-build        Skip `cargo build --release`.
  --no-tag            Do not create a git tag.
  --push              Push the release commit and tag to `origin`.
  --draft             Create the GitHub Release as a draft.
  --dist              Create a tar.gz artifact in ./dist (default).
  --no-dist           Do not create a dist artifact.
  -h, --help          Show this help.

Examples:
  scripts/release.sh 0.3.0
  scripts/release.sh 0.3.0 --e2e
  scripts/release.sh 0.3.0 --dry-run
  scripts/release.sh 0.3.0 --draft
USAGE
}

say() { printf '%s\n' "$*"; }

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

run() {
  if [[ "${DRY_RUN}" == "1" ]]; then
    say "+ $*"
  else
    say "+ $*"
    "$@"
  fi
}

run_bash() {
  if [[ "${DRY_RUN}" == "1" ]]; then
    say "+ $*"
  else
    say "+ $*"
    bash -lc "$*"
  fi
}

if [[ ${#} -lt 1 ]]; then
  usage
  exit 2
fi

VERSION=""
DRY_RUN=0
ALLOW_DIRTY=0
SKIP_TESTS=0
RUN_E2E=0
SKIP_BUILD=0
NO_TAG=0
DO_PUSH=1
GITHUB_DRAFT=0
DO_DIST=1

# First positional is version, then options.
VERSION="$1"
shift

while [[ ${#} -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --allow-dirty) ALLOW_DIRTY=1 ;;
    --skip-tests) SKIP_TESTS=1 ;;
    --e2e) RUN_E2E=1 ;;
    --skip-build) SKIP_BUILD=1 ;;
    --no-tag) NO_TAG=1 ;;
    --push) DO_PUSH=1 ;;
    --draft) GITHUB_DRAFT=1 ;;
    --dist) DO_DIST=1 ;;
    --no-dist) DO_DIST=0 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
  shift
done

# Basic version validation (SemVer-ish).
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  die "Invalid version '$VERSION' (expected like 0.3.0)"
fi
if [[ "$VERSION" == v* ]]; then
  die "Pass version without a leading 'v' (got '$VERSION')"
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

command -v git >/dev/null 2>&1 || die "git not found"
command -v cargo >/dev/null 2>&1 || die "cargo not found"
command -v python3 >/dev/null 2>&1 || die "python3 not found (used to edit Cargo.toml safely)"
command -v gh >/dev/null 2>&1 || die "gh not found (install GitHub CLI and run 'gh auth login')"

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "Not inside a git repository"

if git rev-parse -q --verify "refs/tags/v$VERSION" >/dev/null; then
  die "Tag v$VERSION already exists"
fi

if [[ "$NO_TAG" == "1" ]]; then
  die "--no-tag is not supported because releases are always published to GitHub"
fi

if [[ "$ALLOW_DIRTY" != "1" ]]; then
  if [[ -n "$(git status --porcelain)" ]]; then
    die "Working tree is dirty. Commit/stash changes, or use --allow-dirty."
  fi
fi

CURRENT_VERSION="$(python3 - <<'PY'
import re
from pathlib import Path
text = Path('Cargo.toml').read_text(encoding='utf-8')
# Find the [package] section and version within it.
# Simple approach: scan lines after [package] until next [section].
lines = text.splitlines(True)
in_pkg = False
for line in lines:
    if line.strip() == '[package]':
        in_pkg = True
        continue
    if in_pkg and re.match(r'^\s*\[', line):
        break
    if in_pkg:
        m = re.match(r'^\s*version\s*=\s*"([^"]+)"\s*$', line)
        if m:
            print(m.group(1))
            raise SystemExit(0)
raise SystemExit('Could not find [package].version in Cargo.toml')
PY
)"

if [[ "$CURRENT_VERSION" == "$VERSION" ]]; then
  die "Cargo.toml already at version $VERSION"
fi

say "Releasing fleabox $CURRENT_VERSION -> $VERSION"

# 1) Update Cargo.toml.
if [[ "${DRY_RUN}" == "1" ]]; then
  say "+ Update Cargo.toml [package].version -> ${VERSION}"
else
  RELEASE_VERSION="$VERSION" python3 - <<'PY'
import os
import re
from pathlib import Path

new_version = os.environ["RELEASE_VERSION"]
path = Path("Cargo.toml")
text = path.read_text(encoding="utf-8")
lines = text.splitlines(True)

out = []
in_pkg = False
changed = False

for line in lines:
  if line.strip() == "[package]":
    in_pkg = True
    out.append(line)
    continue

  if in_pkg and re.match(r"^\s*\[", line):
    in_pkg = False
    out.append(line)
    continue

  if in_pkg:
    m = re.match(r"^(\s*version\s*=\s*)\"[^\"]+\"(\s*)$", line)
    if m:
      out.append(f"{m.group(1)}\"{new_version}\"{m.group(2)}\n")
      changed = True
      continue

  out.append(line)

if not changed:
  raise SystemExit("Failed to update [package].version in Cargo.toml")

path.write_text("".join(out), encoding="utf-8")
PY
fi

# 2) Verify build/tests.
if [[ "$SKIP_TESTS" != "1" ]]; then
  run cargo test
fi
if [[ "$SKIP_BUILD" != "1" ]]; then
  run cargo build --release
fi

if [[ "$RUN_E2E" == "1" ]]; then
  if [[ -f e2e/package.json ]]; then
    run_bash "cd e2e && npm test"
  else
    die "e2e/package.json not found"
  fi
fi

# 3) Create dist artifact.
if [[ "$DO_DIST" == "1" ]]; then
  HOST_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
  [[ -n "$HOST_TRIPLE" ]] || die "Could not detect rust host triple"
  ARTIFACT_DIR="$REPO_ROOT/dist"
  ARTIFACT_NAME="fleabox-v${VERSION}-${HOST_TRIPLE}.tar.gz"
  BIN_PATH="$REPO_ROOT/target/release/fleabox"
  [[ -x "$BIN_PATH" ]] || die "Release binary not found at $BIN_PATH (run without --skip-build)"

  run mkdir -p "$ARTIFACT_DIR"
  # Package README + binary (and optionally config example) without committing artifacts.
  run_bash "tar -C '$REPO_ROOT' -czf '$ARTIFACT_DIR/$ARTIFACT_NAME' \
    README.md \
    config.example.json \
    -C 'target/release' fleabox"
  say "Created dist/$ARTIFACT_NAME"
fi

# 4) Commit + tag.
run git add Cargo.toml
if [[ -f Cargo.lock ]]; then
  run git add Cargo.lock || true
fi

if [[ "$DRY_RUN" != "1" ]]; then
  if git diff --cached --quiet; then
    die "No staged changes (expected Cargo.toml version bump)"
  fi
fi

run git commit -m "release: v$VERSION"

if [[ "$NO_TAG" != "1" ]]; then
  run git tag -a "v$VERSION" -m "v$VERSION"
fi

if [[ "$DO_PUSH" == "1" ]]; then
  run git push origin HEAD
  run git push origin "v$VERSION"
fi

# 5) GitHub Release + upload raw binary.
BIN_PATH="$REPO_ROOT/target/release/fleabox"
HOST_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
[[ -n "$HOST_TRIPLE" ]] || die "Could not detect rust host triple"

if [[ "$DRY_RUN" == "1" ]]; then
  say "+ gh auth status"
  say "+ gh release view v$VERSION"
  say "+ gh release create v$VERSION --title v$VERSION --generate-notes ${GITHUB_DRAFT:+--draft} $BIN_PATH#fleabox-${HOST_TRIPLE}"
else
  [[ -x "$BIN_PATH" ]] || die "Release binary not found at $BIN_PATH (run without --skip-build)"

  gh auth status >/dev/null 2>&1 || die "Not authenticated to GitHub. Run: gh auth login"

  if gh release view "v$VERSION" >/dev/null 2>&1; then
    die "GitHub Release v$VERSION already exists"
  fi

  ASSET_SPEC="$BIN_PATH#fleabox-${HOST_TRIPLE}"
  if [[ "$GITHUB_DRAFT" == "1" ]]; then
    run gh release create "v$VERSION" \
      --draft \
      --title "v$VERSION" \
      --generate-notes \
      "$ASSET_SPEC"
  else
    run gh release create "v$VERSION" \
      --title "v$VERSION" \
      --generate-notes \
      "$ASSET_SPEC"
  fi
fi

say "Done."
