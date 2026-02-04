# Fleabox End-to-End Tests

This directory contains Playwright-based end-to-end tests for Fleabox.

## Setup

Install dependencies:

```bash
cd e2e
npm install
npx playwright install
```

## Running Tests

### Run all tests (both app and auth tests):
```bash
npm test
```

### Run only application tests (todo, bookmarks, homepage):
```bash
npm run test:app
```

### Run only authentication tests:
```bash
npm run test:auth
```

Some auth tests include ownership assertions (e.g. verifying files are owned by the authenticated user). Those checks require the Fleabox server to run as root and will be skipped when the test runner is not root.

To run the auth suite with root privileges (so ownership checks can run):

```bash
sudo -E npm run test:auth
```

### Debug tests interactively:
```bash
npm run test:debug
```

### View test report:
```bash
npm run test:report
```

## Test Structure

The tests are organized into two projects:

### 1. App Tests (`app-tests` project)
Regular application functionality tests that share a single dev server:
- `tests/homepage.spec.ts` - Homepage and app listing tests
- `tests/todo.spec.ts` - Todo app functionality tests
- `tests/bookmarks.spec.ts` - Bookmarks app tests

These tests use a shared webServer (defined in playwright.config.ts) that runs on port 3000.

### 2. Auth Tests (`auth-tests` project)
Authentication mode tests that manage their own server instances:
- `tests/auth.spec.ts` - Authentication mode tests (config, proxy, dev)

These tests start and stop their own server instances with different configurations on port 3001.

## Configuration

- `playwright.config.ts` - Main configuration with two test projects:
  - `app-tests`: Uses shared webServer on port 3000
  - `auth-tests`: Manages own servers, no shared webServer

## Why Two Projects?

The test suite is split into two projects to avoid conflicts:

1. **App tests** need a persistent dev server that stays running across all tests
2. **Auth tests** need to start/stop servers with different authentication configurations

Running them as separate projects ensures:
- The app tests' shared server doesn't interfere with auth test servers
- Auth tests can safely start/stop servers without affecting other tests
- Tests can run reliably whether run individually or all together

## Authentication Tests

The `auth.spec.ts` file contains comprehensive tests for all authentication modes:

- **Config Authentication**: Tests login with config file, data isolation, and custom data directories
- **Reverse Proxy Authentication**: Tests X-Remote-User header handling and home directory storage
- **Dev Mode**: Tests no-auth mode with current user
- **PAM Authentication**: Skipped (requires manual testing with real system users)
