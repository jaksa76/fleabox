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

Run all tests (headless):
```bash
npm test
```

Run tests with browser visible:
```bash
npm run test:headed
```

Run tests in UI mode (interactive):
```bash
npm run test:ui
```

Debug tests:
```bash
npm run test:debug
```

Run authentication tests (tests all auth modes):
```bash
npm run test:auth
```

## Test Structure

- `tests/` - Test files
  - `homepage.spec.ts` - Homepage and app listing tests
  - `todo.spec.ts` - Todo app functionality tests
  - `bookmarks.spec.ts` - Bookmarks app tests
  - `auth.spec.ts` - Authentication mode tests (config, proxy, dev)
- `playwright.config.ts` - Default Playwright configuration (dev mode)
- `playwright.auth.config.ts` - Configuration for authentication tests

The standard tests automatically start the Fleabox server in dev mode before running. The authentication tests (`auth.spec.ts`) start and stop their own server instances with different configurations.

## Authentication Tests

The `auth.spec.ts` file contains comprehensive tests for all authentication modes:

- **Config Authentication**: Tests login with config file, data isolation, and custom data directories
- **Reverse Proxy Authentication**: Tests X-Remote-User header handling and home directory storage
- **Dev Mode**: Tests no-auth mode with current user
- **PAM Authentication**: Skipped (requires manual testing with real system users)

To run only authentication tests:
```bash
npm run test:auth
```
