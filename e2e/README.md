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

## Test Structure

- `tests/` - Test files
- `playwright.config.ts` - Playwright configuration

The tests automatically start the Fleabox server before running and shut it down after completion.
