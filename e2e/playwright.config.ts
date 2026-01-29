import { defineConfig, devices } from '@playwright/test';

/**
 * Main Playwright configuration for Fleabox E2E tests.
 * 
 * Test Projects:
 * - 'app-tests': Regular application tests (todo, bookmarks, homepage) that use a shared dev server
 * - 'auth-tests': Authentication tests that manage their own server instances
 * 
 * Run specific project: npx playwright test --project=app-tests
 * Run all tests: npm test (runs both projects sequentially)
 */
export default defineConfig({
  testDir: './tests',
  /* Run tests in files in parallel */
  fullyParallel: false,
  /* Fail the build on CI if you accidentally left test.only in the source code. */
  forbidOnly: !!process.env.CI,
  /* Retry on CI only */
  retries: process.env.CI ? 2 : 0,
  /* Opt out of parallel tests on CI. */
  workers: 1,
  /* Reporter to use. See https://playwright.dev/docs/test-reporters */
  reporter: [['list'], ['json', { outputFile: 'test-results.json' }]],
  /* Shared settings for all the projects below. See https://playwright.dev/docs/api/class-testoptions. */
  use: {
    /* Collect trace when retrying the failed test. See https://playwright.dev/docs/trace-viewer */
    trace: 'on-first-retry',
  },

  /* Configure test projects */
  projects: [
    // Regular app tests using a shared dev server
    {
      name: 'app-tests',
      testIgnore: '**/auth.spec.ts', // Exclude auth tests from this project
      use: { 
        ...devices['Desktop Chrome'],
        baseURL: 'http://localhost:3000',
      },
    },
    // Auth tests that manage their own servers
    {
      name: 'auth-tests',
      testMatch: '**/auth.spec.ts', // Only run auth tests in this project
      use: { 
        ...devices['Desktop Chrome'],
        baseURL: 'http://localhost:3001',
      },
      // No webServer for auth tests - they start their own
    },
  ],

  /* Run local dev server before starting the app-tests */
  webServer: {
    command: 'cargo run -- --dev --apps-dir ./examples/',
    url: 'http://localhost:3000',
    reuseExistingServer: !process.env.CI,
    cwd: '..',
    timeout: 120000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
