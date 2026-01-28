import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright config for testing config-based authentication
 */
export default defineConfig({
  testDir: './tests',
  testMatch: 'auth.spec.ts',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  timeout: 30000,
  reporter: 'list',
  
  use: {
    baseURL: 'http://localhost:3001',
    trace: 'on-first-retry',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  // The auth tests start their own servers, so no webServer config here
});
