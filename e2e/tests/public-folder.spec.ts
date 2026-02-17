import { test, expect } from '@playwright/test';

test.describe('Public Folder API', () => {
  const APP_ID = 'testapp';

  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    // Clean up test data
    await page.evaluate((appId) => {
      return fetch(`/api/${appId}/public/test-file.json`, { method: 'DELETE' }).catch(() => {});
    }, APP_ID);
  });

  test.afterEach(async ({ page }) => {
    // Clean up test data
    await page.evaluate((appId) => {
      return fetch(`/api/${appId}/public/test-file.json`, { method: 'DELETE' }).catch(() => {});
    }, APP_ID);
  });

  test('should list files in the root public directory', async ({ page }) => {
    await page.goto('/');

    // Create files at the root public level
    await page.evaluate((appId) =>
      fetch(`/api/${appId}/public/file1.json`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ public: true }),
      }), APP_ID);

    await page.evaluate((appId) =>
      fetch(`/api/${appId}/public/file2.txt`, {
        method: 'PUT',
        body: 'public content',
      }), APP_ID);

    // Create a subdirectory
    await page.evaluate((appId) =>
      fetch(`/api/${appId}/public/subdir/nested.json`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      }), APP_ID);

    // Fetch the root public directory listing
    const response = await page.evaluate((appId) =>
      fetch(`/api/${appId}/public/`).then(async (r) => ({
        status: r.status,
        body: r.ok ? await r.json() : await r.text(),
      })), APP_ID);

    expect(response.status).toBe(200);
    expect(Array.isArray(response.body)).toBe(true);

    // Verify our created files are present
    const names = response.body.map((e: any) => e.name);
    expect(names).toContain('file1.json');
    expect(names).toContain('file2.txt');
    expect(names).toContain('subdir');

    // Verify subdirectory type
    const subdirEntry = response.body.find((e: any) => e.name === 'subdir');
    expect(subdirEntry).toBeDefined();
    expect(subdirEntry.type).toBe('dir');

    // Cleanup
    await page.evaluate((appId) =>
      fetch(`/api/${appId}/public/file1.json`, { method: 'DELETE' }), APP_ID);
    await page.evaluate((appId) =>
      fetch(`/api/${appId}/public/file2.txt`, { method: 'DELETE' }), APP_ID);
    await page.evaluate((appId) =>
      fetch(`/api/${appId}/public/subdir/`, { method: 'DELETE' }), APP_ID);
  });
});
