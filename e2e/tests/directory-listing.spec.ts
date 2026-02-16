import { test, expect } from '@playwright/test';

test.describe('Directory Listing API', () => {
  const APP_ID = 'todo';

  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    // Clean up any leftover test data to ensure a clean state
    await page.evaluate((appId) => {
      return fetch(`/api/${appId}/data/test-dir-listing/`, { method: 'DELETE' });
    }, APP_ID);
  });

  test.afterEach(async ({ page }) => {
    // Clean up test files and directories
    await page.evaluate((appId) => {
      return fetch(`/api/${appId}/data/test-dir-listing/`, { method: 'DELETE' });
    }, APP_ID);
  });

  test('should list files in a directory', async ({ page }) => {
    await page.goto('/');

    // Create a couple of test files
    await page.evaluate((appId) =>
      fetch(`/api/${appId}/data/test-dir-listing/file1.json`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ a: 1 }),
      }), APP_ID);

    await page.evaluate((appId) =>
      fetch(`/api/${appId}/data/test-dir-listing/file2.txt`, {
        method: 'PUT',
        body: 'hello',
      }), APP_ID);

    // Fetch the directory listing
    const response = await page.evaluate((appId) =>
      fetch(`/api/${appId}/data/test-dir-listing/`).then(async (r) => ({
        status: r.status,
        body: await r.json(),
      })), APP_ID);

    expect(response.status).toBe(200);
    expect(Array.isArray(response.body)).toBe(true);
    expect(response.body).toHaveLength(2);

    const names = response.body.map((e: any) => e.name).sort();
    expect(names).toEqual(['file1.json', 'file2.txt']);

    for (const entry of response.body) {
      expect(entry.type).toBe('file');
      expect(typeof entry.size).toBe('number');
      expect(entry.size).toBeGreaterThan(0);
      expect(typeof entry.mtime).toBe('number');
      expect(entry.mtime).toBeGreaterThan(0);
    }
  });

  test('should list subdirectories with type "dir"', async ({ page }) => {
    await page.goto('/');

    // Create a file inside a subdirectory (parent dirs auto-created)
    await page.evaluate((appId) =>
      fetch(`/api/${appId}/data/test-dir-listing/subdir/nested.json`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      }), APP_ID);

    // Also create a file at the same level
    await page.evaluate((appId) =>
      fetch(`/api/${appId}/data/test-dir-listing/top.json`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      }), APP_ID);

    const response = await page.evaluate((appId) =>
      fetch(`/api/${appId}/data/test-dir-listing/`).then(async (r) => ({
        status: r.status,
        body: await r.json(),
      })), APP_ID);

    expect(response.status).toBe(200);
    expect(response.body).toHaveLength(2);

    const sorted = response.body.sort((a: any, b: any) => a.name.localeCompare(b.name));

    // subdirectory entry
    expect(sorted[0].name).toBe('subdir');
    expect(sorted[0].type).toBe('dir');
    expect(sorted[0].size).toBeUndefined();
    expect(typeof sorted[0].mtime).toBe('number');

    // file entry
    expect(sorted[1].name).toBe('top.json');
    expect(sorted[1].type).toBe('file');
    expect(typeof sorted[1].size).toBe('number');
  });

  test('should return 404 for non-existent directory', async ({ page }) => {
    await page.goto('/');

    const response = await page.evaluate((appId) =>
      fetch(`/api/${appId}/data/no-such-dir/`).then((r) => ({
        status: r.status,
      })), APP_ID);

    expect(response.status).toBe(404);
  });

  test('should return empty array for empty directory', async ({ page }) => {
    await page.goto('/');

    // Create a file then delete it, leaving the parent dir empty
    await page.evaluate((appId) =>
      fetch(`/api/${appId}/data/test-dir-listing/temp.json`, {
        method: 'PUT',
        body: '{}',
      }), APP_ID);

    await page.evaluate((appId) =>
      fetch(`/api/${appId}/data/test-dir-listing/temp.json`, {
        method: 'DELETE',
      }), APP_ID);

    const response = await page.evaluate((appId) =>
      fetch(`/api/${appId}/data/test-dir-listing/`).then(async (r) => ({
        status: r.status,
        body: await r.json(),
      })), APP_ID);

    expect(response.status).toBe(200);
    expect(response.body).toEqual([]);
  });
});
