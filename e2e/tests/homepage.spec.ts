import { test, expect } from '@playwright/test';

test.describe('Fleabox Homepage', () => {
  test('should load homepage, display apps, and verify links', async ({ page }) => {
    // Navigate to the homepage
    await page.goto('/', { waitUntil: 'domcontentloaded' });

    // Check that the page loaded successfully
    await expect(page).toHaveTitle(/fleabox/i);

    // Check for specific example apps that we know exist in examples/
    const expectedApps = ['bookmarks', 'habits', 'journal', 'notes', 'todo', 'tutorial'];
    
    for (const appName of expectedApps) {
      // Look for links containing the app name
      const appElement = page.locator(`text=${appName}`).first();
      await expect(appElement).toBeVisible();
      
      // Check that link has trailing slash
      const link = page.locator(`a:has-text("${appName}")`).first();
      const href = await link.getAttribute('href');
      expect(href).toBe(`/${appName}/`);
    }

    // Test navigation by clicking on bookmarks app
    await page.click('text=bookmarks');
    await expect(page).toHaveURL(/\/bookmarks/);
    await expect(page.locator('body')).toBeVisible();
  });
});
