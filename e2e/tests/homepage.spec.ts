import { test, expect } from '@playwright/test';

test.describe('Fleabox Homepage', () => {
  test('should load and display example apps', async ({ page }) => {
    // Navigate to the homepage
    await page.goto('/');

    // Check that the page loaded successfully
    await expect(page).toHaveTitle(/fleabox/i);

    // Check that example apps are listed
    // The actual selectors will depend on how the homepage is structured
    // These are common patterns - adjust based on actual HTML structure
    
    // Wait for the apps list to be visible
    await page.waitForLoadState('networkidle');

    // Check for specific example apps that we know exist in examples/
    const expectedApps = ['bookmarks', 'habits', 'journal', 'notes', 'todo', 'tutorial'];
    
    for (const appName of expectedApps) {
      // Look for links or text containing the app name
      const appElement = page.locator(`text=${appName}`).first();
      await expect(appElement).toBeVisible({ timeout: 5000 });
    }

    // Optional: Check that clicking on an app link works
    await page.click('text=bookmarks');
    await expect(page).toHaveURL(/\/bookmarks/);
  });

  test('should navigate to bookmarks app', async ({ page }) => {
    await page.goto('/');
    
    // Click on bookmarks app
    await page.click('text=bookmarks');
    
    // Verify navigation
    await expect(page).toHaveURL(/\/bookmarks/);
    await page.waitForLoadState('networkidle');
    
    // Verify the bookmarks app loaded
    await expect(page.locator('body')).toBeVisible();
  });

  test('should have trailing slashes in app links', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // Check that all app links have trailing slashes
    const expectedApps = ['bookmarks', 'habits', 'journal', 'notes', 'todo', 'tutorial'];
    
    for (const appName of expectedApps) {
      const link = page.locator(`a:has-text("${appName}")`).first();
      const href = await link.getAttribute('href');
      expect(href).toBe(`/${appName}/`);
    }
  });
});
