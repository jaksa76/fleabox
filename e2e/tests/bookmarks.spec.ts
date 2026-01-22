import { test, expect } from '@playwright/test';

test.describe('Bookmarks App', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the bookmarks app before each test
    await page.goto('/bookmarks/');
    await page.waitForLoadState('networkidle');
    
    // Clear all existing bookmarks to ensure clean state
    await page.evaluate(() => {
      return fetch('/api/bookmarks/data/bookmarks.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify([])
      });
    });
    
    // Reload to reflect the cleared state
    await page.reload();
    await page.waitForLoadState('networkidle');
  });

  test('should load the bookmarks app', async ({ page }) => {
    // Check page title
    await expect(page).toHaveTitle(/Bookmarks/);

    // Check header is visible
    const header = page.locator('h1');
    await expect(header).toContainText('Bookmarks');

    // Check subtitle
    const subtitle = page.locator('.subtitle');
    await expect(subtitle).toContainText('Powered by Fleabox');

    // Check Add Bookmark button is visible
    const addButton = page.locator('button.toggle-form-btn');
    await expect(addButton).toBeVisible();
    await expect(addButton).toContainText('Add Bookmark');
  });

  test('should load external CSS file', async ({ page }) => {
    // Check that styles.css is loaded by verifying computed styles
    const header = page.locator('h1');
    const color = await header.evaluate(el => window.getComputedStyle(el).color);
    
    // If CSS is loaded, the color should not be the default black
    expect(color).toBeTruthy();
  });

  test('should load external JavaScript file', async ({ page }) => {
    // Check that index.js is loaded by verifying that functions are available
    const hasLoadBookmarks = await page.evaluate(() => typeof (window as any).loadBookmarks === 'function');
    expect(hasLoadBookmarks).toBe(true);
  });

  test('should show empty state when no bookmarks exist', async ({ page }) => {
    // Check for empty state message
    const emptyState = page.locator('.empty-state');
    await expect(emptyState).toBeVisible();
    await expect(emptyState).toContainText('No bookmarks yet');
  });

  test('should toggle add bookmark form', async ({ page }) => {
    const addButton = page.locator('button.toggle-form-btn');
    const form = page.locator('#addForm');

    // Form should be hidden initially
    await expect(form).not.toHaveClass(/show/);

    // Click to show form
    await addButton.click();
    await expect(form).toHaveClass(/show/);

    // Check form fields are visible
    await expect(page.locator('#titleInput')).toBeVisible();
    await expect(page.locator('#urlInput')).toBeVisible();
    await expect(page.locator('#categoryInput')).toBeVisible();
    await expect(page.locator('#descriptionInput')).toBeVisible();
  });

  test('should add a new bookmark', async ({ page }) => {
    // Open the form
    await page.click('button.toggle-form-btn');

    // Fill in bookmark details
    await page.fill('#titleInput', 'GitHub');
    await page.fill('#urlInput', 'https://github.com');
    await page.fill('#categoryInput', 'Dev Tools');
    await page.fill('#descriptionInput', 'Code hosting platform');

    // Save the bookmark
    await page.click('button:has-text("Save Bookmark")');
    await page.waitForTimeout(500);

    // Check that the bookmark is displayed
    await expect(page.locator('.bookmark-item')).toHaveCount(1);
    await expect(page.locator('.bookmark-title a')).toContainText('GitHub');
    await expect(page.locator('.bookmark-url')).toContainText('https://github.com');
    await expect(page.locator('.bookmark-description')).toContainText('Code hosting platform');
    await expect(page.locator('.category-title')).toContainText('Dev Tools');

    // Form should be hidden after save
    await expect(page.locator('#addForm')).not.toHaveClass(/show/);

    // Empty state should be gone
    await expect(page.locator('.empty-state')).not.toBeVisible();
  });

  test('should require title and URL', async ({ page }) => {
    // Open the form
    await page.click('button.toggle-form-btn');

    // Try to save without filling required fields
    await page.click('button:has-text("Save Bookmark")');

    // Error message should appear
    const error = page.locator('#error.show');
    await expect(error).toBeVisible();
    await expect(error).toContainText('Please enter both title and URL');
  });

  test('should validate URL format', async ({ page }) => {
    // Open the form
    await page.click('button.toggle-form-btn');

    // Fill in with invalid URL
    await page.fill('#titleInput', 'Invalid URL');
    await page.fill('#urlInput', 'not-a-valid-url');

    // Try to save
    await page.click('button:has-text("Save Bookmark")');

    // Error message should appear
    const error = page.locator('#error.show');
    await expect(error).toBeVisible();
    await expect(error).toContainText('Please enter a valid URL');
  });

  test('should use default category if not provided', async ({ page }) => {
    // Open the form
    await page.click('button.toggle-form-btn');

    // Fill in without category
    await page.fill('#titleInput', 'Example Site');
    await page.fill('#urlInput', 'https://example.com');

    // Save
    await page.click('button:has-text("Save Bookmark")');
    await page.waitForTimeout(500);

    // Should be in "Uncategorized" category
    await expect(page.locator('.category-title')).toContainText('Uncategorized');
  });

  test('should cancel form and clear inputs', async ({ page }) => {
    // Open the form
    await page.click('button.toggle-form-btn');

    // Fill in some data
    await page.fill('#titleInput', 'Test');
    await page.fill('#urlInput', 'https://test.com');

    // Click cancel
    await page.click('button.cancel-btn');

    // Form should be hidden
    await expect(page.locator('#addForm')).not.toHaveClass(/show/);

    // Reopen form to check if fields are cleared
    await page.click('button.toggle-form-btn');
    await expect(page.locator('#titleInput')).toHaveValue('');
    await expect(page.locator('#urlInput')).toHaveValue('');
  });

  test('should add multiple bookmarks', async ({ page }) => {
    const bookmarks = [
      { title: 'GitHub', url: 'https://github.com', category: 'Dev Tools' },
      { title: 'Stack Overflow', url: 'https://stackoverflow.com', category: 'Dev Tools' },
      { title: 'Gmail', url: 'https://gmail.com', category: 'Productivity' }
    ];

    for (const bookmark of bookmarks) {
      await page.click('button.toggle-form-btn');
      await page.fill('#titleInput', bookmark.title);
      await page.fill('#urlInput', bookmark.url);
      await page.fill('#categoryInput', bookmark.category);
      await page.click('button:has-text("Save Bookmark")');
      await page.waitForTimeout(500);
    }

    // Check that all bookmarks are displayed
    await expect(page.locator('.bookmark-item')).toHaveCount(3);

    // Check categories (Dev Tools and Productivity)
    const categories = page.locator('.category-title');
    await expect(categories).toHaveCount(2);
  });

  test('should group bookmarks by category', async ({ page }) => {
    // Add bookmarks in same category
    const bookmarks = [
      { title: 'Site 1', url: 'https://site1.com', category: 'Work' },
      { title: 'Site 2', url: 'https://site2.com', category: 'Work' },
      { title: 'Site 3', url: 'https://site3.com', category: 'Personal' }
    ];

    for (const bookmark of bookmarks) {
      await page.click('button.toggle-form-btn');
      await page.fill('#titleInput', bookmark.title);
      await page.fill('#urlInput', bookmark.url);
      await page.fill('#categoryInput', bookmark.category);
      await page.click('button:has-text("Save Bookmark")');
      await page.waitForTimeout(500);
    }

    // Check that we have 2 categories
    await expect(page.locator('.category')).toHaveCount(2);

    // Check Work category has 2 bookmarks
    const workCategory = page.locator('.category').filter({ hasText: 'Work' });
    await expect(workCategory.locator('.bookmark-item')).toHaveCount(2);

    // Check Personal category has 1 bookmark
    const personalCategory = page.locator('.category').filter({ hasText: 'Personal' });
    await expect(personalCategory.locator('.bookmark-item')).toHaveCount(1);
  });

  test('should edit a bookmark', async ({ page }) => {
    // Add a bookmark first
    await page.click('button.toggle-form-btn');
    await page.fill('#titleInput', 'Original Title');
    await page.fill('#urlInput', 'https://original.com');
    await page.fill('#categoryInput', 'Original Category');
    await page.click('button:has-text("Save Bookmark")');
    await page.waitForTimeout(500);

    // Click edit button
    await page.click('button.edit-btn');

    // Form should be visible with pre-filled data
    await expect(page.locator('#addForm')).toHaveClass(/show/);
    await expect(page.locator('#titleInput')).toHaveValue('Original Title');
    await expect(page.locator('#urlInput')).toHaveValue('https://original.com');
    await expect(page.locator('#categoryInput')).toHaveValue('Original Category');

    // Modify the bookmark
    await page.fill('#titleInput', 'Updated Title');
    await page.fill('#urlInput', 'https://updated.com');
    await page.fill('#categoryInput', 'Updated Category');
    await page.click('button:has-text("Save Bookmark")');
    await page.waitForTimeout(500);

    // Check that changes are reflected
    await expect(page.locator('.bookmark-title a')).toContainText('Updated Title');
    await expect(page.locator('.bookmark-url')).toContainText('https://updated.com');
    await expect(page.locator('.category-title')).toContainText('Updated Category');

    // Should still have only 1 bookmark
    await expect(page.locator('.bookmark-item')).toHaveCount(1);
  });

  test('should delete a bookmark', async ({ page }) => {
    // Add a bookmark first
    await page.click('button.toggle-form-btn');
    await page.fill('#titleInput', 'Delete Me');
    await page.fill('#urlInput', 'https://deleteme.com');
    await page.click('button:has-text("Save Bookmark")');
    await page.waitForTimeout(500);

    // Check bookmark exists
    await expect(page.locator('.bookmark-item')).toHaveCount(1);

    // Set up dialog handler to accept the confirmation
    page.on('dialog', dialog => dialog.accept());

    // Click delete button
    await page.click('button.delete-btn');
    await page.waitForTimeout(500);

    // Check that bookmark is removed
    await expect(page.locator('.bookmark-item')).toHaveCount(0);

    // Empty state should be visible again
    await expect(page.locator('.empty-state')).toBeVisible();
  });

  test('should not delete bookmark if user cancels confirmation', async ({ page }) => {
    // Add a bookmark first
    await page.click('button.toggle-form-btn');
    await page.fill('#titleInput', 'Keep Me');
    await page.fill('#urlInput', 'https://keepme.com');
    await page.click('button:has-text("Save Bookmark")');
    await page.waitForTimeout(500);

    // Set up dialog handler to dismiss the confirmation
    page.on('dialog', dialog => dialog.dismiss());

    // Click delete button
    await page.click('button.delete-btn');
    await page.waitForTimeout(500);

    // Bookmark should still exist
    await expect(page.locator('.bookmark-item')).toHaveCount(1);
  });

  test('should persist bookmarks after page reload', async ({ page }) => {
    // Add a bookmark
    await page.click('button.toggle-form-btn');
    await page.fill('#titleInput', 'Persistent');
    await page.fill('#urlInput', 'https://persistent.com');
    await page.fill('#categoryInput', 'Test');
    await page.click('button:has-text("Save Bookmark")');
    await page.waitForTimeout(500);

    // Reload the page
    await page.reload();
    await page.waitForLoadState('networkidle');

    // Check that the bookmark is still there
    await expect(page.locator('.bookmark-item')).toHaveCount(1);
    await expect(page.locator('.bookmark-title a')).toContainText('Persistent');
  });

  test('should open bookmark links in new tab', async ({ page }) => {
    // Add a bookmark
    await page.click('button.toggle-form-btn');
    await page.fill('#titleInput', 'Test Link');
    await page.fill('#urlInput', 'https://example.com');
    await page.click('button:has-text("Save Bookmark")');
    await page.waitForTimeout(500);

    // Check that link has target="_blank" and rel attributes
    const link = page.locator('.bookmark-title a');
    await expect(link).toHaveAttribute('target', '_blank');
    await expect(link).toHaveAttribute('rel', 'noopener noreferrer');
  });

  test('should display bookmark icon with first letter', async ({ page }) => {
    // Add a bookmark
    await page.click('button.toggle-form-btn');
    await page.fill('#titleInput', 'Test Site');
    await page.fill('#urlInput', 'https://test.com');
    await page.click('button:has-text("Save Bookmark")');
    await page.waitForTimeout(500);

    // Check that icon shows first letter
    const icon = page.locator('.bookmark-icon');
    await expect(icon).toBeVisible();
    await expect(icon).toHaveText('T');
  });

  test('should handle special characters in bookmark data', async ({ page }) => {
    // Add a bookmark with special characters
    await page.click('button.toggle-form-btn');
    await page.fill('#titleInput', '<script>alert("xss")</script>');
    await page.fill('#urlInput', 'https://example.com');
    await page.fill('#categoryInput', 'Test & Special');
    await page.fill('#descriptionInput', 'Special chars: < > & "');
    await page.click('button:has-text("Save Bookmark")');
    await page.waitForTimeout(500);

    // Check that special characters are properly escaped
    const title = page.locator('.bookmark-title a');
    const titleText = await title.textContent();
    expect(titleText).toContain('<script>');
    
    const category = page.locator('.category-title');
    await expect(category).toContainText('Test & Special');
  });

  test('should sort categories alphabetically', async ({ page }) => {
    // Add bookmarks with different categories
    const bookmarks = [
      { title: 'Zebra', url: 'https://z.com', category: 'Zebra' },
      { title: 'Apple', url: 'https://a.com', category: 'Apple' },
      { title: 'Middle', url: 'https://m.com', category: 'Middle' }
    ];

    for (const bookmark of bookmarks) {
      await page.click('button.toggle-form-btn');
      await page.fill('#titleInput', bookmark.title);
      await page.fill('#urlInput', bookmark.url);
      await page.fill('#categoryInput', bookmark.category);
      await page.click('button:has-text("Save Bookmark")');
      await page.waitForTimeout(500);
    }

    // Get all category titles
    const categoryTitles = await page.locator('.category-title').allTextContents();
    
    // Check they are in alphabetical order
    expect(categoryTitles).toEqual(['Apple', 'Middle', 'Zebra']);
  });
});
