import { test, expect } from '@playwright/test';

test.describe('Todo App', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the todo app before each test
    await page.goto('/todo', { waitUntil: 'domcontentloaded' });
    
    // Clear all existing todos to ensure clean state
    await page.evaluate(() => {
      return fetch('/api/todo/data/todos.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify([])
      });
    });
    
    // Reload to reflect the cleared state
    await page.reload({ waitUntil: 'domcontentloaded' });
  });

  test('should load todo app with empty state', async ({ page }) => {
    // Check page title
    await expect(page).toHaveTitle(/Todo App/);

    // Check header is visible
    const header = page.locator('h1');
    await expect(header).toContainText('Todo List');

    // Check subtitle
    const subtitle = page.locator('.subtitle');
    await expect(subtitle).toContainText('Powered by Fleabox');

    // Check input field is visible
    const input = page.locator('#todoInput');
    await expect(input).toBeVisible();
    await expect(input).toHaveAttribute('placeholder', 'What needs to be done?');

    // Check Add button is visible
    const addButton = page.locator('button:has-text("Add")');
    await expect(addButton).toBeVisible();

    // Check for empty state message
    const emptyState = page.locator('.empty-state');
    await expect(emptyState).toBeVisible();
    await expect(emptyState).toContainText('No todos yet');
  });

  test('should add a new todo by clicking Add or pressing Enter', async ({ page }) => {
    const todoText = 'Buy groceries';

    // Enter todo text and click Add button
    await page.fill('#todoInput', todoText);
    await page.click('button:has-text("Add")');

    // Wait for and check that the todo is displayed
    const todoItem = page.locator('.todo-item').first();
    await expect(todoItem).toBeVisible();
    await expect(todoItem.locator('.todo-text')).toHaveText(todoText);

    // Check that input is cleared
    await expect(page.locator('#todoInput')).toHaveValue('');

    // Check that empty state is gone
    await expect(page.locator('.empty-state')).not.toBeVisible();

    // Test adding by pressing Enter
    const secondTodo = 'Write tests';
    await page.fill('#todoInput', secondTodo);
    await page.press('#todoInput', 'Enter');

    // Check that the second todo is displayed
    const secondItem = page.locator('.todo-item').nth(1);
    await expect(secondItem).toBeVisible();
    await expect(secondItem.locator('.todo-text')).toHaveText(secondTodo);
    
    // Should have 2 todos now
    await expect(page.locator('.todo-item')).toHaveCount(2);
  });

  test('should not add empty todos', async ({ page }) => {
    // Try to add empty todo
    await page.click('button:has-text("Add")');

    // Empty state should still be visible
    await expect(page.locator('.empty-state')).toBeVisible();

    // Try to add todo with only spaces
    await page.fill('#todoInput', '   ');
    await page.click('button:has-text("Add")');

    // Empty state should still be visible
    await expect(page.locator('.empty-state')).toBeVisible();
  });

  test('should add multiple todos', async ({ page }) => {
    const todos = ['First todo', 'Second todo', 'Third todo'];

    // Add multiple todos
    for (const todo of todos) {
      await page.fill('#todoInput', todo);
      await page.click('button:has-text("Add")');
      // Wait for input to be cleared
      await expect(page.locator('#todoInput')).toHaveValue('');
    }

    // Check that all todos are displayed
    const todoItems = page.locator('.todo-item');
    await expect(todoItems).toHaveCount(todos.length);

    // Check each todo text
    for (let i = 0; i < todos.length; i++) {
      await expect(todoItems.nth(i).locator('.todo-text')).toHaveText(todos[i]);
    }
  });

  test('should toggle todo completion', async ({ page }) => {
    // Add a todo
    await page.fill('#todoInput', 'Complete this task');
    await page.click('button:has-text("Add")');

    const todoItem = page.locator('.todo-item').first();
    const checkbox = todoItem.locator('input[type="checkbox"]');

    // Check that todo is not completed initially
    await expect(todoItem).toBeVisible();
    await expect(checkbox).not.toBeChecked();
    await expect(todoItem).not.toHaveClass(/completed/);

    // Toggle completion
    await checkbox.check();

    // Check that todo is marked as completed
    await expect(checkbox).toBeChecked();
    await expect(todoItem).toHaveClass(/completed/);

    // Toggle back to uncompleted
    await checkbox.uncheck();

    // Check that todo is uncompleted
    await expect(checkbox).not.toBeChecked();
    await expect(todoItem).not.toHaveClass(/completed/);
  });

  test('should delete todos', async ({ page }) => {
    // Add a single todo and delete it
    await page.fill('#todoInput', 'Delete me');
    await page.click('button:has-text("Add")');

    // Check that todo exists
    const todoItem = page.locator('.todo-item').first();
    await expect(todoItem).toBeVisible();

    // Delete the todo
    await todoItem.locator('button.delete-btn').click();

    // Check that todo is removed
    await expect(page.locator('.todo-item')).toHaveCount(0);

    // Empty state should be visible again
    await expect(page.locator('.empty-state')).toBeVisible();

    // Test deleting specific todo from multiple todos
    const todos = ['First todo', 'Second todo', 'Third todo'];
    for (const todo of todos) {
      await page.fill('#todoInput', todo);
      await page.click('button:has-text("Add")');
      await expect(page.locator('#todoInput')).toHaveValue('');
    }

    // Delete the second todo
    await page.locator('.todo-item').nth(1).locator('button.delete-btn').click();

    // Check that we have 2 todos left
    await expect(page.locator('.todo-item')).toHaveCount(2);

    // Check that the correct todos remain
    await expect(page.locator('.todo-item').nth(0).locator('.todo-text')).toHaveText('First todo');
    await expect(page.locator('.todo-item').nth(1).locator('.todo-text')).toHaveText('Third todo');
  });

  test('should persist todos and completion state after page reload', async ({ page }) => {
    // Add a todo
    const todoText = 'Persistent todo';
    await page.fill('#todoInput', todoText);
    await page.click('button:has-text("Add")');
    await expect(page.locator('.todo-item').first()).toBeVisible();

    // Mark as completed and wait for save to complete
    const checkbox = page.locator('.todo-item').first().locator('input[type="checkbox"]');
    await Promise.all([
      page.waitForResponse(resp => resp.url().includes('/api/todo/data/todos.json') && resp.request().method() === 'PUT'),
      checkbox.check(),
    ]);
    await expect(checkbox).toBeChecked();

    // Reload the page
    await page.reload({ waitUntil: 'domcontentloaded' });

    // Check that the todo is still there and still completed
    const todoItem = page.locator('.todo-item').first();
    await expect(todoItem).toBeVisible();
    await expect(todoItem.locator('.todo-text')).toHaveText(todoText);
    
    const reloadedCheckbox = todoItem.locator('input[type="checkbox"]');
    await expect(reloadedCheckbox).toBeChecked();
    await expect(todoItem).toHaveClass(/completed/);
  });

  test('should handle special characters in todo text', async ({ page }) => {
    const specialText = 'Todo with <script>alert("xss")</script> & special chars';

    // Add todo with special characters
    await page.fill('#todoInput', specialText);
    await page.click('button:has-text("Add")');

    // Check that the text is properly escaped and displayed
    const todoText = page.locator('.todo-item').first().locator('.todo-text');
    await expect(todoText).toBeVisible();
    
    // The text should be escaped, so script tags should be displayed as text, not executed
    const textContent = await todoText.textContent();
    expect(textContent).toContain('<script>');
    expect(textContent).toContain('&');
  });

  test('should handle long todo text', async ({ page }) => {
    const longText = 'This is a very long todo item text that should be handled properly by the application even though it contains many words and might wrap to multiple lines in the UI';

    // Add long todo
    await page.fill('#todoInput', longText);
    await page.click('button:has-text("Add")');

    // Check that the todo is displayed
    const todoText = page.locator('.todo-item').first().locator('.todo-text');
    await expect(todoText).toHaveText(longText);
  });

  test('should complete, verify styling, and delete multiple todos', async ({ page }) => {
    // Add multiple todos
    const todos = ['Task 1', 'Task 2', 'Task 3', 'Task 4'];
    for (const todo of todos) {
      await page.fill('#todoInput', todo);
      await page.click('button:has-text("Add")');
      await expect(page.locator('#todoInput')).toHaveValue('');
    }

    // Mark some as completed
    await page.locator('.todo-item').nth(0).locator('input[type="checkbox"]').check();
    await page.locator('.todo-item').nth(2).locator('input[type="checkbox"]').check();

    // Verify UI styling for completed todo
    const completedItem = page.locator('.todo-item').nth(0);
    await expect(completedItem).toHaveClass(/completed/);
    
    const completedText = completedItem.locator('.todo-text');
    await expect(completedText).toHaveCSS('text-decoration-line', 'line-through');

    // Delete a completed todo
    await page.locator('.todo-item').nth(0).locator('button.delete-btn').click();

    // Check remaining todos
    await expect(page.locator('.todo-item')).toHaveCount(3);
    
    // First item should now be "Task 2" (uncompleted)
    await expect(page.locator('.todo-item').nth(0).locator('.todo-text')).toHaveText('Task 2');
    await expect(page.locator('.todo-item').nth(0).locator('input[type="checkbox"]')).not.toBeChecked();
    
    // Second item should be "Task 3" (completed)
    await expect(page.locator('.todo-item').nth(1).locator('.todo-text')).toHaveText('Task 3');
    await expect(page.locator('.todo-item').nth(1).locator('input[type="checkbox"]')).toBeChecked();
  });

  test('should handle rapid successive operations and verify delete button', async ({ page }) => {
    // Rapidly add multiple todos
    const todos = ['Quick 1', 'Quick 2', 'Quick 3'];
    for (const todo of todos) {
      await page.fill('#todoInput', todo);
      await page.press('#todoInput', 'Enter');
    }

    // Check that all todos were added
    const todoItems = page.locator('.todo-item');
    await expect(todoItems).toHaveCount(3);
    
    // Verify delete button styling on first todo
    const deleteButton = todoItems.first().locator('button.delete-btn');
    
    // Check button is visible and has correct text
    await expect(deleteButton).toBeVisible();
    await expect(deleteButton).toHaveText('Delete');
    
    // Check button has the delete-btn class
    await expect(deleteButton).toHaveClass(/delete-btn/);
  });
});
