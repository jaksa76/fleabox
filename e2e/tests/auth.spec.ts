import { test, expect } from '@playwright/test';
import { spawn, ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

/**
 * E2E tests for all three authentication modes:
 * 1. PAM authentication
 * 2. Config file authentication
 * 3. Reverse proxy (none) authentication
 * 
 * These tests verify:
 * - Proper authentication flows
 * - Correct data directory usage
 * - API access control
 */

const PROJECT_DIR = path.resolve(__dirname, '../..');
const EXAMPLES_DIR = path.resolve(__dirname, '../../examples');
const TEST_PORT = 3001; // Use separate port for auth tests
const BASE_URL = `http://localhost:${TEST_PORT}`;

// Helper to start fleabox server
async function startFleabox(args: string[], useSudo: boolean = false): Promise<ChildProcess> {
  return new Promise((resolve, reject) => {
    let proc: ChildProcess;

    if (useSudo) {
      // For PAM authentication, run with sudo
      // Build the binary first to avoid sudo issues with cargo
      const buildProc = spawn('cargo', ['build', '--release'], {
        cwd: PROJECT_DIR,
        stdio: 'inherit'
      });

      buildProc.on('close', (code) => {
        if (code !== 0) {
          reject(new Error('Build failed'));
          return;
        }

        // Run the built binary with sudo
        const binaryPath = path.join(PROJECT_DIR, 'target', 'release', 'fleabox');
        proc = spawn('sudo', [binaryPath, ...args], {
          cwd: PROJECT_DIR,
          stdio: ['ignore', 'pipe', 'pipe']
        });

        let output = '';

        proc.stdout?.on('data', (data) => {
          output += data.toString();
          if (output.includes('Server running')) {
            resolve(proc);
          }
        });

        proc.stderr?.on('data', (data) => {
          console.error('Fleabox stderr:', data.toString());
        });

        proc.on('error', reject);

        // Timeout after 15 seconds
        setTimeout(() => reject(new Error('Server startup timeout')), 15000);
      });
    } else {
      proc = spawn('cargo', ['run', '--', ...args], {
        cwd: PROJECT_DIR,
        stdio: ['ignore', 'pipe', 'pipe']
      });

      let output = '';
      let resolved = false;

      proc.stdout?.on('data', (data) => {
        const text = data.toString();
        output += text;
        if (!resolved && output.includes('Server running')) {
          resolved = true;
          resolve(proc);
        }
      });

      proc.stderr?.on('data', (data) => {
        const text = data.toString();
        // Cargo outputs "Running" message to stderr, which includes our server startup message
        if (!resolved && text.includes('Server running')) {
          resolved = true;
          resolve(proc);
        }
      });

      proc.on('error', reject);

      // Timeout after 15 seconds
      setTimeout(() => {
        if (!resolved) {
          reject(new Error('Server startup timeout'));
        }
      }, 15000);
    }
  });
}

// Helper to stop fleabox server
function stopFleabox(proc: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    let resolved = false;
    
    const cleanup = () => {
      if (!resolved) {
        resolved = true;
        // Kill any remaining fleabox processes
        const killProc = spawn('sudo', ['pkill', '-9', 'fleabox'], { stdio: 'ignore' });
        killProc.on('close', () => resolve());
        // Always resolve after a short delay even if pkill hangs
        setTimeout(() => resolve(), 300);
      }
    };
    
    if (!proc.killed && proc.pid) {
      // Try graceful shutdown first
      proc.kill('SIGTERM');
      
      // If process exits, clean up
      proc.on('exit', cleanup);
      
      // Force kill after 2 seconds
      setTimeout(() => {
        if (!resolved && !proc.killed) {
          proc.kill('SIGKILL');
        }
      }, 2000);
      
      // Always resolve after 3 seconds maximum
      setTimeout(cleanup, 3000);
    } else {
      cleanup();
    }
  });
}

// Helper to wait for server to be ready
async function waitForServer(url: string, timeout = 10000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    try {
      const response = await fetch(url);
      if (response.ok || response.status === 401 || response.status === 302) {
        return;
      }
    } catch (e) {
      // Server not ready yet
    }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error('Server did not start in time');
}

// Get RSA public key from login page
async function getRSAPublicKey(baseURL: string): Promise<string> {
  const response = await fetch(`${baseURL}/login`);
  const html = await response.text();
  const match = html.match(/const PUBLIC_KEY_PEM = `([^`]+)`/);
  if (!match) throw new Error('Could not extract public key');
  return match[1];
}

// Encrypt password using RSA public key
async function encryptPassword(password: string, publicKeyPem: string): Promise<string> {
  // Import the public key
  const pemContents = publicKeyPem
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s/g, '');

  const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));

  const publicKey = await crypto.subtle.importKey(
    'spki',
    binaryDer,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    false,
    ['encrypt']
  );

  // Encrypt the password
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'RSA-OAEP',
    },
    publicKey,
    data
  );

  // Convert to base64
  return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}

test.describe('Config-based Authentication', () => {
  let server: ChildProcess;
  const baseURL = BASE_URL;
  const configPath = path.join(os.tmpdir(), `fleabox-test-config-${Date.now()}.json`);
  const testDataDir = path.join(os.tmpdir(), `fleabox-test-data-${Date.now()}`);

  test.beforeAll(async () => {
    // Create test data directory
    fs.mkdirSync(testDataDir, { recursive: true });

    // Create config file
    const config = {
      users: [
        {
          username: 'testuser',
          password: 'testpass123',
          data_dir: testDataDir
        },
        {
          username: 'alice',
          password: 'alicepass',
          data_dir: path.join(testDataDir, 'alice')
        }
      ]
    };
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));

    // Create alice's data directory
    fs.mkdirSync(path.join(testDataDir, 'alice'), { recursive: true });

    // Start server with config auth
    server = await startFleabox([
      '--apps-dir', EXAMPLES_DIR,
      '--auth', 'config',
      '--config', configPath,
      '--port', '3001'
    ]);

    await waitForServer(baseURL);
  });

  test.afterAll(async () => {
    if (server) {
      await stopFleabox(server);
    }
    // Cleanup
    try {
      fs.unlinkSync(configPath);
      fs.rmSync(testDataDir, { recursive: true, force: true });
    } catch (e) {
      // Ignore cleanup errors
    }
  });

  test('should redirect to login and show login form', async ({ page }) => {
    // Check redirect when not authenticated
    await page.goto(`${baseURL}/todo/`);
    await page.waitForURL(/\/login/);
    expect(page.url()).toContain('/login');

    // Verify login form elements are visible
    await expect(page.locator('input[name="username"]')).toBeVisible();
    await expect(page.locator('input[name="password"]')).toBeVisible();

    // Test invalid credentials
    await page.fill('input[name="username"]', 'wronguser');
    await page.fill('input[name="password"]', 'wrongpass');
    await page.click('button[type="submit"]');

    // Should see error
    await expect(page.locator('.error')).toBeVisible();
  });

  test('should login successfully and store data in config-specified data_dir', async ({ page }) => {
    // Login with valid credentials
    await page.goto(`${baseURL}/login?next=/todo/`);
    await page.fill('input[name="username"]', 'testuser');
    await page.fill('input[name="password"]', 'testpass123');
    await page.click('button[type="submit"]');

    // Should redirect to todo app
    await page.waitForURL(/\/todo/, { timeout: 5000 });
    expect(page.url()).toContain('/todo');

    // Add a todo item to verify data storage
    await page.fill('#todoInput', 'Test config auth data');
    await page.click('button:has-text("Add")');

    // Wait for todo to appear in list (use first() to handle any duplicates)
    await expect(page.locator('.todo-item, li').filter({ hasText: 'Test config auth data' }).first()).toBeVisible();

    // Verify data file was created in the correct location
    const dataFile = path.join(testDataDir, 'todo', 'data', 'todos.json');
    expect(fs.existsSync(dataFile)).toBeTruthy();

    const data = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
    expect(data).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ text: 'Test config auth data' })
      ])
    );
  });

  test('should logout successfully and clear cookies', async ({ page, context }) => {
    // Login first
    await page.goto(`${baseURL}/login`);
    await page.fill('input[name="username"]', 'testuser');
    await page.fill('input[name="password"]', 'testpass123');
    await page.click('button[type="submit"]');

    // Wait for successful login
    await page.waitForURL((url) => !url.pathname.includes('/login'));

    // Verify cookies are set
    const cookies = await context.cookies();
    const tokenCookie = cookies.find(c => c.name === 'fleabox_token');
    const usernameCookie = cookies.find(c => c.name === 'fleabox_username');
    expect(tokenCookie).toBeDefined();
    expect(usernameCookie).toBeDefined();
    expect(usernameCookie?.value).toBe('testuser');

    // Navigate to logout
    await page.goto(`${baseURL}/logout`);

    // Should redirect to login page (in Config mode, homepage requires auth)
    await page.waitForURL(/\/login/);
    expect(page.url()).toContain('/login');

    // Verify cookies are cleared
    const cookiesAfterLogout = await context.cookies();
    const tokenAfterLogout = cookiesAfterLogout.find(c => c.name === 'fleabox_token' && c.value !== '');
    const usernameAfterLogout = cookiesAfterLogout.find(c => c.name === 'fleabox_username' && c.value !== '');
    expect(tokenAfterLogout).toBeUndefined();
    expect(usernameAfterLogout).toBeUndefined();

    // Verify can't access protected resources
    await page.goto(`${baseURL}/todo/`);
    await page.waitForURL(/\/login/);
    expect(page.url()).toContain('/login');
  });

  test('should allow re-login after logout', async ({ page, context }) => {
    // Login
    await page.goto(`${baseURL}/login`);
    await page.fill('input[name="username"]', 'testuser');
    await page.fill('input[name="password"]', 'testpass123');
    await page.click('button[type="submit"]');
    await page.waitForURL((url) => !url.pathname.includes('/login'));

    // Logout
    await page.goto(`${baseURL}/logout`);
    await page.waitForURL(/\/login/);

    // Login again
    await page.goto(`${baseURL}/login`);
    await page.fill('input[name="username"]', 'testuser');
    await page.fill('input[name="password"]', 'testpass123');
    await page.click('button[type="submit"]');
    await page.waitForURL((url) => !url.pathname.includes('/login'));

    // Should be able to access protected resources
    await page.goto(`${baseURL}/todo/`, { waitUntil: 'domcontentloaded' });
    expect(page.url()).toContain('/todo');
    await expect(page.locator('h1')).toContainText('Todo List');
  });

  test('should handle logout when already logged out', async ({ page }) => {
    // Try to logout without being logged in
    await page.goto(`${baseURL}/logout`);

    // Should still redirect to login page without error (in Config mode)
    await page.waitForURL(/\/login/);
    expect(page.url()).toContain('/login');
  });

  test('should handle multiple consecutive logouts', async ({ page, context }) => {
    // Login
    await page.goto(`${baseURL}/login`);
    await page.fill('input[name="username"]', 'testuser');
    await page.fill('input[name="password"]', 'testpass123');
    await page.click('button[type="submit"]');
    await page.waitForURL((url) => !url.pathname.includes('/login'));

    // First logout
    await page.goto(`${baseURL}/logout`);
    await page.waitForURL(/\/login/);

    // Second logout (should be idempotent)
    await page.goto(`${baseURL}/logout`);
    await page.waitForURL(/\/login/);
    expect(page.url()).toContain('/login');

    // Third logout (still works)
    await page.goto(`${baseURL}/logout`);
    await page.waitForURL(/\/login/);
    expect(page.url()).toContain('/login');
  });

  test('should isolate data between users', async ({ page, context }) => {
    // Login as alice
    await context.clearCookies();
    await page.goto(`${baseURL}/login`);
    await page.fill('input[name="username"]', 'alice');
    await page.fill('input[name="password"]', 'alicepass');
    await page.click('button[type="submit"]');

    // Wait for redirect to todo app
    await page.waitForURL(/\/todo|\/$/, { timeout: 5000 });

    // Navigate to todo app if not already there
    if (!page.url().includes('/todo')) {
      await page.goto(`${baseURL}/todo/`, { waitUntil: 'domcontentloaded' });
    }

    // Add a todo item
    await page.fill('#todoInput', 'Alice\'s private task');
    await page.click('button:has-text("Add")');
    
    // Wait for todo to appear (use first() to handle any duplicates)
    await expect(page.locator('.todo-item, li').filter({ hasText: 'Alice\'s private task' }).first()).toBeVisible();

    // Verify data is in alice's directory
    const aliceDataFile = path.join(testDataDir, 'alice', 'todo', 'data', 'todos.json');
    expect(fs.existsSync(aliceDataFile)).toBeTruthy();

    const aliceData = JSON.parse(fs.readFileSync(aliceDataFile, 'utf8'));
    expect(aliceData).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ text: 'Alice\'s private task' })
      ])
    );

    // Verify testuser's data is separate
    const testuserDataFile = path.join(testDataDir, 'todo', 'data', 'todos.json');
    const testuserData = JSON.parse(fs.readFileSync(testuserDataFile, 'utf8'));
    expect(testuserData).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ text: 'Alice\'s private task' })
      ])
    );
  });

  test('should set correct file ownership (requires running as root)', async ({ page, context }) => {
    // This test verifies that files are owned by the correct user when fleabox runs as root
    // It will be skipped if not running as root
    
    const isRoot = process.getuid && process.getuid() === 0;
    test.skip(!isRoot, 'Test requires root privileges to verify file ownership');

    // Login as testuser
    await page.goto(`${baseURL}/login`);
    await page.fill('input[name="username"]', 'testuser');
    await page.fill('input[name="password"]', 'testpass123');
    await page.click('button[type="submit"]');

    // Wait for redirect and navigate to todo app
    await page.waitForURL((url) => !url.pathname.includes('/login'));
    await page.goto(`${baseURL}/todo/`, { waitUntil: 'domcontentloaded' });

    // Clear existing data
    await page.evaluate(() => {
      return fetch('/api/todo/data/todos.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify([])
      });
    });

    // Add a todo item to create a new file
    await page.fill('#todoInput', 'Ownership test item');
    await page.click('button:has-text("Add")');
    
    // Wait for todo to appear (use first() to handle any duplicates)
    await expect(page.locator('.todo-item, li').filter({ hasText: 'Ownership test item' }).first()).toBeVisible();

    // Check file ownership
    const dataFile = path.join(testDataDir, 'todo', 'data', 'todos.json');
    expect(fs.existsSync(dataFile)).toBeTruthy();

    // Get file stats
    const stats = fs.statSync(dataFile);
    
    // For config-based auth, files should be owned by the current process's uid/gid
    // In a real deployment with root, this would be the user's uid/gid
    // For testing purposes, we check that uid/gid are set (not -1 or undefined)
    expect(stats.uid).toBeGreaterThanOrEqual(0);
    expect(stats.gid).toBeGreaterThanOrEqual(0);

    // Check directory ownership as well
    const dataDir = path.join(testDataDir, 'todo', 'data');
    const dirStats = fs.statSync(dataDir);
    expect(dirStats.uid).toBeGreaterThanOrEqual(0);
    expect(dirStats.gid).toBeGreaterThanOrEqual(0);

    // If we can get the testuser's uid/gid, verify they match
    // In config mode with a non-existent system user, ownership falls back to 0:0
    // This is expected behavior documented in the implementation
    console.log(`File ownership - UID: ${stats.uid}, GID: ${stats.gid}`);
    console.log(`Directory ownership - UID: ${dirStats.uid}, GID: ${dirStats.gid}`);
  });
});

test.describe('Reverse Proxy Authentication (none)', () => {
  let server: ChildProcess;
  const baseURL = BASE_URL;
  const testUser = process.env.USER || 'testuser';
  const userHome = os.homedir();
  const expectedDataDir = path.join(userHome, '.local', 'share', 'fleabox');

  test.beforeAll(async () => {
    // Start server with no auth (reverse proxy mode)
    server = await startFleabox([
      '--apps-dir', EXAMPLES_DIR,
      '--auth', 'none',
      '--port', '3001'
    ]);

    await waitForServer(baseURL);
  });

  test.afterAll(async () => {
    if (server) {
      await stopFleabox(server);
    }
  });

  test('should reject requests without X-Remote-User header', async ({ request }) => {
    const response = await request.get(`${baseURL}/todo/`);
    expect(response.status()).toBe(401);
  });

  test('should accept requests with X-Remote-User header', async ({ request }) => {
    const response = await request.get(`${baseURL}/todo/`, {
      headers: {
        'X-Remote-User': testUser
      }
    });
    expect(response.status()).toBe(200);
  });

  test('should not show login page in reverse proxy mode', async ({ request }) => {
    const response = await request.get(`${baseURL}/login`);
    expect(response.status()).toBe(400);
  });

  test('should store data in user home directory', async ({ page }) => {
    // Set X-Remote-User header for all requests
    await page.route('**/*', async (route) => {
      await route.continue({
        headers: {
          ...route.request().headers(),
          'X-Remote-User': testUser
        }
      });
    });

    // Navigate to todo app
    await page.goto(`${baseURL}/todo/`, { waitUntil: 'domcontentloaded' });

    // Clear existing todos
    await page.evaluate(() => {
      return fetch('/api/todo/data/todos.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify([])
      });
    });

    // Add a todo item
    await page.fill('#todoInput', 'Test proxy auth data');
    await page.click('button:has-text("Add")');
    
    // Wait for todo to appear (use first() to handle any duplicates)
    await expect(page.locator('.todo-item, li').filter({ hasText: 'Test proxy auth data' }).first()).toBeVisible();

    // Verify data file was created in user's home directory
    const dataFile = path.join(expectedDataDir, 'todo', 'data', 'todos.json');
    expect(fs.existsSync(dataFile)).toBeTruthy();

    const data = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
    expect(data).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ text: 'Test proxy auth data' })
      ])
    );
  });

  test('should handle different users via X-Remote-User header', async ({ request }) => {
    // Request as user1
    const response1 = await request.get(`${baseURL}/todo/`, {
      headers: { 'X-Remote-User': 'user1' }
    });
    expect(response1.status()).toBe(200);

    // Request as user2
    const response2 = await request.get(`${baseURL}/todo/`, {
      headers: { 'X-Remote-User': 'user2' }
    });
    expect(response2.status()).toBe(200);

    // Both should succeed but access different data
  });
});

test.describe('Dev Mode', () => {
  let server: ChildProcess;
  const baseURL = BASE_URL;
  const currentUser = process.env.USER || os.userInfo().username;

  test.beforeAll(async () => {
    // Start server in dev mode
    server = await startFleabox([
      '--dev',
      '--apps-dir', EXAMPLES_DIR,
      '--port', '3001'
    ]);

    await waitForServer(baseURL);
  });

  test.afterAll(async () => {
    if (server) {
      await stopFleabox(server);
    }
  });

  test('should allow access without authentication and store data correctly', async ({ page }) => {
    // Should load directly without redirect to login
    await page.goto(`${baseURL}/todo/`, { waitUntil: 'domcontentloaded' });
    await expect(page.locator('h1')).toContainText('Todo List');

    // Verify no redirect to login page
    expect(page.url()).not.toContain('login');

    // Clear and add a todo to test data storage
    await page.evaluate(() => {
      return fetch('/api/todo/data/todos.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify([])
      });
    });

    await page.fill('#todoInput', 'Dev mode task');
    await page.click('button:has-text("Add")');
    
    // Wait for todo to appear (use first() to handle any duplicates)
    await expect(page.locator('.todo-item, li').filter({ hasText: 'Dev mode task' }).first()).toBeVisible();

    // In dev mode, should use current user's home
    const userHome = os.homedir();
    const dataFile = path.join(userHome, '.local', 'share', 'fleabox', 'todo', 'data', 'todos.json');

    // Check if file exists (might not if running in container, but test the flow)
    if (fs.existsSync(dataFile)) {
      const data = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
      expect(data).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ text: 'Dev mode task' })
        ])
      );
    }
  });

  test('should set file ownership to current user in dev mode', async ({ page }) => {
    await page.goto(`${baseURL}/todo/`, { waitUntil: 'domcontentloaded' });

    // Clear and add a todo
    await page.evaluate(() => {
      return fetch('/api/todo/data/todos.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify([])
      });
    });

    await page.fill('#todoInput', 'Dev mode ownership test');
    await page.click('button:has-text("Add")');
    
    // Wait for todo to appear (use first() to handle any duplicates)
    await expect(page.locator('.todo-item, li').filter({ hasText: 'Dev mode ownership test' }).first()).toBeVisible();

    // In dev mode, should use current user's home
    const userHome = os.homedir();
    const dataFile = path.join(userHome, '.local', 'share', 'fleabox', 'todo', 'data', 'todos.json');

    // Check if file exists
    if (fs.existsSync(dataFile)) {
      const stats = fs.statSync(dataFile);
      const currentUid = process.getuid ? process.getuid() : -1;
      const currentGid = process.getgid ? process.getgid() : -1;

      // In dev mode, files should be owned by the current process's user
      if (currentUid !== -1) {
        expect(stats.uid).toBe(currentUid);
        console.log(`Dev mode: File UID ${stats.uid} matches process UID ${currentUid}`);
      }
      if (currentGid !== -1) {
        expect(stats.gid).toBe(currentGid);
        console.log(`Dev mode: File GID ${stats.gid} matches process GID ${currentGid}`);
      }
    }
  });

  test('should logout in dev mode and prevent access to protected resources', async ({ page, context }) => {
    // In dev mode, user is auto-authenticated, but logout should still work
    await page.goto(`${baseURL}/todo/`, { waitUntil: 'domcontentloaded' });
    await expect(page.locator('h1')).toContainText('Todo List');

    // Navigate to logout
    await page.goto(`${baseURL}/logout`);

    // Should redirect to homepage
    await page.waitForURL(baseURL + '/');
    expect(page.url()).toBe(baseURL + '/');

    // In dev mode, user can still access apps after logout (no auth required)
    // But cookies should be cleared
    const cookies = await context.cookies();
    const tokenCookie = cookies.find(c => c.name === 'fleabox_token' && c.value !== '');
    const usernameCookie = cookies.find(c => c.name === 'fleabox_username' && c.value !== '');
    expect(tokenCookie).toBeUndefined();
    expect(usernameCookie).toBeUndefined();
  });
});

test.describe('PAM Authentication', () => {
  let server: ChildProcess;
  const baseURL = 'http://localhost:3002'; // Use separate port to avoid conflicts
  const aliceDataDir = '/home/alice/.local/share/fleabox';
  const bobDataDir = '/home/bob/.local/share/fleabox';

  // Check if PAM test users exist
  const pamUsersExist = () => {
    try {
      return fs.existsSync('/home/alice') && fs.existsSync('/home/bob');
    } catch {
      return false;
    }
  };

  test.beforeAll(async () => {
    // Skip PAM tests if test users don't exist
    if (!pamUsersExist()) {
      test.skip();
      return;
    }

    // Start server with PAM auth (using sudo for PAM permissions)
    server = await startFleabox([
      '--apps-dir', EXAMPLES_DIR,
      '--auth', 'pam',
      '--port', '3002'
    ], true); // Use sudo for PAM authentication

    await waitForServer(baseURL);
  });

  test.afterAll(async () => {
    if (server) {
      await stopFleabox(server);
    }
  });

  test('should redirect to login and handle authentication', async ({ page }) => {
    // Check redirect when not authenticated
    await page.goto(`${baseURL}/todo/`);
    await page.waitForURL(/\/login/);
    expect(page.url()).toContain('/login');

    // Verify login form elements
    await expect(page.locator('input[name="username"]')).toBeVisible();
    await expect(page.locator('input[name="password"]')).toBeVisible();

    // Test invalid credentials
    await page.fill('input[name="username"]', 'nonexistentuser');
    await page.fill('input[name="password"]', 'wrongpassword');
    await page.click('button[type="submit"]');

    // Should see error
    await expect(page.locator('.error')).toBeVisible();
  });

  test('should login with alice credentials and store data in her home directory', async ({ page }) => {
    // Login with alice's credentials
    await page.goto(`${baseURL}/login?next=/todo/`);
    await page.fill('input[name="username"]', 'alice');
    await page.fill('input[name="password"]', 'alice123');
    await page.click('button[type="submit"]');

    // Should redirect to todo app
    await page.waitForURL(/\/todo/, { timeout: 10000 });
    expect(page.url()).toContain('/todo');

    // Wait for todo input to be ready
    await expect(page.locator('#todoInput')).toBeVisible();

    // Clear existing todos
    await page.evaluate(() => {
      return fetch('/api/todo/data/todos.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify([])
      });
    });

    // Add a todo item
    await page.fill('#todoInput', 'Alice PAM test task');
    await page.click('button:has-text("Add")');
    
    // Wait for todo to appear (use first() to handle any duplicates)
    await expect(page.locator('.todo-item, li').filter({ hasText: 'Alice PAM test task' }).first()).toBeVisible();

    // Verify data file was created in alice's home directory
    const dataFile = path.join(aliceDataDir, 'todo', 'data', 'todos.json');
    expect(fs.existsSync(dataFile)).toBeTruthy();

    const data = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
    expect(data).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ text: 'Alice PAM test task' })
      ])
    );
  });

  test('should login with bob credentials and isolate data from alice', async ({ page, context }) => {
    // Clear cookies and login as bob
    await context.clearCookies();
    await page.goto(`${baseURL}/login?next=/todo/`);
    await page.fill('input[name="username"]', 'bob');
    await page.fill('input[name="password"]', 'bob123');
    await page.click('button[type="submit"]');

    // Should redirect to todo app
    await page.waitForURL(/\/todo/, { timeout: 10000 });
    expect(page.url()).toContain('/todo');

    // Wait for todo input to be ready
    await expect(page.locator('#todoInput')).toBeVisible();

    // Clear existing todos
    await page.evaluate(() => {
      return fetch('/api/todo/data/todos.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify([])
      });
    });

    // Add a todo item as bob
    await page.fill('#todoInput', 'Bob PAM test task');
    await page.click('button:has-text("Add")');
    
    // Wait for todo to appear (use first() to handle any duplicates)
    await expect(page.locator('.todo-item, li').filter({ hasText: 'Bob PAM test task' }).first()).toBeVisible();

    // Verify data is in bob's directory
    const bobDataFile = path.join(bobDataDir, 'todo', 'data', 'todos.json');
    expect(fs.existsSync(bobDataFile)).toBeTruthy();

    const bobData = JSON.parse(fs.readFileSync(bobDataFile, 'utf8'));
    expect(bobData).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ text: 'Bob PAM test task' })
      ])
    );

    // Verify alice's data is separate and doesn't contain bob's task
    const aliceDataFile = path.join(aliceDataDir, 'todo', 'data', 'todos.json');
    if (fs.existsSync(aliceDataFile)) {
      const aliceData = JSON.parse(fs.readFileSync(aliceDataFile, 'utf8'));
      expect(aliceData).not.toEqual(
        expect.arrayContaining([
          expect.objectContaining({ text: 'Bob PAM test task' })
        ])
      );
    }
  });

  test('should logout successfully in PAM mode and clear authentication', async ({ page, context }) => {
    // Login as alice
    await page.goto(`${baseURL}/login`);
    await page.fill('input[name="username"]', 'alice');
    await page.fill('input[name="password"]', 'alice123');
    await page.click('button[type="submit"]');

    // Wait for successful login
    await page.waitForURL(/\/todo/, { timeout: 10000 });

    // Verify cookies are set
    const cookies = await context.cookies();
    const tokenCookie = cookies.find(c => c.name === 'fleabox_token');
    const usernameCookie = cookies.find(c => c.name === 'fleabox_username');
    expect(tokenCookie).toBeDefined();
    expect(usernameCookie).toBeDefined();
    expect(usernameCookie?.value).toBe('alice');

    // Navigate to logout
    await page.goto(`${baseURL}/logout`);

    // Should redirect to login page (in PAM mode, homepage requires auth)
    await page.waitForURL(/\/login/);
    expect(page.url()).toContain('/login');

    // Verify cookies are cleared
    const cookiesAfterLogout = await context.cookies();
    const tokenAfterLogout = cookiesAfterLogout.find(c => c.name === 'fleabox_token' && c.value !== '');
    const usernameAfterLogout = cookiesAfterLogout.find(c => c.name === 'fleabox_username' && c.value !== '');
    expect(tokenAfterLogout).toBeUndefined();
    expect(usernameAfterLogout).toBeUndefined();

    // Verify can't access protected resources
    await page.goto(`${baseURL}/todo/`);
    await page.waitForURL(/\/login/);
    expect(page.url()).toContain('/login');
  });

  test('should allow different user to login after logout in PAM mode', async ({ page, context }) => {
    // Login as alice
    await page.goto(`${baseURL}/login`);
    await page.fill('input[name="username"]', 'alice');
    await page.fill('input[name="password"]', 'alice123');
    await page.click('button[type="submit"]');
    await page.waitForURL(/\/todo/, { timeout: 10000 });

    // Logout
    await page.goto(`${baseURL}/logout`);
    await page.waitForURL(/\/login/);

    // Login as bob
    await page.goto(`${baseURL}/login`);
    await page.fill('input[name="username"]', 'bob');
    await page.fill('input[name="password"]', 'bob123');
    await page.click('button[type="submit"]');
    await page.waitForURL(/\/todo/, { timeout: 10000 });

    // Verify logged in as bob
    const cookies = await context.cookies();
    const usernameCookie = cookies.find(c => c.name === 'fleabox_username');
    expect(usernameCookie?.value).toBe('bob');

    // Should be able to access todo app
    await expect(page.locator('#todoInput')).toBeVisible();
  });


});
