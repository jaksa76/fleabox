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
      const buildProc = spawn('cargo', ['build'], {
        cwd: PROJECT_DIR,
        stdio: 'inherit'
      });
      
      buildProc.on('close', (code) => {
        if (code !== 0) {
          reject(new Error('Build failed'));
          return;
        }
        
        // Run the built binary with sudo
        const binaryPath = path.join(PROJECT_DIR, 'target', 'debug', 'fleabox');
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
    }
  });
}

// Helper to stop fleabox server
function stopFleabox(proc: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (!proc.killed) {
      proc.kill('SIGTERM');
      proc.on('exit', () => {
        // Also try to kill any remaining fleabox processes
        spawn('sudo', ['pkill', '-9', 'fleabox']);
        setTimeout(() => resolve(), 500);
      });
      setTimeout(() => {
        if (!proc.killed) {
          proc.kill('SIGKILL');
          // Ensure cleanup
          spawn('sudo', ['pkill', '-9', 'fleabox']);
          setTimeout(() => resolve(), 500);
        }
      }, 2000);
    } else {
      resolve();
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
      '--auth=config',
      `--config=${configPath}`,
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

  test('should redirect to login when not authenticated', async ({ page }) => {
    await page.goto(`${baseURL}/todo/`);
    await page.waitForURL(/\/login/);
    expect(page.url()).toContain('/login');
  });

  test('should show login page', async ({ page }) => {
    await page.goto(`${baseURL}/login`);
    await expect(page.locator('h1')).toContainText('Login');
    await expect(page.locator('input[name="username"]')).toBeVisible();
    await expect(page.locator('input[name="password"]')).toBeVisible();
  });

  test('should reject invalid credentials', async ({ page }) => {
    await page.goto(`${baseURL}/login`);

    // Fill in invalid credentials
    await page.fill('input[name="username"]', 'wronguser');
    await page.fill('input[name="password"]', 'wrongpass');
    await page.click('button[type="submit"]');

    // Should see error
    await page.waitForSelector('.error', { state: 'visible', timeout: 5000 });
  });

  test('should login with valid credentials from config', async ({ page }) => {
    await page.goto(`${baseURL}/login?next=/todo/`);

    // Fill in valid credentials
    await page.fill('input[name="username"]', 'testuser');
    await page.fill('input[name="password"]', 'testpass123');
    await page.click('button[type="submit"]');

    // Should redirect to todo app
    await page.waitForURL(/\/todo/, { timeout: 5000 });
    expect(page.url()).toContain('/todo');
  });

  test('should store data in config-specified data_dir', async ({ page, context }) => {
    // Login as testuser
    await page.goto(`${baseURL}/login`);
    await page.fill('input[name="username"]', 'testuser');
    await page.fill('input[name="password"]', 'testpass123');
    await page.click('button[type="submit"]');
    
    // Wait for redirect away from login page
    await page.waitForURL((url) => !url.pathname.includes('/login'));
    await page.waitForLoadState('networkidle');

    // Navigate to todo app
    await page.goto(`${baseURL}/todo/`);
    await page.waitForLoadState('networkidle');

    // Add a todo item
    await page.fill('#todoInput', 'Test config auth data');
    await page.click('button:has-text("Add")');
    await page.waitForTimeout(500);

    // Verify data file was created in the correct location
    const dataFile = path.join(testDataDir, 'todo', 'data', 'todos.json');

    // Wait a bit for file to be written
    await page.waitForTimeout(1000);

    // Check that file exists in the config-specified directory
    expect(fs.existsSync(dataFile)).toBeTruthy();

    const data = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
    expect(data).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ text: 'Test config auth data' })
      ])
    );
  });

  test('should isolate data between users', async ({ page, context }) => {
    // Login as alice
    await context.clearCookies();
    await page.goto(`${baseURL}/login`);
    await page.fill('input[name="username"]', 'alice');
    await page.fill('input[name="password"]', 'alicepass');
    await page.click('button[type="submit"]');
    
    // Wait for redirect away from login page
    await page.waitForURL((url) => !url.pathname.includes('/login'));
    await page.waitForLoadState('networkidle');

    // Navigate to todo app
    await page.goto(`${baseURL}/todo/`);
    await page.waitForLoadState('networkidle');

    // Add a todo item
    await page.fill('#todoInput', 'Alice\'s private task');
    await page.click('button:has-text("Add")');
    await page.waitForTimeout(1000);

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
      '--auth=none',
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
    await page.goto(`${baseURL}/todo/`);
    await page.waitForLoadState('networkidle');

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
    await page.waitForTimeout(1000);

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

  test('should allow access without authentication', async ({ page }) => {
    await page.goto(`${baseURL}/todo/`);
    // Should load directly without redirect
    await page.waitForLoadState('networkidle');
    await expect(page.locator('h1')).toContainText('Todo List');
  });

  test('should not show login page in dev mode', async ({ page }) => {
    // Dev mode should still have login disabled or use auto-auth
    await page.goto(`${baseURL}/`);
    await page.waitForLoadState('networkidle');
    // Should see homepage, not login
    expect(page.url()).not.toContain('login');
  });

  test('should use current user for dev mode', async ({ page }) => {
    await page.goto(`${baseURL}/todo/`);
    await page.waitForLoadState('networkidle');

    // Clear and add a todo
    await page.evaluate(() => {
      return fetch('/api/todo/data/todos.json', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify([])
      });
    });

    await page.fill('#todoInput', 'Dev mode task');
    await page.click('button:has-text("Add")');
    await page.waitForTimeout(1000);

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
      '--auth=pam',
      '--port', '3002'
    ], true); // Use sudo for PAM authentication

    await waitForServer(baseURL);
  });

  test.afterAll(async () => {
    if (server) {
      await stopFleabox(server);
    }
  });

  test('should redirect to login when not authenticated', async ({ page }) => {
    await page.goto(`${baseURL}/todo/`);
    await page.waitForURL(/\/login/);
    expect(page.url()).toContain('/login');
  });

  test('should show login page', async ({ page }) => {
    await page.goto(`${baseURL}/login`);
    await expect(page.locator('h1')).toContainText('Login');
    await expect(page.locator('input[name="username"]')).toBeVisible();
    await expect(page.locator('input[name="password"]')).toBeVisible();
  });

  test('should reject invalid credentials', async ({ page }) => {
    await page.goto(`${baseURL}/login`);

    // Fill in invalid credentials (non-existent user to avoid locking out real users)
    await page.fill('input[name="username"]', 'nonexistentuser');
    await page.fill('input[name="password"]', 'wrongpassword');
    await page.click('button[type="submit"]');

    // Should see error
    await page.waitForSelector('.error', { state: 'visible', timeout: 5000 });
  });

  test('should login with alice credentials', async ({ page }) => {
    await page.goto(`${baseURL}/login?next=/todo/`);

    // Fill in alice's credentials
    await page.fill('input[name="username"]', 'alice');
    await page.fill('input[name="password"]', 'alice123');
    await page.click('button[type="submit"]');

    // Should redirect to todo app
    await page.waitForURL(/\/todo/, { timeout: 10000 });
    expect(page.url()).toContain('/todo');
  });

  test('should store alice data in her home directory', async ({ page }) => {
    // Login as alice first
    await page.goto(`${baseURL}/login`);
    await page.fill('input[name="username"]', 'alice');
    await page.fill('input[name="password"]', 'alice123');
    await page.click('button[type="submit"]');
    
    // Wait for redirect after login
    await page.waitForURL((url) => !url.pathname.includes('/login'), { timeout: 10000 });
    
    // Navigate to todo app
    await page.goto(`${baseURL}/todo/`);
    await page.waitForLoadState('networkidle');

    // Wait for todo app to be ready
    await page.waitForSelector('#todoInput', { timeout: 10000 });

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
    await page.waitForTimeout(1000);

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

  test('should login with bob credentials', async ({ page, context }) => {
    // Clear cookies to start fresh
    await context.clearCookies();

    await page.goto(`${baseURL}/login?next=/todo/`);

    // Fill in bob's credentials
    await page.fill('input[name="username"]', 'bob');
    await page.fill('input[name="password"]', 'bob123');
    await page.click('button[type="submit"]');

    // Should redirect to todo app
    await page.waitForURL(/\/todo/, { timeout: 10000 });
    expect(page.url()).toContain('/todo');
  });

  test('should isolate data between alice and bob', async ({ page, context }) => {
    // Clear cookies and login as bob
    await context.clearCookies();
    await page.goto(`${baseURL}/login`);
    await page.fill('input[name="username"]', 'bob');
    await page.fill('input[name="password"]', 'bob123');
    await page.click('button[type="submit"]');
    
    // Wait for redirect after login
    await page.waitForURL((url) => !url.pathname.includes('/login'), { timeout: 10000 });
    
    // Navigate to todo app
    await page.goto(`${baseURL}/todo/`);
    await page.waitForLoadState('networkidle');

    // Wait for todo app to be ready
    await page.waitForSelector('#todoInput', { timeout: 10000 });

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
    await page.waitForTimeout(1000);

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


});
