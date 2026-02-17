import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { readFileSync } from 'fs';
import { join } from 'path';

test.describe('Fleabox CLI', () => {
  test('should display version with --version flag', async () => {
    // Read the version from Cargo.toml
    const cargoTomlPath = join(__dirname, '../../Cargo.toml');
    const cargoToml = readFileSync(cargoTomlPath, 'utf-8');
    const versionMatch = cargoToml.match(/^version\s*=\s*"([^"]+)"/m);
    
    expect(versionMatch).not.toBeNull();
    const expectedVersion = versionMatch![1];
    
    // Execute the binary with --version flag
    const output = execSync('cargo run --quiet -- --version', {
      cwd: join(__dirname, '../..'),
      encoding: 'utf-8',
      timeout: 30000,
    });
    
    // Verify output format and content
    expect(output.trim()).toBe(`fleabox ${expectedVersion}`);
    expect(output).toContain('fleabox');
    expect(output).toContain(expectedVersion);
  });

  test('should include --version in help output', async () => {
    // Execute the binary with --help flag
    const output = execSync('cargo run --quiet -- --help', {
      cwd: join(__dirname, '../..'),
      encoding: 'utf-8',
      timeout: 30000,
    });
    
    // Verify --version is documented in help
    expect(output).toContain('--version');
    expect(output).toMatch(/--version\s+Print version information/);
  });
});
