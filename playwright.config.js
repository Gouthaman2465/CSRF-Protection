// @ts-check
const { defineConfig, devices } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests/e2e',
  timeout: 30000,
  fullyParallel: false,
  workers: 1, // Single worker running tests serially to prevent port collisions
  reporter: 'list',
  use: {
    ...devices['Desktop Chrome'],
    headless: true,
    ignoreHTTPSErrors: true,
  },
});
