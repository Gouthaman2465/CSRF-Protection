// @ts-check
const { test, expect } = require('@playwright/test');
const path = require('path');
const { createApp } = require('../../src/app');
const { createAttackerApp } = require('../../attacker/server');
const { resetUsers } = require('../../src/auth/users');
const { resetSessions } = require('../../src/auth/sessions');

const SECRET = '0123456789abcdef0123456789abcdef';
const SCREENSHOT_DIR = path.join(__dirname, '../../docs/screenshots');

/**
 * Helper to spin up victim and attacker in-process for testing.
 */
function startServers(options = {}) {
  const config = {
    mode: options.mode || 'secure',
    secret: SECRET,
    victimPort: 5001,
    attackerPort: 7000,
    allowedOrigins: ['http://localhost:5001'],
    sameSite: options.sameSite || 'none',
    tokenTtlMinutes: 60,
    tokenTtlMs: 3600000,
    enableTokenCheck: true,
    enableOriginCheck: true,
  };

  resetUsers();
  resetSessions();

  const victimApp = createApp(config);
  const attackerApp = createAttackerApp({ victimUrl: 'http://localhost:5001' });

  return new Promise((resolve, reject) => {
    const victimServer = victimApp.listen(5001, '127.0.0.1', () => {
      const attackerServer = attackerApp.listen(7000, '127.0.0.1', () => {
        resolve({
          close: () => {
            return new Promise((done) => {
              victimServer.close(() => {
                attackerServer.close(() => {
                  done(undefined);
                });
              });
            });
          },
        });
      });
      attackerServer.on('error', reject);
    });
    victimServer.on('error', reject);
  });
}

const matrix = [
  // MODE: off
  { mode: 'off', attack: 'change-email', page: 'attack-change-email.html', expectedSuccess: true, type: 'email' },
  { mode: 'off', attack: 'transfer', page: 'attack-transfer.html', expectedSuccess: true, type: 'transfer' },
  { mode: 'off', attack: 'unbound-token', page: 'attack-unbound-token.html', expectedSuccess: true, type: 'email' },
  { mode: 'off', attack: 'no-referrer', page: 'attack-no-referrer.html', expectedSuccess: true, type: 'email' },

  // MODE: weak-referer
  { mode: 'weak-referer', attack: 'change-email', page: 'attack-change-email.html', expectedSuccess: false, type: 'email' },
  { mode: 'weak-referer', attack: 'transfer', page: 'attack-transfer.html', expectedSuccess: false, type: 'transfer' },
  { mode: 'weak-referer', attack: 'unbound-token', page: 'attack-unbound-token.html', expectedSuccess: false, type: 'email' },
  { mode: 'weak-referer', attack: 'no-referrer', page: 'attack-no-referrer.html', expectedSuccess: true, type: 'email' },

  // MODE: weak-token
  { mode: 'weak-token', attack: 'change-email', page: 'attack-change-email.html', expectedSuccess: false, type: 'email' },
  { mode: 'weak-token', attack: 'transfer', page: 'attack-transfer.html', expectedSuccess: false, type: 'transfer' },
  { mode: 'weak-token', attack: 'unbound-token', page: 'attack-unbound-token.html', expectedSuccess: true, type: 'email' },
  { mode: 'weak-token', attack: 'no-referrer', page: 'attack-no-referrer.html', expectedSuccess: false, type: 'email' },

  // MODE: secure
  { mode: 'secure', attack: 'change-email', page: 'attack-change-email.html', expectedSuccess: false, type: 'email' },
  { mode: 'secure', attack: 'transfer', page: 'attack-transfer.html', expectedSuccess: false, type: 'transfer' },
  { mode: 'secure', attack: 'unbound-token', page: 'attack-unbound-token.html', expectedSuccess: false, type: 'email' },
  { mode: 'secure', attack: 'no-referrer', page: 'attack-no-referrer.html', expectedSuccess: false, type: 'email' },
];

test.describe.serial('CSRF Attack Verification Matrix (16 Tests)', () => {
  for (const item of matrix) {
    test(`Matrix [Mode: ${item.mode}] Attack: ${item.attack} -> ${item.expectedSuccess ? 'SUCCEEDS (✓)' : 'BLOCKED (✗)'}`, async ({
      browser,
    }) => {
      const server = await startServers({ mode: item.mode, sameSite: 'none' });
      const context = await browser.newContext();
      const page = await context.newPage();

      try {
        // Step 1: Alice signs in on the legitimate victim site
        await page.goto('http://localhost:5001/login.html');
        await page.fill('#username', 'alice');
        await page.fill('#password', 'alice-password');
        await page.click('#login-btn');
        await page.waitForURL('http://localhost:5001/dashboard.html');

        // Step 2: Victim navigates to the attacker website
        // The attacker page immediately auto-submits a cross-site POST form
        await page.goto(`http://127.0.0.1:7000/${item.page}`);

        // Wait for form submission response to load
        await page.waitForURL(/http:\/\/localhost:5001\/api\//, { timeout: 10000 });

        // Save screenshot of the post-attack page response
        const screenshotPath = path.join(
          SCREENSHOT_DIR,
          `${item.mode}__${item.attack}.png`
        );
        await page.screenshot({ path: screenshotPath });

        // Step 3: Query profile directly in browser context to verify attack outcome
        const profile = await page.evaluate(async () => {
          const res = await fetch('http://localhost:5001/api/me');
          return res.json();
        });

        if (item.type === 'email') {
          if (item.expectedSuccess) {
            expect(profile.email).toBe('hacked@evil.test');
          } else {
            expect(profile.email).toBe('alice@example.com');
          }
        } else if (item.type === 'transfer') {
          if (item.expectedSuccess) {
            expect(profile.balance).toBe(500);
          } else {
            expect(profile.balance).toBe(1000);
          }
        }
      } finally {
        await context.close();
        await server.close();
      }
    });
  }
});

test.describe.serial('Normal User Journey E2E in Each Mode', () => {
  const modes = ['off', 'weak-referer', 'weak-token', 'secure'];

  for (const mode of modes) {
    test(`Legitimate user workflow in "${mode}" mode`, async ({ browser }) => {
      const server = await startServers({ mode, sameSite: 'none' });
      const context = await browser.newContext();
      const page = await context.newPage();

      try {
        await page.goto('http://localhost:5001/login.html');
        await page.fill('#username', 'alice');
        await page.fill('#password', 'alice-password');
        await page.click('#login-btn');
        await page.waitForURL('http://localhost:5001/dashboard.html');

        // Change email via legitimate dashboard UI
        await page.fill('#new-email', 'alice-updated@example.com');
        await page.click('#update-email-btn');

        // Verify message and user profile element updated
        await expect(page.locator('#email-message')).toContainText(/successfully/i);
        await expect(page.locator('#user-email')).toHaveText('alice-updated@example.com');
      } finally {
        await context.close();
        await server.close();
      }
    });
  }
});

test.describe.serial('SameSite Defense Layer Verification', () => {
  test('Mode "off" with SESSION_SAMESITE=lax blocks basic cross-site form submission', async ({
    browser,
  }) => {
    // Mode is "off" (server has zero CSRF defenses), but SameSite=Lax is set on session cookie
    const server = await startServers({ mode: 'off', sameSite: 'lax' });
    const context = await browser.newContext();
    const page = await context.newPage();

    try {
      await page.goto('http://localhost:5001/login.html');
      await page.fill('#username', 'alice');
      await page.fill('#password', 'alice-password');
      await page.click('#login-btn');
      await page.waitForURL('http://localhost:5001/dashboard.html');

      // Victim visits attacker page
      await page.goto('http://127.0.0.1:7000/attack-change-email.html');
      await page.waitForURL(/http:\/\/localhost:5001\/api\//, { timeout: 10000 });

      // Save screenshot proving browser blocked cross-site session cookie
      await page.screenshot({
        path: path.join(SCREENSHOT_DIR, 'samesite-lax__change-email.png'),
      });

      // Query profile: because SameSite=Lax stripped the cookie on cross-site POST,
      // Alice's email remains UNCHANGED!
      const profile = await page.evaluate(async () => {
        const res = await fetch('http://localhost:5001/api/me');
        return res.json();
      });

      expect(profile.email).toBe('alice@example.com');
    } finally {
      await context.close();
      await server.close();
    }
  });
});
