const { loadConfig } = require('../../src/config');
const { createCsrfProtection } = require('../../src/csrf/index');

describe('Config and Factory Validation', () => {
  const validSecret = '0123456789abcdef0123456789abcdef'; // 32 chars

  test('throws if PROTECTION_MODE is invalid', () => {
    expect(() => loadConfig({ PROTECTION_MODE: 'invalid-mode' })).toThrow(/Invalid PROTECTION_MODE/);
  });

  test('throws if CSRF_SECRET is missing in secure mode', () => {
    expect(() => loadConfig({ PROTECTION_MODE: 'secure', CSRF_SECRET: '' })).toThrow(/CSRF_SECRET is required/);
  });

  test('throws if CSRF_SECRET is shorter than 32 characters', () => {
    expect(() => loadConfig({ PROTECTION_MODE: 'secure', CSRF_SECRET: 'too-short' })).toThrow(/at least 32 characters/);
  });

  test('allows missing CSRF_SECRET if PROTECTION_MODE is off', () => {
    const config = loadConfig({ PROTECTION_MODE: 'off', CSRF_SECRET: '' });
    expect(config.mode).toBe('off');
  });

  test('throws if SESSION_SAMESITE is invalid', () => {
    expect(() => loadConfig({ CSRF_SECRET: validSecret, SESSION_SAMESITE: 'unknown' })).toThrow(/Invalid SESSION_SAMESITE/);
  });

  test('throws if VICTIM_PORT or ATTACKER_PORT is out of range', () => {
    expect(() => loadConfig({ CSRF_SECRET: validSecret, VICTIM_PORT: '999999' })).toThrow(/Invalid VICTIM_PORT/);
    expect(() => loadConfig({ CSRF_SECRET: validSecret, ATTACKER_PORT: 'abc' })).toThrow(/Invalid ATTACKER_PORT/);
  });

  test('createCsrfProtection throws if secret is missing or too short', () => {
    expect(() => createCsrfProtection({ secret: '', getSessionId: () => '1' })).toThrow(
      /at least 32 characters/
    );
    expect(() => createCsrfProtection({ secret: 'short', getSessionId: () => '1' })).toThrow(
      /at least 32 characters/
    );
  });

  test('createCsrfProtection throws if getSessionId is not a function', () => {
    expect(() => createCsrfProtection({ secret: validSecret })).toThrow(
      /requires a getSessionId function/
    );
    expect(() => createCsrfProtection({ secret: validSecret, getSessionId: 'not-a-fn' })).toThrow(
      /requires a getSessionId function/
    );
  });
});
