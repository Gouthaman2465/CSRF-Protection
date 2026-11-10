const {
  generateToken,
  parseToken,
  verifyToken,
  timingSafeEqual,
} = require('../../src/csrf/token');

describe('CSRF Token Module', () => {
  const secret = 'a_very_secure_test_secret_key_1234567890';
  const sessionId = 'session_alice_abcdef1234567890';
  const ttlMs = 60 * 60 * 1000;

  test('generates and verifies a valid token successfully', () => {
    const token = generateToken(secret, sessionId, ttlMs);
    expect(typeof token).toBe('string');
    expect(token.startsWith('v1.')).toBe(true);

    const result = verifyToken(secret, sessionId, token);
    expect(result.valid).toBe(true);
    expect(result.code).toBeUndefined();
    expect(result.expiresAtMs).toBeGreaterThan(Date.now());
  });

  test('fails verification when secret differs', () => {
    const wrongSecret = 'another_totally_different_secret_key_98765';
    const token = generateToken(secret, sessionId, ttlMs);
    const result = verifyToken(wrongSecret, sessionId, token);

    expect(result.valid).toBe(false);
    expect(result.code).toBe('CSRF_TOKEN_NOT_BOUND_TO_SESSION');
  });

  test('fails verification when session ID differs (session binding)', () => {
    const mallorySession = 'session_mallory_999999999999999';
    const token = generateToken(secret, sessionId, ttlMs);
    const result = verifyToken(secret, mallorySession, token);

    expect(result.valid).toBe(false);
    expect(result.code).toBe('CSRF_TOKEN_NOT_BOUND_TO_SESSION');
  });

  test('fails verification when token is tampered', () => {
    const token = generateToken(secret, sessionId, ttlMs);
    const parts = token.split('.');

    // Tamper with salt
    const tamperedSalt = parts[1].replace(/^[0-9a-f]/, (c) => (c === 'a' ? 'b' : 'a'));
    const tamperedToken1 = `v1.${tamperedSalt}.${parts[2]}.${parts[3]}`;
    expect(verifyToken(secret, sessionId, tamperedToken1).valid).toBe(false);

    // Tamper with HMAC
    const tamperedHmac = parts[3].slice(0, -1) + (parts[3].endsWith('0') ? '1' : '0');
    const tamperedToken2 = `v1.${parts[1]}.${parts[2]}.${tamperedHmac}`;
    expect(verifyToken(secret, sessionId, tamperedToken2).valid).toBe(false);
  });

  test('fails verification when token is expired', () => {
    // Generate token with negative TTL
    const expiredToken = generateToken(secret, sessionId, -5000);
    const result = verifyToken(secret, sessionId, expiredToken);

    expect(result.valid).toBe(false);
    expect(result.code).toBe('CSRF_TOKEN_EXPIRED');
  });

  test('fails verification for malformed tokens', () => {
    expect(verifyToken(secret, sessionId, null).code).toBe('CSRF_TOKEN_MALFORMED');
    expect(verifyToken(secret, sessionId, '').code).toBe('CSRF_TOKEN_MALFORMED');
    expect(verifyToken(secret, sessionId, 'not-a-token').code).toBe('CSRF_TOKEN_MALFORMED');
    expect(verifyToken(secret, sessionId, 'v2.abc.123.def').code).toBe('CSRF_TOKEN_MALFORMED');
    expect(verifyToken(secret, sessionId, 'v1.short.123.hmac').code).toBe('CSRF_TOKEN_MALFORMED');
  });

  test('fails verification when session ID is missing or null', () => {
    const token = generateToken(secret, sessionId, ttlMs);
    expect(verifyToken(secret, null, token).code).toBe('NO_SESSION');
    expect(verifyToken(secret, undefined, token).code).toBe('NO_SESSION');
  });

  test('timingSafeEqual never throws when string lengths differ', () => {
    expect(() => timingSafeEqual('short', 'much_longer_string')).not.toThrow();
    expect(timingSafeEqual('short', 'much_longer_string')).toBe(false);
    expect(timingSafeEqual('', 'nonempty')).toBe(false);
    expect(timingSafeEqual('same', 'same')).toBe(true);
    expect(timingSafeEqual('a', 'b')).toBe(false);
    expect(timingSafeEqual(null, 'abc')).toBe(false);
  });
});
