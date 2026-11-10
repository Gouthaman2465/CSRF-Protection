const { checkOrigin } = require('../../src/csrf/originCheck');

describe('Origin Check Module (Section 6 Rule 4)', () => {
  const allowedOrigins = ['http://localhost:5001'];

  test('allows request when Origin exactly matches allowed origin', () => {
    const req = { headers: { origin: 'http://localhost:5001' } };
    const result = checkOrigin(req, allowedOrigins);
    expect(result.valid).toBe(true);
  });

  test('blocks request when Origin differs from allowed origins', () => {
    const req = { headers: { origin: 'http://127.0.0.1:7000' } };
    const result = checkOrigin(req, allowedOrigins);
    expect(result.valid).toBe(false);
    expect(result.code).toBe('ORIGIN_MISMATCH');
  });

  test('blocks request when Origin is "null" (sandboxed iframe / privacy redirect)', () => {
    const req = { headers: { origin: 'null' } };
    const result = checkOrigin(req, allowedOrigins);
    expect(result.valid).toBe(false);
    expect(result.code).toBe('ORIGIN_MISMATCH');
  });

  test('allows request when Origin is missing but Referer origin matches', () => {
    const req = { headers: { referer: 'http://localhost:5001/dashboard.html?query=1' } };
    const result = checkOrigin(req, allowedOrigins);
    expect(result.valid).toBe(true);
  });

  test('blocks request when Origin is missing and Referer origin differs', () => {
    const req = { headers: { referer: 'http://evil.com/attacker.html' } };
    const result = checkOrigin(req, allowedOrigins);
    expect(result.valid).toBe(false);
    expect(result.code).toBe('ORIGIN_MISMATCH');
  });

  test('blocks request when Referer is an invalid URL string', () => {
    const req = { headers: { referer: 'invalid-url-string' } };
    const result = checkOrigin(req, allowedOrigins);
    expect(result.valid).toBe(false);
    expect(result.code).toBe('ORIGIN_MISMATCH');
  });

  test('blocks request when both Origin and Referer are missing', () => {
    const req = { headers: {} };
    const result = checkOrigin(req, allowedOrigins);
    expect(result.valid).toBe(false);
    expect(result.code).toBe('ORIGIN_MISSING');
  });
});
