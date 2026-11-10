const { createCsrfProtection } = require('../../src/csrf/index');

describe('Method Allowlist Logic', () => {
  const secret = '0123456789abcdef0123456789abcdef';
  const { middleware } = createCsrfProtection({
    secret,
    getSessionId: () => 'test-session-123',
    allowedOrigins: ['http://localhost:5001'],
  });

  const runMiddleware = (method) => {
    return new Promise((resolve) => {
      const req = {
        method,
        headers: {},
        url: '/api/action',
      };
      let blockedCode = null;
      let nextCalled = false;

      const res = {
        status: (code) => ({
          json: (data) => {
            blockedCode = data.code;
            resolve({ nextCalled: false, blockedCode, status: code });
          },
          send: (body) => {
            resolve({ nextCalled: false, blockedBody: body, status: code });
          },
        }),
      };

      middleware(req, res, () => {
        nextCalled = true;
        resolve({ nextCalled: true });
      });
    });
  };

  test('safe methods GET, HEAD, OPTIONS bypass CSRF verification', async () => {
    expect((await runMiddleware('GET')).nextCalled).toBe(true);
    expect((await runMiddleware('HEAD')).nextCalled).toBe(true);
    expect((await runMiddleware('OPTIONS')).nextCalled).toBe(true);
  });

  test('unsafe methods POST, PUT, DELETE, PATCH are subject to verification', async () => {
    expect((await runMiddleware('POST')).nextCalled).toBe(false);
    expect((await runMiddleware('PUT')).nextCalled).toBe(false);
    expect((await runMiddleware('DELETE')).nextCalled).toBe(false);
    expect((await runMiddleware('PATCH')).nextCalled).toBe(false);
  });

  test('unknown or custom methods are subject to verification (allowlist approach)', async () => {
    expect((await runMiddleware('CUSTOM_VERB')).nextCalled).toBe(false);
    expect((await runMiddleware('PURGE')).nextCalled).toBe(false);
  });
});
