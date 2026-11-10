const request = require('supertest');
const { createApp } = require('../../src/app');
const { resetUsers } = require('../../src/auth/users');
const { resetSessions } = require('../../src/auth/sessions');
const { generateToken } = require('../../src/csrf/token');

describe('Secure Mode Enforcement and Block Reason Codes', () => {
  const secret = '0123456789abcdef0123456789abcdef';
  let app;
  let aliceCookieHeader;
  let aliceToken;
  let aliceSessionId;

  beforeEach(async () => {
    resetUsers();
    resetSessions();

    app = createApp({
      mode: 'secure',
      secret,
      allowedOrigins: ['http://localhost:5001'],
      sameSite: 'none',
      tokenTtlMs: 3600000,
      enableTokenCheck: true,
      enableOriginCheck: true,
    });

    // Obtain pre-login token
    const preRes = await request(app)
      .get('/api/csrf-token')
      .set('Origin', 'http://localhost:5001');
    const preCookies = preRes.headers['set-cookie'].map((c) => c.split(';')[0]).join('; ');

    // Log in as Alice
    const loginRes = await request(app)
      .post('/api/login')
      .set('Origin', 'http://localhost:5001')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Cookie', preCookies)
      .set('x-csrf-token', preRes.body.token)
      .send({ username: 'alice', password: 'alice-password' });

    const postCookies = loginRes.headers['set-cookie'].map((c) => c.split(';')[0]).join('; ');
    aliceSessionId = postCookies.match(/sid=([^;]+)/)[1];

    // Get active post-login CSRF token
    const tokenRes = await request(app)
      .get('/api/csrf-token')
      .set('Origin', 'http://localhost:5001')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Cookie', postCookies);

    aliceToken = tokenRes.body.token;
    aliceCookieHeader = `sid=${aliceSessionId}; csrf_token=${aliceToken}`;
  });

  test('blocks request when x-csrf-token header is missing', async () => {
    const res = await request(app)
      .post('/api/change-email')
      .set('Origin', 'http://localhost:5001')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Cookie', aliceCookieHeader)
      .send({ email: 'new@example.com' });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('CSRF_TOKEN_MISSING');
  });

  test('blocks request when csrf_token cookie is missing', async () => {
    const res = await request(app)
      .post('/api/change-email')
      .set('Origin', 'http://localhost:5001')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Cookie', `sid=${aliceSessionId}`) // missing csrf_token cookie
      .set('x-csrf-token', aliceToken)
      .send({ email: 'new@example.com' });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('CSRF_TOKEN_MISSING');
  });

  test('blocks request when header token does not match cookie token', async () => {
    const otherToken = generateToken(secret, aliceSessionId, 3600000);
    const res = await request(app)
      .post('/api/change-email')
      .set('Origin', 'http://localhost:5001')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Cookie', `sid=${aliceSessionId}; csrf_token=${aliceToken}`)
      .set('x-csrf-token', otherToken)
      .send({ email: 'new@example.com' });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('CSRF_TOKEN_MISMATCH');
  });

  test('blocks request when token is expired', async () => {
    const expiredToken = generateToken(secret, aliceSessionId, -1000);
    const res = await request(app)
      .post('/api/change-email')
      .set('Origin', 'http://localhost:5001')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Cookie', `sid=${aliceSessionId}; csrf_token=${expiredToken}`)
      .set('x-csrf-token', expiredToken)
      .send({ email: 'new@example.com' });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('CSRF_TOKEN_EXPIRED');
  });

  test('blocks cookie injection: valid token pair taken from another session', async () => {
    // Mallory session
    const mallorySessionId = 'session_mallory_injected_cookie_99999';
    // Mallory creates a token pair signed for her own session
    const malloryToken = generateToken(secret, mallorySessionId, 3600000);

    // Mallory tosses/injects both the header and the csrf_token cookie into Alice's request,
    // but Alice's session cookie is sid=aliceSessionId
    const res = await request(app)
      .post('/api/change-email')
      .set('Origin', 'http://localhost:5001')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Cookie', `sid=${aliceSessionId}; csrf_token=${malloryToken}`)
      .set('x-csrf-token', malloryToken)
      .send({ email: 'injected@attacker.com' });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('CSRF_TOKEN_NOT_BOUND_TO_SESSION');
  });

  test('blocks PATCH method when token is absent', async () => {
    const res = await request(app)
      .patch('/api/change-email')
      .set('Origin', 'http://localhost:5001')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Cookie', aliceCookieHeader)
      .send({ email: 'patched@evil.test' });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('CSRF_TOKEN_MISSING');
  });

  test('blocks request when Origin header is from untrusted origin', async () => {
    const res = await request(app)
      .post('/api/change-email')
      .set('Origin', 'http://127.0.0.1:7000')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Cookie', aliceCookieHeader)
      .set('x-csrf-token', aliceToken)
      .send({ email: 'new@example.com' });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('ORIGIN_MISMATCH');
  });

  test('blocks request when Origin header is "null"', async () => {
    const res = await request(app)
      .post('/api/change-email')
      .set('Origin', 'null')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Cookie', aliceCookieHeader)
      .set('x-csrf-token', aliceToken)
      .send({ email: 'new@example.com' });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('ORIGIN_MISMATCH');
  });

  test('blocks request when Origin, Referer, and Sec-Fetch-Site are all missing', async () => {
    const res = await request(app)
      .post('/api/change-email')
      .set('Cookie', aliceCookieHeader)
      .set('x-csrf-token', aliceToken)
      .send({ email: 'new@example.com' });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('ORIGIN_MISSING');
  });

  test('blocks request when Sec-Fetch-Site is cross-site', async () => {
    const res = await request(app)
      .post('/api/change-email')
      .set('Origin', 'http://localhost:5001')
      .set('Sec-Fetch-Site', 'cross-site')
      .set('Cookie', aliceCookieHeader)
      .set('x-csrf-token', aliceToken)
      .send({ email: 'new@example.com' });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('FETCH_METADATA_CROSS_SITE');
  });

  test('blocks login CSRF when login is attempted without CSRF token', async () => {
    // Case 1: No session at all
    const resNoSession = await request(app)
      .post('/api/login')
      .set('Origin', 'http://localhost:5001')
      .set('Sec-Fetch-Site', 'same-origin')
      .send({ username: 'alice', password: 'alice-password' });

    expect(resNoSession.status).toBe(403);
    expect(resNoSession.body.code).toBe('NO_SESSION');

    // Case 2: Session exists but CSRF token is omitted
    const preRes = await request(app)
      .get('/api/csrf-token')
      .set('Origin', 'http://localhost:5001');
    const sidCookie = preRes.headers['set-cookie'].find((c) => c.startsWith('sid=')).split(';')[0];

    const resNoToken = await request(app)
      .post('/api/login')
      .set('Origin', 'http://localhost:5001')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Cookie', sidCookie)
      .send({ username: 'alice', password: 'alice-password' });

    expect(resNoToken.status).toBe(403);
    expect(resNoToken.body.code).toBe('CSRF_TOKEN_MISSING');
  });
});
