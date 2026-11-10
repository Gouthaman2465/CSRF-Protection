const request = require('supertest');
const { createApp } = require('../../src/app');
const { resetUsers, cleanForLogs } = require('../../src/auth/users');
const { resetSessions, createSession, getSession } = require('../../src/auth/sessions');

describe('Security Properties and Defensive Guarantees', () => {
  const secret = '0123456789abcdef0123456789abcdef';

  beforeEach(() => {
    resetUsers();
    resetSessions();
  });

  test('regenerates session ID after login and invalidates previous session ID', async () => {
    const app = createApp({
      mode: 'secure',
      secret,
      allowedOrigins: ['http://localhost:5001'],
      sameSite: 'none',
    });

    // 1. Establish anonymous pre-auth session
    const preRes = await request(app)
      .get('/api/csrf-token')
      .set('Origin', 'http://localhost:5001');

    const preCookies = preRes.headers['set-cookie'].join('; ');
    const oldSidMatch = preCookies.match(/sid=([^;]+)/);
    expect(oldSidMatch).not.toBeNull();
    const oldSid = oldSidMatch[1];
    const preToken = preRes.body.token;

    // 2. Perform login
    const loginRes = await request(app)
      .post('/api/login')
      .set('Origin', 'http://localhost:5001')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('Cookie', `sid=${oldSid}; csrf_token=${preToken}`)
      .set('x-csrf-token', preToken)
      .send({ username: 'alice', password: 'alice-password' });

    expect(loginRes.status).toBe(200);

    const postCookies = loginRes.headers['set-cookie'].join('; ');
    const newSidMatch = postCookies.match(/sid=([^;]+)/);
    expect(newSidMatch).not.toBeNull();
    const newSid = newSidMatch[1];

    // Verify session ID has changed
    expect(newSid).not.toBe(oldSid);

    // Old session ID must be destroyed in the session store
    expect(getSession(oldSid)).toBeNull();

    // Querying with old session ID fails with 401
    const meRes = await request(app)
      .get('/api/me')
      .set('Cookie', `sid=${oldSid}`);
    expect(meRes.status).toBe(401);
  });

  test('validates inputs and cleans control characters to prevent log forging', async () => {
    const app = createApp({
      mode: 'off', // Bypass CSRF to test input validation
      sameSite: 'none',
    });

    // Clean for logs helper verification
    expect(cleanForLogs('alice\r\nINJECTED LOG LINE')).toBe('aliceINJECTED LOG LINE');

    // Invalid username with newline
    const resUsernameNewline = await request(app)
      .post('/api/login')
      .send({ username: 'alice\nadmin', password: 'password' });
    expect(resUsernameNewline.status).toBe(400);

    // Invalid username with special characters
    const resSpecialChars = await request(app)
      .post('/api/login')
      .send({ username: 'alice<script>', password: 'password' });
    expect(resSpecialChars.status).toBe(400);

    // Logged in session for transfer and email checks
    const aliceSession = createSession({ username: 'alice' });

    // Invalid email format
    const resBadEmail = await request(app)
      .post('/api/change-email')
      .set('Cookie', `sid=${aliceSession.id}`)
      .send({ email: 'not-an-email' });
    expect(resBadEmail.status).toBe(400);

    // Negative transfer amount
    const resNegativeAmount = await request(app)
      .post('/api/transfer')
      .set('Cookie', `sid=${aliceSession.id}`)
      .send({ to: 'mallory', amount: -50 });
    expect(resNegativeAmount.status).toBe(400);

    // Overdraft transfer amount
    const resOverdraft = await request(app)
      .post('/api/transfer')
      .set('Cookie', `sid=${aliceSession.id}`)
      .send({ to: 'mallory', amount: 50000 });
    expect(resOverdraft.status).toBe(400);
    expect(resOverdraft.body.error).toMatch(/insufficient/i);
  });

  test('never includes Access-Control-Allow-Origin header on responses', async () => {
    const app = createApp({
      mode: 'secure',
      secret,
      allowedOrigins: ['http://localhost:5001'],
      sameSite: 'none',
    });

    // Test GET, POST, OPTIONS across different routes and error codes
    const r1 = await request(app).get('/api/mode');
    expect(r1.headers['access-control-allow-origin']).toBeUndefined();

    const r2 = await request(app).options('/api/change-email');
    expect(r2.headers['access-control-allow-origin']).toBeUndefined();

    const r3 = await request(app).post('/api/change-email');
    expect(r3.headers['access-control-allow-origin']).toBeUndefined();

    const r4 = await request(app).get('/api/me');
    expect(r4.headers['access-control-allow-origin']).toBeUndefined();
  });

  test('sets correct cookie flags (sid HttpOnly, SameSite from config)', async () => {
    const sameSiteOptions = ['none', 'lax', 'strict'];

    for (const sameSite of sameSiteOptions) {
      const app = createApp({
        mode: 'secure',
        secret,
        allowedOrigins: ['http://localhost:5001'],
        sameSite,
      });

      const res = await request(app)
        .get('/api/csrf-token')
        .set('Origin', 'http://localhost:5001');

      const setCookies = res.headers['set-cookie'] || [];
      const sidCookie = setCookies.find((c) => c.startsWith('sid='));
      expect(sidCookie).toBeDefined();

      // Verify HttpOnly
      expect(sidCookie).toMatch(/httponly/i);

      // Verify SameSite matches configuration
      expect(sidCookie.toLowerCase()).toContain(`samesite=${sameSite}`);

      // Verify Secure flag when SameSite=None
      if (sameSite === 'none') {
        expect(sidCookie).toMatch(/secure/i);
      }
    }
  });

  test('formats responses correctly based on Accept header (JSON vs HTML)', async () => {
    const app = createApp({
      mode: 'secure',
      secret,
      allowedOrigins: ['http://localhost:5001'],
      sameSite: 'none',
    });

    // 1. JSON error response for standard fetch request
    const jsonBlockedRes = await request(app)
      .post('/api/change-email')
      .set('Accept', 'application/json')
      .send({ email: 'new@example.com' });

    expect(jsonBlockedRes.status).toBe(403);
    expect(jsonBlockedRes.headers['content-type']).toMatch(/json/);
    expect(jsonBlockedRes.body.code).toBe('ORIGIN_MISSING');

    // 2. HTML error response for plain form submission
    const htmlBlockedRes = await request(app)
      .post('/api/change-email')
      .set('Accept', 'text/html,application/xhtml+xml')
      .send({ email: 'new@example.com' });

    expect(htmlBlockedRes.status).toBe(403);
    expect(htmlBlockedRes.headers['content-type']).toMatch(/html/);
    expect(htmlBlockedRes.text).toContain('Blocked by CSRF protection: ORIGIN_MISSING');
  });
});
