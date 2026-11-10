const request = require('supertest');
const { createApp } = require('../../src/app');
const { resetUsers } = require('../../src/auth/users');
const { resetSessions, createSession } = require('../../src/auth/sessions');

describe('Independent Verification of Defense Layers', () => {
  const secret = '0123456789abcdef0123456789abcdef';
  let aliceSession;

  beforeEach(() => {
    resetUsers();
    resetSessions();
    aliceSession = createSession({ username: 'alice' });
  });

  test('token-only layer blocks attacks even when origin checks are disabled', async () => {
    const app = createApp({
      mode: 'secure',
      secret,
      allowedOrigins: ['http://localhost:5001'],
      sameSite: 'none',
      tokenTtlMs: 3600000,
      enableTokenCheck: true,
      enableOriginCheck: false,
    });

    // Attacker initiates cross-site request with no token
    const res = await request(app)
      .post('/api/change-email')
      .set('Origin', 'http://127.0.0.1:7000')
      .set('Sec-Fetch-Site', 'cross-site')
      .set('Cookie', `sid=${aliceSession.id}`)
      .send({ email: 'hacked@evil.test' });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('CSRF_TOKEN_MISSING');
  });

  test('origin-only layer blocks attacks even when token checks are disabled', async () => {
    const app = createApp({
      mode: 'secure',
      secret,
      allowedOrigins: ['http://localhost:5001'],
      sameSite: 'none',
      tokenTtlMs: 3600000,
      enableTokenCheck: false,
      enableOriginCheck: true,
    });

    // Attacker initiates cross-site request
    const res = await request(app)
      .post('/api/change-email')
      .set('Origin', 'http://127.0.0.1:7000')
      .set('Sec-Fetch-Site', 'cross-site')
      .set('Cookie', `sid=${aliceSession.id}`)
      .send({ email: 'hacked@evil.test' });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('FETCH_METADATA_CROSS_SITE');
  });

  test('when both layers are disabled, cross-site requests pass', async () => {
    const app = createApp({
      mode: 'secure',
      secret,
      allowedOrigins: ['http://localhost:5001'],
      sameSite: 'none',
      tokenTtlMs: 3600000,
      enableTokenCheck: false,
      enableOriginCheck: false,
    });

    const res = await request(app)
      .post('/api/change-email')
      .set('Origin', 'http://127.0.0.1:7000')
      .set('Sec-Fetch-Site', 'cross-site')
      .set('Cookie', `sid=${aliceSession.id}`)
      .send({ email: 'hacked@evil.test' });

    expect(res.status).toBe(200);
    expect(res.body.email).toBe('hacked@evil.test');
  });
});
