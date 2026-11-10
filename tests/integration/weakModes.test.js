const request = require('supertest');
const { createApp } = require('../../src/app');
const { resetUsers } = require('../../src/auth/users');
const { resetSessions, createSession } = require('../../src/auth/sessions');

describe('Vulnerable Lab Modes Behavior (Section 7)', () => {
  let aliceSession;

  beforeEach(() => {
    resetUsers();
    resetSessions();
    aliceSession = createSession({ username: 'alice' });
  });

  describe('weak-token mode (Bypass Demo 1)', () => {
    let app;

    beforeEach(() => {
      app = createApp({
        mode: 'weak-token',
        sameSite: 'none',
        allowedOrigins: ['http://localhost:5001'],
      });
    });

    test('accepts attacker-harvested token embedded in body field _csrf (unbound bypass)', async () => {
      // Attacker (Mallory) fetches a token on her own session
      const mallorySession = createSession({ username: 'mallory' });
      const tokenRes = await request(app)
        .get('/api/csrf-token')
        .set('Cookie', `sid=${mallorySession.id}`);

      const malloryToken = tokenRes.body.token;
      expect(malloryToken).toBeDefined();

      // Alice's browser visits attacker form which submits with Alice's cookie + Mallory's _csrf token
      const attackRes = await request(app)
        .post('/api/change-email')
        .set('Origin', 'http://127.0.0.1:7000')
        .set('Cookie', `sid=${aliceSession.id}`)
        .send({
          email: 'hacked-by-unbound-token@evil.test',
          _csrf: malloryToken,
        });

      expect(attackRes.status).toBe(200);
      expect(attackRes.body.email).toBe('hacked-by-unbound-token@evil.test');
    });

    test('blocks request when no token is supplied', async () => {
      const res = await request(app)
        .post('/api/change-email')
        .set('Cookie', `sid=${aliceSession.id}`)
        .send({ email: 'hacked@evil.test' });

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('CSRF_TOKEN_MISSING');
    });

    test('blocks request when an unissued token is supplied', async () => {
      const res = await request(app)
        .post('/api/change-email')
        .set('Cookie', `sid=${aliceSession.id}`)
        .send({ email: 'hacked@evil.test', _csrf: 'unrecognized_fake_token_123' });

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('CSRF_TOKEN_INVALID');
    });
  });

  describe('weak-referer mode (Bypass Demo 2)', () => {
    let app;

    beforeEach(() => {
      app = createApp({
        mode: 'weak-referer',
        sameSite: 'none',
        allowedOrigins: ['http://localhost:5001'],
      });
    });

    test('bypasses protection when Referer header is omitted (e.g. via meta no-referrer)', async () => {
      // Attacker suppresses Referer header
      const res = await request(app)
        .post('/api/change-email')
        .set('Cookie', `sid=${aliceSession.id}`)
        .send({ email: 'hacked-by-no-referrer@evil.test' });

      expect(res.status).toBe(200);
      expect(res.body.email).toBe('hacked-by-no-referrer@evil.test');
    });

    test('blocks request when Referer header indicates untrusted origin', async () => {
      const res = await request(app)
        .post('/api/change-email')
        .set('Referer', 'http://127.0.0.1:7000/attack.html')
        .set('Cookie', `sid=${aliceSession.id}`)
        .send({ email: 'hacked@evil.test' });

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('ORIGIN_MISMATCH');
    });

    test('allows request when Referer header origin matches allowed origin', async () => {
      const res = await request(app)
        .post('/api/change-email')
        .set('Referer', 'http://localhost:5001/dashboard.html')
        .set('Cookie', `sid=${aliceSession.id}`)
        .send({ email: 'legitimate@example.com' });

      expect(res.status).toBe(200);
      expect(res.body.email).toBe('legitimate@example.com');
    });
  });
});
