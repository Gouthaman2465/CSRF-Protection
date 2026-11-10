const request = require('supertest');
const { createApp } = require('../../src/app');
const { resetUsers } = require('../../src/auth/users');
const { resetSessions } = require('../../src/auth/sessions');

describe('Normal User Journey Across All Modes', () => {
  const modes = ['off', 'weak-token', 'weak-referer', 'secure'];
  const secret = '0123456789abcdef0123456789abcdef';

  beforeEach(() => {
    resetUsers();
    resetSessions();
  });

  modes.forEach((mode) => {
    test(`executes full legitimate user journey in "${mode}" mode`, async () => {
      const app = createApp({
        mode,
        secret,
        allowedOrigins: ['http://localhost:5001'],
        sameSite: 'none',
        tokenTtlMs: 3600000,
        enableTokenCheck: true,
        enableOriginCheck: true,
      });

      // 1. Check mode banner API
      const modeRes = await request(app).get('/api/mode');
      expect(modeRes.status).toBe(200);
      expect(modeRes.body.mode).toBe(mode);

      // 2. Fetch pre-login CSRF token and anonymous session
      const tokenRes = await request(app)
        .get('/api/csrf-token')
        .set('Origin', 'http://localhost:5001');
      expect(tokenRes.status).toBe(200);

      const preLoginToken = tokenRes.body.token;
      const initialCookies = tokenRes.headers['set-cookie'] || [];
      const cookieHeader = initialCookies.map((c) => c.split(';')[0]).join('; ');

      // 3. User login (Alice)
      const loginReq = request(app)
        .post('/api/login')
        .set('Origin', 'http://localhost:5001')
        .set('Sec-Fetch-Site', 'same-origin')
        .set('Cookie', cookieHeader)
        .send({ username: 'alice', password: 'alice-password' });

      if (preLoginToken) {
        loginReq.set('x-csrf-token', preLoginToken);
      }

      const loginRes = await loginReq;
      expect(loginRes.status).toBe(200);
      expect(loginRes.body.success).toBe(true);

      // Extract new session cookies (regenerated)
      const postLoginCookies = loginRes.headers['set-cookie'] || [];
      let authCookieHeader = postLoginCookies.map((c) => c.split(';')[0]).join('; ');

      // 4. Fetch post-login token
      const postTokenRes = await request(app)
        .get('/api/csrf-token')
        .set('Origin', 'http://localhost:5001')
        .set('Sec-Fetch-Site', 'same-origin')
        .set('Cookie', authCookieHeader);
      expect(postTokenRes.status).toBe(200);

      const activeToken = postTokenRes.body.token;
      if (postTokenRes.headers['set-cookie']) {
        const extraCookies = postTokenRes.headers['set-cookie']
          .map((c) => c.split(';')[0])
          .join('; ');
        authCookieHeader = `${authCookieHeader}; ${extraCookies}`;
      }

      // 5. Query user profile (/api/me)
      const meRes = await request(app)
        .get('/api/me')
        .set('Cookie', authCookieHeader);
      expect(meRes.status).toBe(200);
      expect(meRes.body.username).toBe('alice');
      expect(meRes.body.balance).toBe(1000);

      // 6. Change email
      const emailReq = request(app)
        .post('/api/change-email')
        .set('Origin', 'http://localhost:5001')
        .set('Sec-Fetch-Site', 'same-origin')
        .set('Cookie', authCookieHeader)
        .send({ email: 'alice-new@example.com' });

      if (activeToken) {
        emailReq.set('x-csrf-token', activeToken);
      }

      const emailRes = await emailReq;
      expect(emailRes.status).toBe(200);
      expect(emailRes.body.email).toBe('alice-new@example.com');

      // 7. Transfer funds to Mallory
      const transferReq = request(app)
        .post('/api/transfer')
        .set('Origin', 'http://localhost:5001')
        .set('Sec-Fetch-Site', 'same-origin')
        .set('Cookie', authCookieHeader)
        .send({ to: 'mallory', amount: 250 });

      if (activeToken) {
        transferReq.set('x-csrf-token', activeToken);
      }

      const transferRes = await transferReq;
      expect(transferRes.status).toBe(200);
      expect(transferRes.body.balance).toBe(750);

      // 8. Logout
      const logoutReq = request(app)
        .post('/api/logout')
        .set('Origin', 'http://localhost:5001')
        .set('Sec-Fetch-Site', 'same-origin')
        .set('Cookie', authCookieHeader);

      if (activeToken) {
        logoutReq.set('x-csrf-token', activeToken);
      }

      const logoutRes = await logoutReq;
      expect(logoutRes.status).toBe(200);

      // Profile should now return 401
      const meAfterLogout = await request(app)
        .get('/api/me')
        .set('Cookie', authCookieHeader);
      expect(meAfterLogout.status).toBe(401);
    });
  });
});
