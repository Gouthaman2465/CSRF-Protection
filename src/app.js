const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');

const {
  findUser,
  verifyPassword,
  cleanForLogs,
  isValidUsername,
  isValidEmail,
} = require('./auth/users');

const {
  createSession,
  getSession,
  destroySession,
  regenerateSession,
  setSessionCookie,
  clearSessionCookie,
} = require('./auth/sessions');

const { getProtectionByMode } = require('./lab/index');

/**
 * Creates the Express application configured with security headers,
 * session management, CSRF defense, and victim application routes.
 *
 * @param {object} config System configuration object
 * @returns {express.Application} Express application (does not listen)
 */
function createApp(config) {
  const app = express();

  // 1. Handcrafted security headers (CSP and X-Content-Type-Options)
  app.use((req, res, next) => {
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; frame-ancestors 'none'"
    );
    res.setHeader('X-Content-Type-Options', 'nosniff');
    next();
  });

  // 2. Cookie parser
  app.use(cookieParser());

  // 3. Body parsers
  // NOTE: express.urlencoded is enabled intentionally because cross-site HTML forms
  // natively submit form-urlencoded data. This demonstrates classic CSRF attacks.
  // In contrast, cross-site JSON requests trigger a browser CORS preflight (OPTIONS)
  // which fails when no Access-Control-Allow-Origin header is present.
  app.use(express.json({ limit: '10kb' }));
  app.use(express.urlencoded({ extended: false, limit: '10kb' }));

  // Helper to extract session ID from parsed cookies or raw Cookie header
  function extractSessionId(req) {
    if (req.cookies && req.cookies.sid) {
      return req.cookies.sid;
    }
    const raw = req.headers.cookie;
    if (!raw) return null;
    const parts = raw.split(';');
    for (const part of parts) {
      const idx = part.indexOf('=');
      if (idx === -1) continue;
      if (part.slice(0, idx).trim() === 'sid') {
        try {
          return decodeURIComponent(part.slice(idx + 1).trim());
        } catch {
          return part.slice(idx + 1).trim();
        }
      }
    }
    return null;
  }

  // 4. Session resolution middleware
  app.use((req, res, next) => {
    const sid = extractSessionId(req);
    const session = getSession(sid);
    if (session) {
      req.session = session;
      req.sessionId = session.id;
    } else {
      req.session = null;
      req.sessionId = null;
    }
    next();
  });

  // 5. CSRF defense middleware (initialized according to config.mode)
  const csrf = getProtectionByMode(config, (req) => req.sessionId);
  app.use(csrf.middleware);

  // 6. Serve static assets (HTML, CSS, client-side JS)
  app.use(express.static(path.join(__dirname, 'public')));

  // ==========================================
  // API ROUTES
  // ==========================================

  // Returns current protection mode and SameSite configuration for UI banner
  app.get('/api/mode', (req, res) => {
    res.json({
      mode: config.mode,
      sameSite: config.sameSite,
    });
  });

  // Obtains a CSRF token for state-changing operations
  app.get('/api/csrf-token', (req, res) => {
    // Ensure an anonymous session exists if not already authenticated
    if (!req.session) {
      const session = createSession({ username: null });
      setSessionCookie(res, session.id, config);
      req.session = session;
      req.sessionId = session.id;
    }

    const token = csrf.issueToken(req, res);
    res.json({ token });
  });

  // User login: protected by CSRF defense to prevent Login CSRF attacks
  app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!isValidUsername(username) || typeof password !== 'string') {
      return res.status(400).json({ error: 'Invalid input' });
    }

    const user = findUser(username);
    if (!user || !verifyPassword(password, user)) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Regenerate session identifier to prevent session fixation and invalidate pre-auth tokens
    const oldSid = req.sessionId;
    const newSession = regenerateSession(oldSid, { username: user.username });
    req.session = newSession;
    req.sessionId = newSession.id;
    setSessionCookie(res, newSession.id, config);

    console.log(`[AUTH] User "${cleanForLogs(username)}" logged in successfully.`);

    res.json({
      success: true,
      message: 'Logged in successfully',
      user: {
        username: user.username,
        email: user.email,
        balance: user.balance,
      },
    });
  });

  // User logout
  app.post('/api/logout', (req, res) => {
    if (req.sessionId) {
      destroySession(req.sessionId);
      req.session = null;
      req.sessionId = null;
    }
    clearSessionCookie(res, config);
    res.json({ success: true, message: 'Logged out successfully' });
  });

  // User profile
  app.get('/api/me', (req, res) => {
    if (!req.session || !req.session.data || !req.session.data.username) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const user = findUser(req.session.data.username);
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    res.json({
      username: user.username,
      email: user.email,
      balance: user.balance,
    });
  });

  // Change user email (state-changing)
  app.post('/api/change-email', (req, res) => {
    const accept = req.headers.accept || '';

    if (!req.session || !req.session.data || !req.session.data.username) {
      if (accept.includes('text/html')) {
        return res.status(401).send(`<!DOCTYPE html>
<html>
  <head><title>Unauthorized</title></head>
  <body style="font-family:sans-serif;padding:2rem;">
    <h1 style="color:#d32f2f;">401 Unauthorized</h1>
    <p>No authenticated session found. (Session cookie may have been withheld by browser SameSite policy).</p>
    <a href="/login.html">Sign In</a>
  </body>
</html>`);
      }
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const user = findUser(req.session.data.username);
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { email } = req.body;
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email address' });
    }

    user.email = email;
    console.log(
      `[PROFILE] User "${cleanForLogs(user.username)}" changed email to "${cleanForLogs(email)}"`
    );

    if (accept.includes('text/html')) {
      return res.status(200).send(`<!DOCTYPE html>
<html>
  <head><title>Success</title></head>
  <body style="font-family:sans-serif;padding:2rem;">
    <h1 style="color:#2e7d32;">Done</h1>
    <p>Email changed to ${cleanForLogs(email)}</p>
    <a href="/dashboard.html">Back to Dashboard</a>
  </body>
</html>`);
    }

    res.json({
      success: true,
      message: 'Email updated successfully',
      email: user.email,
    });
  });

  // Transfer funds (state-changing)
  app.post('/api/transfer', (req, res) => {
    const accept = req.headers.accept || '';

    if (!req.session || !req.session.data || !req.session.data.username) {
      if (accept.includes('text/html')) {
        return res.status(401).send(`<!DOCTYPE html>
<html>
  <head><title>Unauthorized</title></head>
  <body style="font-family:sans-serif;padding:2rem;">
    <h1 style="color:#d32f2f;">401 Unauthorized</h1>
    <p>No authenticated session found. (Session cookie may have been withheld by browser SameSite policy).</p>
    <a href="/login.html">Sign In</a>
  </body>
</html>`);
      }
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const user = findUser(req.session.data.username);
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { to, amount } = req.body;
    if (!isValidUsername(to)) {
      return res.status(400).json({ error: 'Invalid recipient username' });
    }

    const recipient = findUser(to);
    if (!recipient) {
      return res.status(400).json({ error: 'Recipient does not exist' });
    }

    const parsedAmount = typeof amount === 'number' ? amount : parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      return res.status(400).json({ error: 'Amount must be greater than zero' });
    }

    if (parsedAmount > user.balance) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    user.balance -= parsedAmount;
    recipient.balance += parsedAmount;

    console.log(
      `[TRANSFER] User "${cleanForLogs(user.username)}" transferred ${parsedAmount} to "${cleanForLogs(to)}"`
    );

    if (accept.includes('text/html')) {
      return res.status(200).send(`<!DOCTYPE html>
<html>
  <head><title>Success</title></head>
  <body style="font-family:sans-serif;padding:2rem;">
    <h1 style="color:#2e7d32;">Done</h1>
    <p>Transferred ${parsedAmount} to ${cleanForLogs(to)}</p>
    <a href="/dashboard.html">Back to Dashboard</a>
  </body>
</html>`);
    }

    res.json({
      success: true,
      message: `Transferred ${parsedAmount} to ${to}`,
      balance: user.balance,
    });
  });

  return app;
}

module.exports = {
  createApp,
};
