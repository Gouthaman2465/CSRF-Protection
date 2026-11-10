// INTENTIONALLY VULNERABLE. For learning only. Never use in a real app.

const crypto = require('crypto');
const { defaultOnBlock } = require('../csrf/index');

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Creates an intentionally vulnerable CSRF protection middleware where tokens
 * are stored globally and not bound to the user's session or identity.
 *
 * Flaw: Any user (such as an attacker) can request a valid token and embed it
 * into an attack form submitted on behalf of another authenticated user.
 */
function createWeakTokenProtection(options = {}) {
  const { cookieOptions = {} } = options;
  const issuedTokens = new Set();

  function issueToken(req, res) {
    const token = crypto.randomBytes(32).toString('hex');
    issuedTokens.add(token);

    const sameSite = cookieOptions.sameSite || 'none';
    const isSecure =
      cookieOptions.secure !== undefined
        ? cookieOptions.secure
        : sameSite === 'none' || process.env.NODE_ENV === 'production';

    res.cookie('csrf_token', token, {
      path: '/',
      httpOnly: false,
      sameSite,
      secure: isSecure,
      ...cookieOptions,
    });

    return token;
  }

  function middleware(req, res, next) {
    if (SAFE_METHODS.has(req.method.toUpperCase())) {
      return next();
    }

    const headerToken = req.headers['x-csrf-token'];
    const bodyToken = req.body && req.body._csrf;
    const candidate = headerToken || bodyToken;

    if (!candidate) {
      return defaultOnBlock(req, res, 'CSRF_TOKEN_MISSING');
    }

    if (!issuedTokens.has(candidate)) {
      return defaultOnBlock(req, res, 'CSRF_TOKEN_INVALID');
    }

    next();
  }

  return {
    middleware,
    issueToken,
    _issuedTokens: issuedTokens,
  };
}

module.exports = {
  createWeakTokenProtection,
};
