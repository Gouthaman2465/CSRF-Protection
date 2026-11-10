// INTENTIONALLY VULNERABLE. For learning only. Never use in a real app.

const { defaultOnBlock } = require('../csrf/index');

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Creates an intentionally vulnerable CSRF protection middleware that checks
 * the Referer header only when present, but naively allows requests where
 * the Referer header was omitted.
 *
 * Flaw: Attackers can suppress the Referer header using <meta name="referrer" content="no-referrer">
 * or rel="noreferrer", completely bypassing the check.
 */
function createWeakRefererProtection(options = {}) {
  const { allowedOrigins = ['http://localhost:5001'] } = options;

  function issueToken() {
    return null;
  }

  function middleware(req, res, next) {
    if (SAFE_METHODS.has(req.method.toUpperCase())) {
      return next();
    }

    const rawReferer = req.headers.referer;

    // Vulnerability: If Referer is omitted, the check is skipped entirely!
    if (!rawReferer) {
      return next();
    }

    try {
      const parsed = new URL(rawReferer);
      if (allowedOrigins.includes(parsed.origin)) {
        return next();
      }
      return defaultOnBlock(req, res, 'ORIGIN_MISMATCH');
    } catch {
      return defaultOnBlock(req, res, 'ORIGIN_MISMATCH');
    }
  }

  return {
    middleware,
    issueToken,
  };
}

module.exports = {
  createWeakRefererProtection,
};
