/**
 * CSRF PROTECTION MIDDLEWARE DESIGN SUMMARY
 * -----------------------------------------
 * 1. Method Allowlist: Safe methods (GET, HEAD, OPTIONS) skip verification; all others are checked.
 * 2. Independent Cookie Parsing: Parses the Cookie header directly without requiring external packages.
 * 3. Session-Bound Tokens: Tokens contain random salt, timestamp, and HMAC-SHA256 bound to sessionId.
 * 4. Double-Submit Pattern: Tokens are submitted via both an HTTP header and a cookie.
 * 5. Constant-Time Compare: Verifies header and cookie equality using timing-safe comparisons.
 * 6. Token Reuse: Reuses valid unexpired tokens on repeated requests to prevent desynchronization.
 * 7. Fetch Metadata: Validates Sec-Fetch-Site to ensure requests originate from same-origin contexts.
 * 8. Origin Allowlist: Enforces exact matches for Origin and Referer headers against trusted origins.
 * 9. Defense in Depth: Origin and token layers can be run together or tested independently.
 * 10. Granular Reason Codes: Provides structured error codes for logging and security monitoring.
 */

const { timingSafeEqual, generateToken, verifyToken } = require('./token');
const { checkOrigin } = require('./originCheck');
const { checkFetchMetadata } = require('./fetchMetadata');

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Remove newline and control characters to prevent log forging.
 *
 * @param {any} input
 * @returns {string}
 */
function cleanForLogs(input) {
  if (typeof input !== 'string') return String(input || '');
  return input.replace(/[\r\n\x00-\x1f\x7f]/g, '');
}

/**
 * Extract a cookie value from req.cookies or the raw Cookie header.
 *
 * @param {import('express').Request} req
 * @param {string} cookieName
 * @returns {string|undefined}
 */
function extractCookie(req, cookieName) {
  if (req.cookies && req.cookies[cookieName] !== undefined) {
    return req.cookies[cookieName];
  }
  const rawCookie = req.headers.cookie;
  if (!rawCookie || typeof rawCookie !== 'string') return undefined;

  const pairs = rawCookie.split(';');
  for (const pair of pairs) {
    const idx = pair.indexOf('=');
    if (idx === -1) continue;
    const key = pair.slice(0, idx).trim();
    if (key === cookieName) {
      const val = pair.slice(idx + 1).trim();
      try {
        return decodeURIComponent(val);
      } catch {
        return val;
      }
    }
  }
  return undefined;
}

/**
 * Default response handler when a request is blocked by CSRF defense.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {string} reason
 */
function defaultOnBlock(req, res, reason) {
  console.warn(
    `[CSRF BLOCK] ${cleanForLogs(req.method)} ${cleanForLogs(req.originalUrl || req.url)} - Reason: ${cleanForLogs(reason)}`
  );

  const accept = req.headers.accept || '';
  if (accept.includes('text/html')) {
    return res.status(403).send(`<!DOCTYPE html>
<html>
  <head><title>CSRF Blocked</title></head>
  <body style="font-family:sans-serif;padding:2rem;">
    <h1 style="color:#d32f2f;">Blocked by CSRF protection: ${cleanForLogs(reason)}</h1>
    <p>Your request was blocked by the application's CSRF defense layer.</p>
    <a href="/dashboard.html">Back to Dashboard</a>
  </body>
</html>`);
  }

  return res.status(403).json({
    error: 'Blocked by CSRF protection',
    code: reason,
  });
}

/**
 * Factory function creating CSRF middleware and token issuance utilities.
 *
 * @param {object} options
 * @param {string} options.secret Secret key for HMAC signing (min 32 chars)
 * @param {(req: import('express').Request) => string|null|undefined} options.getSessionId Function returning current session id
 * @param {number} [options.ttlMs=3600000] Token TTL in milliseconds
 * @param {string[]} [options.allowedOrigins=['http://localhost:5001']] Array of allowed origins
 * @param {string} [options.cookieName='csrf_token'] Cookie name for CSRF token
 * @param {string} [options.headerName='x-csrf-token'] Header name for CSRF token
 * @param {object} [options.cookieOptions={}] Additional cookie options
 * @param {boolean} [options.enableTokenCheck=true] Enable session-bound token verification
 * @param {boolean} [options.enableOriginCheck=true] Enable Origin and Fetch Metadata checks
 * @param {(req: any, res: any, reason: string) => void} [options.onBlock] Custom block handler
 * @returns {{ middleware: Function, issueToken: Function }}
 */
function createCsrfProtection(options = {}) {
  const {
    secret,
    getSessionId,
    ttlMs = 60 * 60 * 1000,
    allowedOrigins = ['http://localhost:5001'],
    cookieName = 'csrf_token',
    headerName = 'x-csrf-token',
    cookieOptions = {},
    enableTokenCheck = true,
    enableOriginCheck = true,
    onBlock = defaultOnBlock,
  } = options;

  if (!secret || typeof secret !== 'string' || secret.length < 32) {
    throw new Error('CSRF protection requires a secret string of at least 32 characters.');
  }

  if (typeof getSessionId !== 'function') {
    throw new Error('CSRF protection requires a getSessionId function.');
  }

  /**
   * Issues a CSRF token for the session. Reuses existing token if still valid.
   *
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @returns {string|null} Issued or reused token, or null if no session
   */
  function issueToken(req, res) {
    const sessionId = getSessionId(req);
    if (!sessionId) return null;

    const existingToken = extractCookie(req, cookieName);
    if (existingToken) {
      const check = verifyToken(secret, sessionId, existingToken);
      if (check.valid && check.expiresAtMs) {
        const remainingMs = check.expiresAtMs - Date.now();
        // Reuse if token has more than 20% TTL remaining
        if (remainingMs > ttlMs * 0.2) {
          return existingToken;
        }
      }
    }

    const token = generateToken(secret, sessionId, ttlMs);
    const sameSite = cookieOptions.sameSite || 'none';
    const isSecure =
      cookieOptions.secure !== undefined
        ? cookieOptions.secure
        : sameSite === 'none' || process.env.NODE_ENV === 'production';

    res.cookie(cookieName, token, {
      path: '/',
      maxAge: ttlMs,
      httpOnly: false,
      sameSite,
      secure: isSecure,
      ...cookieOptions,
    });

    return token;
  }

  /**
   * Express middleware performing CSRF defense checks.
   *
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @param {import('express').NextFunction} next
   */
  function middleware(req, res, next) {
    // 1. Method allowlist check: safe methods skip checks
    if (SAFE_METHODS.has(req.method.toUpperCase())) {
      return next();
    }

    // 2. Origin Layer (Fetch Metadata + Origin / Referer allowlist)
    if (enableOriginCheck) {
      const hasSecFetchSite = req.headers['sec-fetch-site'] !== undefined;
      const hasOrigin = req.headers.origin !== undefined;
      const hasReferer = req.headers.referer !== undefined;

      // If all three headers are missing, block with ORIGIN_MISSING
      if (!hasSecFetchSite && !hasOrigin && !hasReferer) {
        return onBlock(req, res, 'ORIGIN_MISSING');
      }

      // Check Fetch Metadata if present
      if (hasSecFetchSite) {
        const fmResult = checkFetchMetadata(req);
        if (!fmResult.valid) {
          return onBlock(req, res, fmResult.code);
        }
      }

      // Check Origin / Referer
      const originResult = checkOrigin(req, allowedOrigins);
      if (!originResult.valid) {
        return onBlock(req, res, originResult.code);
      }
    }

    // 3. Token Layer (Session-bound signed double-submit cookie)
    if (enableTokenCheck) {
      const sessionId = getSessionId(req);
      if (!sessionId) {
        return onBlock(req, res, 'NO_SESSION');
      }

      const clientHeaderToken = req.headers[headerName.toLowerCase()];
      const clientCookieToken = extractCookie(req, cookieName);

      if (!clientHeaderToken || !clientCookieToken) {
        return onBlock(req, res, 'CSRF_TOKEN_MISSING');
      }

      // Double-submit equality check
      if (!timingSafeEqual(clientHeaderToken, clientCookieToken)) {
        return onBlock(req, res, 'CSRF_TOKEN_MISMATCH');
      }

      // Cryptographic and session-binding verification
      const tokenVerification = verifyToken(secret, sessionId, clientHeaderToken);
      if (!tokenVerification.valid) {
        return onBlock(req, res, tokenVerification.code);
      }
    }

    // All enabled checks passed
    next();
  }

  return {
    middleware,
    issueToken,
  };
}

module.exports = {
  createCsrfProtection,
  extractCookie,
  cleanForLogs,
  defaultOnBlock,
};
