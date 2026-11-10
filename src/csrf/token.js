const crypto = require('crypto');

/**
 * Compare two strings in constant time.
 * Prevents timing attacks. Never throws even if lengths differ.
 *
 * @param {string} a First string
 * @param {string} b Second string
 * @returns {boolean} True if strings match
 */
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Compute HMAC-SHA256 digest binding sessionId, random salt, and expiration.
 *
 * @param {string} secret Server secret key
 * @param {string} sessionId User session identifier
 * @param {string} random Random 16-byte hex salt
 * @param {number|string} expiresAtMs Expiration timestamp in milliseconds
 * @returns {string} Hex-encoded HMAC
 */
function computeHmac(secret, sessionId, random, expiresAtMs) {
  const payload = `${sessionId}|${random}|${expiresAtMs}`;
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

/**
 * Generate a new session-bound CSRF token.
 * Format: v1.<random 16 bytes hex>.<expiresAtMs>.<hmacHex>
 *
 * @param {string} secret Server secret key
 * @param {string} sessionId User session identifier
 * @param {number} ttlMs Time-to-live in milliseconds
 * @returns {string} CSRF token
 */
function generateToken(secret, sessionId, ttlMs) {
  const random = crypto.randomBytes(16).toString('hex');
  const expiresAtMs = Date.now() + ttlMs;
  const hmac = computeHmac(secret, sessionId, random, expiresAtMs);
  return `v1.${random}.${expiresAtMs}.${hmac}`;
}

/**
 * Parse a token into its constituent fields.
 *
 * @param {string} tokenString
 * @returns {{ version: string, random: string, expiresAtMs: number, hmac: string }|null}
 */
function parseToken(tokenString) {
  if (typeof tokenString !== 'string') return null;
  const parts = tokenString.split('.');
  if (parts.length !== 4) return null;
  const [version, random, expiresAtStr, hmac] = parts;
  if (version !== 'v1') return null;
  if (!/^[a-f0-9]{32}$/i.test(random)) return null;
  const expiresAtMs = parseInt(expiresAtStr, 10);
  if (isNaN(expiresAtMs) || expiresAtMs <= 0) return null;
  if (!/^[a-f0-9]{64}$/i.test(hmac)) return null;
  return { version, random, expiresAtMs, hmac };
}

/**
 * Verify a CSRF token against the given secret and current session ID.
 *
 * @param {string} secret Server secret key
 * @param {string} sessionId Current user session identifier
 * @param {string} tokenString Token to verify
 * @returns {{ valid: boolean, code?: string, expiresAtMs?: number }}
 */
function verifyToken(secret, sessionId, tokenString) {
  if (!sessionId) {
    return { valid: false, code: 'NO_SESSION' };
  }
  const parsed = parseToken(tokenString);
  if (!parsed) {
    return { valid: false, code: 'CSRF_TOKEN_MALFORMED' };
  }
  if (Date.now() > parsed.expiresAtMs) {
    return { valid: false, code: 'CSRF_TOKEN_EXPIRED' };
  }
  const expectedHmac = computeHmac(secret, sessionId, parsed.random, parsed.expiresAtMs);
  if (!timingSafeEqual(expectedHmac, parsed.hmac)) {
    return { valid: false, code: 'CSRF_TOKEN_NOT_BOUND_TO_SESSION' };
  }
  return { valid: true, expiresAtMs: parsed.expiresAtMs };
}

module.exports = {
  timingSafeEqual,
  computeHmac,
  generateToken,
  parseToken,
  verifyToken,
};
