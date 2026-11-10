/**
 * Validates Origin and Referer headers against an allowlist of trusted origins.
 *
 * Rules:
 * 1. If Origin header is present, it must exactly equal an allowed origin ('null' is rejected).
 * 2. If Origin is missing, the origin parsed from Referer must equal an allowed origin.
 * 3. If both Origin and Referer are missing, the check fails with ORIGIN_MISSING.
 *
 * @param {import('express').Request} req Incoming HTTP request
 * @param {string[]} allowedOrigins List of trusted origins
 * @returns {{ valid: boolean, code?: string, present: boolean }}
 */
function checkOrigin(req, allowedOrigins = []) {
  const rawOrigin = req.headers.origin;
  const rawReferer = req.headers.referer;

  // Case 1: Origin header is present
  if (rawOrigin !== undefined && rawOrigin !== null && rawOrigin !== '') {
    const origin = Array.isArray(rawOrigin) ? rawOrigin[0] : rawOrigin;

    // 'null' origin is explicitly untrusted (sandboxed iframes, file://, privacy redirects)
    if (origin === 'null') {
      return { valid: false, code: 'ORIGIN_MISMATCH', present: true };
    }

    if (allowedOrigins.includes(origin)) {
      return { valid: true, present: true };
    }

    return { valid: false, code: 'ORIGIN_MISMATCH', present: true };
  }

  // Case 2: Origin is absent, fallback to Referer
  if (rawReferer !== undefined && rawReferer !== null && rawReferer !== '') {
    const referer = Array.isArray(rawReferer) ? rawReferer[0] : rawReferer;
    try {
      const parsed = new URL(referer);
      const refererOrigin = parsed.origin;

      if (allowedOrigins.includes(refererOrigin)) {
        return { valid: true, present: true };
      }

      return { valid: false, code: 'ORIGIN_MISMATCH', present: true };
    } catch {
      return { valid: false, code: 'ORIGIN_MISMATCH', present: true };
    }
  }

  // Case 3: Both Origin and Referer are absent
  return { valid: false, code: 'ORIGIN_MISSING', present: false };
}

module.exports = {
  checkOrigin,
};
